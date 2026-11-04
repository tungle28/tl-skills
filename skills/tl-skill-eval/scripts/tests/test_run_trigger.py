"""Regression tests for run_trigger.py trigger detection.

Incident: the eval workspace sat under .skill-evals/tl-skill-eval/, so every Read of the fixture's
own SKILL.md matched the skill name as a substring and counted as a trigger, and the first such
Read ended the run before a real Skill call could follow.

Run:  python -m unittest discover -s <skill>/scripts/tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import run_trigger  # noqa: E402

SKILL = "tl-skill-eval"


class FakePopen:
    """Stands in for `claude -p --output-format stream-json`, emitting the given tool calls."""

    def __init__(self, calls):
        lines = []
        for name, inp in calls:
            msg = {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": name, "input": inp}]}}
            lines.append((json.dumps(msg) + "\n").encode("utf-8"))
        lines.append(b'{"type": "result"}\n')
        self.stdout = iter(lines)

    def poll(self):
        return 0

    def kill(self):
        pass


def detect(calls, cwd):
    with mock.patch.object(run_trigger.subprocess, "Popen", lambda *a, **k: FakePopen(calls)):
        return run_trigger.run_query("claude", "q", SKILL, cwd, timeout=30, model=None)


class RunTriggerDetection(unittest.TestCase):
    def setUp(self):
        # A cwd whose path contains the skill name, as in .skill-evals/<skill>/iteration-N/fixture.
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.path.join(self.tmp.name, ".skill-evals", SKILL, "iteration-1", "fixture")
        os.makedirs(self.cwd)
        self.fixture_skill = os.path.join(self.cwd, "skills", "my-skill", "SKILL.md")
        self.installed = os.path.join(self.tmp.name, "home", ".claude", "skills", SKILL, "SKILL.md")

    def tearDown(self):
        self.tmp.cleanup()

    def test_fixture_skill_read_under_named_workspace_is_not_a_trigger(self):
        hit, fired = detect([("Read", {"file_path": self.fixture_skill})], self.cwd)
        self.assertFalse(hit, fired)

    def test_fixture_read_does_not_end_run_before_real_skill_call(self):
        hit, fired = detect([("Read", {"file_path": self.fixture_skill}),
                             ("Skill", {"skill": SKILL})], self.cwd)
        self.assertTrue(hit, fired)

    def test_installed_skill_read_is_a_trigger(self):
        hit, _ = detect([("Read", {"file_path": self.installed})], self.cwd)
        self.assertTrue(hit)

    def test_other_skill_is_not_a_trigger(self):
        hit, fired = detect([("Skill", {"skill": "anthropic-skills:skill-creator"})], self.cwd)
        self.assertFalse(hit)
        self.assertEqual(fired, "skill:anthropic-skills:skill-creator")

    def test_name_prefix_of_another_skill_is_not_a_trigger(self):
        hit, _ = detect([("Skill", {"skill": SKILL + "-adjudicator"})], self.cwd)
        self.assertFalse(hit)

    def test_plugin_prefixed_skill_is_a_trigger(self):
        hit, _ = detect([("Skill", {"skill": "my-plugin:" + SKILL})], self.cwd)
        self.assertTrue(hit)


if __name__ == "__main__":
    unittest.main()
