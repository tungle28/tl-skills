"""Regression tests for lint_skill.py.

Incident: the Windows-path check was written as \\\\ inside a raw string, so it only matched two
backslashes in a row and missed every ordinary path such as scripts\\build.py or C:\\Users.

Run:  python -m unittest discover -s <skill>/scripts/tests -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import lint_skill  # noqa: E402

WARN = "Windows-style backslash paths"


def lint_body(body):
    with tempfile.TemporaryDirectory() as tmp:
        skill = os.path.join(tmp, "demo-skill")
        os.makedirs(skill)
        with open(os.path.join(skill, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("---\nname: demo-skill\ndescription: Formats demo output. Use when the user "
                    "asks for a demo.\n---\n\n# Demo\n\n" + body + "\n")
        return lint_skill.lint(Path(skill))["warnings"]


class WindowsPathCheck(unittest.TestCase):
    def assertFlags(self, body, expected):
        flagged = any(WARN in w for w in lint_body(body))
        self.assertEqual(flagged, expected, body)

    def test_flags_windows_paths(self):
        for body in ["Run `python scripts\\build.py`.", "Open C:\\Users\\me\\x.txt.",
                     "Look in references\\deep\\ first.", 'Set "C:\\\\Tools" in JSON.']:
            self.assertFlags(body, True)

    def test_ignores_forward_slashes_and_escapes(self):
        for body in ["Run `python scripts/build.py`.", "Match `\\d+\\.\\d+` in the version.",
                     "Join lines with `\\n`.", "Escape the dot: `Crypto\\.Encrypt\\(`."]:
            self.assertFlags(body, False)


if __name__ == "__main__":
    unittest.main()
