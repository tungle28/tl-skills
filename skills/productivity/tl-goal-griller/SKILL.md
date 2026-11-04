---
name: tl-goal-griller
description: Turn vague ideas into verifiable autonomous-work specifications for coding agents. Use when the user asks to clarify a goal, plan autonomous or long-running agent work, define success criteria or a definition of done, write a goal/spec/brief for an agent, or be interviewed ("grill me", "interview me") before implementation — including requests like "làm rõ mục tiêu", "viết goal cho agent", "hỏi tôi trước khi làm".
license: MIT
---

# Goal Griller

Interrogate fuzzy intent until it becomes a goal that any coding agent can pursue, verify, and stop on. Ask one question at a time, recommend an answer, and inspect the codebase instead of asking when the answer is discoverable.

The output must be platform-neutral. Do not require a product-specific command, API, hook, or goal mode. If the agent you are running in has a native goal/task mechanism, the specification can be adapted to it. Otherwise, the specification itself is the deliverable.

## Language

Ask questions, give recommendations, and explain in the language the user writes in; if they switch, follow the latest message.

In the final specification, keep the section labels in English exactly as in the contract below (`Goal:`, `Allowed changes:`, `Done when:`, `Pause if:`…) so any agent can parse it; write the content under them in the user's language. Keep code, file paths, commands, identifiers, and test names in their original form.

## Hard Gate

Do not produce a final goal specification until these six fields are clear enough:

1. Outcome: the single truth the user wants made real.
2. Success condition: measurable or objectively inspectable proof that the outcome is true.
3. Scope boundary: what may change and what must not change.
4. Context: files, docs, logs, issues, screenshots, services, or commands the agent should read first.
5. Validation loop: cheap checks during work, final checks before claiming done, and the proof artifact left behind for review (test output, benchmark, screenshot, log, PR description).
6. Stop and pause rules: when to stop as done, and when to pause for human input.

A field is "clear enough" when it is any of:
- confirmed by the user;
- discovered from the repository or provided material (and you say where it came from);
- your recommended answer, stated explicitly, which the user did not object to.

If any field is missing, ask the next highest-leverage question instead of drafting the final goal.

**Escape hatch.** If the user says to skip the interview or draft now ("just write it", "cứ viết đi"), do not keep asking. Draft the specification immediately, mark every field that is still a guess with `[ASSUMPTION]`, and add exactly one `Pause if:` rule for each `[ASSUMPTION]` marker so the executing agent stops instead of acting on a wrong guess. Never merge two assumptions into one pause rule; if two guesses are really one decision, mark them once.

## Interview Loop

1. Restate the apparent intent in one sentence.
2. If the request contains several independent goals, split them: list them, recommend an order (usually the one that unblocks the others, or the smallest verifiable one first), justify it with evidence from the repository when there is any (a documented known issue, an existing dependency, what the code already does), and grill only the first. Offer to do the next one afterwards.
3. Identify the weakest missing field from the hard gate.
4. If the answer can be discovered from local files, logs, docs, tests, issues, or repo conventions, inspect those sources instead of asking. State what you found as fact, with its source; do not ask the user to confirm it, and do not fold it back into a question ("how is it measured?" when the repo already has the benchmark).
5. Ask exactly one question at a time. Gaps you discovered along the way (a missing file, a stale doc) go into your findings as statements, not as a second ask or an "also tell me…" aside.
6. For each question, include your recommended answer and why it is probably right.
7. After the user answers, update the working goal shape and repeat.

### Asking through a question dialog

If your agent has a structured question tool (for example `AskUserQuestion` in Claude Code), use it for questions with a few distinct plausible answers: still one question per call, 2–4 options, your recommended answer as the first option labelled "(Recommended)", and the reason in its description. The user can always type their own answer instead.

Ask in plain text when you cannot offer grounded options, because only the user knows the answer (a bug report, a file path, an external system or contact), or when no such tool exists. A target you can recommend from the repo (a documented baseline, an existing benchmark) is not open-ended: offer it as options. Never force a question into options just to use the dialog.

The interview should feel useful, not bureaucratic. Prefer three sharp questions over ten generic ones: every question must close a hard-gate field that you could not fill yourself. Stop interviewing as soon as all six fields are clear enough.

## Question Priority

Ask in this order unless local context shows a different blocker. Each question maps to a hard-gate field:

1. What should be true at the end? (Outcome)
2. How will we prove it is true? (Success condition)
3. What may change, and what is explicitly off-limits? (Scope boundary)
4. What should the agent read or preserve before acting? (Context)
5. What checks should run repeatedly versus only at the end, and what proof should the agent leave behind for review? (Validation loop)
6. What should make the agent pause instead of improvising? (Stop and pause rules)

## Anti-Vague Rewrites

Reject goals shaped like these:

- "Improve the app."
- "Fix all bugs."
- "Make it production ready."
- "Refactor this codebase."
- "Research this and do the best thing."

Convert them into a single outcome plus proof:

- Instead of "Improve the app": "Reduce dashboard initial load time by at least 25% with no visible behavior regressions, proven by benchmark output and browser screenshots."
- Instead of "Fix all bugs": "Make the checkout flow pass the failing Playwright suite and preserve existing successful payment behavior."
- Instead of "Make it production ready": "Close the three launch blockers agreed with the user — secrets moved out of the repo into environment config, a health-check endpoint returning 200, and CI running the existing test suite on every PR — proven by a clean secret scan, a curl against the health endpoint, and a green CI run."
- Instead of "Refactor this codebase": "Extract the duplicated auth/session logic into one shared module while preserving all current tests and public API behavior."
- Instead of "Research this and do the best thing": split into two goals. First: "Compare options A, B and C for [problem] against the agreed criteria (cost, effort, risk) and write a one-page recommendation to `docs/decisions/[topic].md`; do not change code." Second, only after the user picks an option: implement it as its own goal.

## Goal Prompt Contract

When the hard gate is satisfied (or the escape hatch was used), output this platform-neutral specification. Carry every answer the user confirmed into it verbatim, and keep `Allowed changes` exactly as wide as agreed: do not add files, folders, or kinds of change (tests, config, dependencies) the user did not accept. If the goal seems to need something outside the agreed scope, add a `Pause if:` rule for it instead of widening the scope.

```text
Goal: [single objective]

Context to read first:
- [...]

Allowed changes:
- [files, modules, or kinds of change that are in scope]

Must not change:
- [files, public APIs, behavior, data, or dependencies that are off-limits]

Operating rules:
- Keep a concise progress log in [file — default: PROGRESS.md next to the goal file, or in the PR description] when the task is long-running.
- Prefer small verified iterations over large unverified edits.
- Do not expand scope without pausing.

Validation loop:
- During work: [...]
- Final proof: [...]
- Leave for review: [proof artifact]

Done when:
- [...]

Pause if:
- [...]
```

Also include a short "Why this goal is safe to run" note with the success condition, main risk, and proof artifact.

### Saving the specification

Show the specification in the reply. Additionally offer to save it to a file when the goal will run for a long time, will be handed to another agent or person, or will be executed in a later session. Default location: `docs/goals/<short-slug>.md` if the repository has a `docs/` folder, otherwise `GOAL.md` at the repository root — or wherever the user or repo convention says. Only write the file after the user agrees (or if they asked for a file in the first place). If a file is saved, point the progress log rule at a sibling file (e.g. `docs/goals/<short-slug>.progress.md`).

## Do Not Silently Start

There are two cases:

1. **The user asked only for a goal specification.** Present it (and save it if agreed) and stop. Do not start implementation or invoke any goal/task tool.
2. **The user asked to create and execute the goal.** Present the final specification first and wait for the user to confirm that it matches their intent. Then execute:
   - If you have a native goal/task tool available, use it with the specification adapted to the format it expects.
   - Otherwise, treat the specification as your working contract: stay within `Allowed changes`, run the `Validation loop`, stop on `Done when`, and pause on any `Pause if`.

   Skip the confirmation only when there was no interview and no inference at all — the user supplied every field themselves. Never invent a product-specific command or API.
