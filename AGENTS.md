# AGENTS.md

Instructions for AI agents (and contributors) working in this repository.

## Hard rule: keep docs in sync

After **any** change to this repository — code, build files, tests, phasing,
whatever — update [README.md](README.md) and [DESIGN.md](DESIGN.md) if the
change makes anything in them outdated. This is not optional and not
best-effort; treat it as part of the change itself, not a follow-up.

Specifically:

- **README.md** describes what exists and works *today*: build/test
  instructions, repo layout, requirements, and the "Current status" section.
  If you add, remove, or move a project/directory, change how tests are run,
  change the target framework, or complete/start a phase, update README.md
  in the same change.
- **DESIGN.md** is the plan: goals, architecture, phasing, and the
  `Status`/`Target` line at the top. If a change completes a phase, alters
  the architecture it describes, or contradicts a decision recorded there,
  update DESIGN.md — either revise the section or, if the plan itself
  changed, say so explicitly rather than leaving stale text.

Before finishing any change, re-read both files and ask: does anything here
now describe something that is no longer true? If yes, fix it before
considering the change done. It's easy to lose track of these two files
drifting from reality — do not let that happen silently.
