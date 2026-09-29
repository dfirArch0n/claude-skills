# ADR 0003: Hunt output stays out of this repository

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

This repository is public, chosen deliberately so the skills can be shown to
other people.

The `threat-hunt` skill produces a hunt package: charter, data survey, gap
register, queries, findings, detection candidates, report. Every one of those
files is, by design, specific about a real environment. The gap register names
the teams that own broken telemetry and the share of servers missing an agent.
The findings name hosts and accounts. The queries carry index names, table names
and tenant identifiers. The charter names which threats the organization
considers relevant.

Taken together, a hunt package is a reconnaissance document written by the
defender. A skill that writes those files into its own repository, in a
repository that pushes to a public remote, is a data-loss incident with a
scheduler.

## Decision

Hunt packages are written to `hunts/` in the **analyst's own private
repository**, never into this one.

Four mechanisms enforce it rather than relying on care:

- `/hunts/` is in `.gitignore` here, so a `new_hunt.py` run inside this checkout
  cannot reach a commit. The leading slash is load-bearing: an unanchored
  `hunts/` matches at every level, and the first version of this file silently
  excluded `examples/hunts/` too, keeping the worked example out of the
  repository entirely. `tests/test_examples.py` now asserts the example is
  tracked, because a rule that over-matches fails silently by construction.
- `scaffold.create_hunt` **refuses** to write inside this repository unless
  explicitly overridden, checked before any file is created. A warning issued
  after the files exist is an observation, not a control.
- `.env.op` is git-ignored here, unlike in `security-tooling-dev` where it is
  committed. It holds only `op://` references and no values, but a reference
  still names a vault and an item, and that is free reconnaissance.
- `CLAUDE.md` states the rule in the repository the model reads before working.

Worked examples under `examples/` are built from **public** sources — CISA
advisories, vendor threat reporting, ATT&CK — and name the source they came from.

## Alternatives considered

- **A private repository instead.** Removes the risk entirely, and removes the
  reason for making it public: the skills are meant to be shown. The output, not
  the method, is what must stay private, and those separate cleanly.
- **Sanitizing real hunts for inclusion.** Sanitization is a manual step under
  time pressure, performed by someone who already knows the environment and
  therefore cannot see what is identifying about it. It fails eventually, and it
  fails silently.
- **Warning instead of refusing.** The original design warned after the files
  were written. A warning issued after the fact is an observation, not a
  control, and the evaluation runs walked straight past it. `create_hunt` now
  refuses unless `allow_in_skills_repo` is passed deliberately.
- **Relying on the model to be careful.** The skill runs unattended, in a
  directory the user chose, at the end of a long session. A `.gitignore` entry
  does not get tired.

## Consequences

- The skill's default output path assumes a separate hunt repository, so a
  first-time user has one more thing to set up. `new_hunt.py` warns when it is
  asked to scaffold inside this checkout.
- Examples are less vivid than real hunts would be. Public threat reporting is
  detailed enough to carry the method, which is what the examples are for.
- Anyone reading this repository sees how the hunting is done and learns nothing
  about where it was done. That is the intended split.
- Should the repository ever be made private, this ADR is superseded rather than
  deleted — the separation is still sound, just no longer forced.
