# ADR 0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

A skill is a set of instructions that will be followed by a model, repeatedly,
without the author present to explain what was meant. Every rule in a skill is a
decision — to constrain the model here and to trust it there — and those
decisions are invisible in the finished prose. "Why does the skill insist on
this?" is the question that gets asked the first time the rule is inconvenient.

This mirrors the practice already established in `security-tooling-dev`, and for
the same reason: decisions made silently are indistinguishable from accidents a
week later.

## Decision

Every meaningful choice gets a short ADR in `docs/adr/`, numbered sequentially,
recording context, the decision, alternatives considered, and consequences.
"Meaningful" means a reader could reasonably have expected the opposite choice.

Formatting, naming, and anything the linter already enforces do not get an ADR.

## Alternatives considered

- **Comments inside `SKILL.md`.** They travel with the skill, but a skill is
  read by a model that treats everything in the file as instruction. Rationale
  aimed at a future human maintainer would be spent as context on every
  invocation, and rejected alternatives would read as options still on the table.
- **Commit messages.** Already used for the *what*. Hard to browse, and nobody
  reads them as a set.
- **Nothing.** Fastest, and the reason most skills cannot explain themselves.

## Consequences

- A small, browsable record of why each skill constrains the model the way it
  does — which is also the material for defending the design out loud.
- ADRs are append-only **once merged**. Superseding an accepted decision means
  writing a new ADR that says so, not editing history. An ADR inside an open,
  unmerged pull request is still a draft and is revised in place.
- An ADR records a *decision and its trade-offs*, not the work that prompted it.
  "Added the data survey stage" is a commit message. "Data gaps are recorded and
  the hunt continues, and here is what that costs" is an ADR.
- Slight friction on every non-obvious change, which is the point.
