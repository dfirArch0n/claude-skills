# ADR 0004: The pyramid rung is recorded, and a sweep is called a sweep

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

Threat reports arrive as indicator lists. Searching those lists is fast,
satisfying, and produces a report that says "we hunted for APT-whoever." It is
also worth very little: Bianco's Pyramid of Pain exists to point out that a hash
costs an adversary seconds to change and an address costs them minutes.

The failure mode this creates is not that indicator sweeps happen — they should,
and during a live campaign they are urgent. It is that a sweep and a hunt produce
identically-shaped reports, so a program running nothing but sweeps cannot tell
that from the outside, and neither can its leadership. Everyone is busy, the
reports keep arriving, and the organization's ability to detect the same
adversary next quarter has not moved.

Nothing in the workflow naturally surfaces this. The hunter knows which rung they
reached; the record does not.

## Decision

Every hunt records the **pyramid rung it hunted at** as a required field, in both
`00-charter.md` and `metadata.yml`, alongside a `classification` of `hunt` or
`ioc_sweep` and a shelf-life estimate.

Where the highest reachable rung is hash, address or domain, the skill names the
work an **IOC sweep** in the charter and states what telemetry would be needed to
climb. It does not decline to run it — sweeps are legitimate — it declines to let
it be recorded as something it is not.

The charter also carries the climb itself as a table, so the reasoning that
produced the rung is visible rather than asserted.

## Alternatives considered

- **Leave the rung as guidance in the skill prose.** Guidance that produces no
  artifact is unmeasurable, and the prose already says to climb. The gap is in
  the record, so the fix belongs in the record.
- **Refuse to run low-rung hunts.** Wrong, and it would make the skill useless
  during exactly the incidents where speed matters most. A sweep during an active
  campaign is good work.
- **Score hunt quality directly.** A quality score invites gaming and compresses
  several unrelated things into one number. The rung is an observation about
  shelf life, not a grade, and it stays useful precisely because it is not one.
- **Record the ATT&CK technique only.** Necessary but insufficient: a rule that
  matches one named binary and a rule that matches the behavior any tool must
  perform can carry the same technique ID and have shelf lives three orders of
  magnitude apart.

## Consequences

- A program can be asked a question it could not previously answer: what share
  of our hunts reached rung 5 or 6, and is that share moving? `metadata.yml`
  across a hunt repository answers it by counting.
- Every stalled climb produces a gap register entry naming the telemetry that
  would unstall it, which converts a disappointing hunt into a collection
  argument.
- Some hunts get recorded as sweeps, which reads as less impressive. That is the
  point of the field, and the honesty is what makes the trend line mean anything.
- The rung is a judgment, and two hunters may rate the same hunt differently.
  The climb table in the charter makes the judgment inspectable, which is enough
  — precision here would be false anyway.
