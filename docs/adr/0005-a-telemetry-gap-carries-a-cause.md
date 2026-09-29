# ADR 0005: A telemetry gap carries a cause, because absence is also a signal

- **Status:** Accepted
- **Date:** 2026-09-29

## Context

Stage 2 of the `threat-hunt` skill surveys whether the telemetry to test a
hypothesis actually exists, and records every shortfall in a gap register with an
owning team and a concrete ask. The register was designed around one assumption:
that a gap is a collection failure. Somebody did not deploy the sensor, or the
GPO missed an organizational unit, or retention is shorter than advertised.

That assumption is usually right and occasionally catastrophic.

ATT&CK v19 (28 April 2026) split Defense Evasion into **Stealth (TA0005)** and
**Defense Impairment (TA0112)**, the latter defined as "the adversary is trying
to break security mechanisms, pipelines, and tooling so defenders can't see or
trust what's happening." Its detection approach is not pattern matching. It is
watching for the **absence of expected signals** and validating control
integrity.

Which means the artifact this stage already produces — a list of places the
organization cannot see — is simultaneously the raw material for a hunt, and the
skill was treating every entry in it as a procurement item.

The survey also already computes the thing that distinguishes the two cases.
Coverage is measured over a window, so its *shape* is available at no extra cost:
a host that never reported is an engineering gap, while a host that reported
until Tuesday is something else.

## Decision

Every gap register entry carries a **`cause`** of `engineering`, `adversary` or
`undetermined`, plus **`cause_evidence`** stating what was checked to decide.

`01-data-survey.md` gains a short table classifying each gap by coverage shape —
never, stopped, or thinned — which is the input to that judgment. `SKILL.md`
states the rule in Stage 2 so it is not reachable only by reading a reference.

`undetermined` is an acceptable answer and becomes a backlog item. Omitting the
field is not acceptable: an unexamined absence is the one an adversary is most
comfortable hiding in.

Separately, `metadata.yml` records an ATT&CK **`version`**, because v19 revoked
and re-issued technique IDs (T1562 merged into T1685, several sub-techniques
promoted to top-level) as well as moving techniques between tactics. Counting
techniques across hunts recorded either side of a release counts two different
taxonomies, which would quietly corrupt the coverage metric ADR 0004 promises.

## Alternatives considered

- **Leave it as prose advice in the reference.** The skill already said to survey
  coverage. Advice that produces no field produces no discipline, and this is
  precisely the check that gets skipped when a hunt is running late.
- **A separate "impairment hunt" as its own stage.** Cleaner conceptually, and
  wrong in practice: it would duplicate the coverage measurement Stage 2 already
  performs, and it would run only when someone remembered to schedule it. The
  value here is that the question rides along with work that happens anyway.
- **Treat every gap as potentially adversarial.** Maximally paranoid and useless
  at volume. Most gaps in most estates are genuinely nobody deploying the agent,
  and a register where every line demands an investigation is a register nobody
  reads.
- **Record the cause but not the evidence.** Halves the cost and loses the point:
  `engineering` asserted without a coverage check is a guess wearing a field name.

## Consequences

- The least interesting stage of the hunt becomes a second place badness can
  surface, at a cost of one column and one question per gap.
- Some gaps will be classified `engineering` wrongly, because coverage shape is
  evidence and not proof. `cause_evidence` makes that reviewable rather than
  invisible, which is the most this can honestly offer.
- `undetermined` entries accumulate into a backlog of absences nobody has
  explained. That list is uncomfortable and is the point.
- The gap register schema changed, so registers written before this ADR lack the
  field. They are still valid; the field is additive.
- Recording an ATT&CK version makes coverage counting correct across releases and
  adds a maintenance obligation: the version in `metadata.yml` is a fact about
  the hunt, not a value to bump globally.
