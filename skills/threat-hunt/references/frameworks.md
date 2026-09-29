# The frameworks, and when each earns its keep

Reached from `SKILL.md` when a hunt needs orienting against published practice —
or when someone asks which methodology this follows.

Frameworks are load-bearing only where they change what you do next. Each entry
below says what it is for, and when to leave it alone.

## Pyramid of Pain — David Bianco, 2013

Ranks indicator types by what detecting on them costs the adversary: hashes
(seconds to change) up through TTPs (years). The spine of this skill, because it
converts "we have indicators" into "here is the shelf life of what we are about
to build."

**Use it** on every trigger, to decide which rung to hunt at and to name an IOC
sweep as a sweep.

**Do not** treat the rung as a quality score. A rung-2 sweep during an active
campaign can be the right call; it just expires.

Detail: `pyramid-and-hypothesis.md`.

## PEAK — David Bianco / Splunk

**P**repare, **E**xecute, **A**ct with **K**nowledge. Three hunt types:

- **Hypothesis-driven** — you have a supposition and test it. What this skill does.
- **Baseline** (exploratory data analysis) — you have no hypothesis, so you
  characterise normal and look at the edges. The right move when you know a data
  source is rich and do not yet know what lives in it.
- **Model-assisted (M-ATH)** — machine learning models normal or malicious
  behavior and flags departures.

PEAK contributes two things this skill uses directly: **ABLE** for hypothesis
structure, and the insistence that the Act phase is not optional — documentation,
detection creation, and backlog are where the hunt's value actually lands.

**Use it** for vocabulary, and when a hunt has no hypothesis available — that is
the signal to run a baseline hunt instead of forcing a bad one.

## TaHiTI — Dutch financial sector, 2018

**Ta**rgeted **Hi**nting integrating **T**hreat **I**ntelligence. Three phases —
Initiate, Hunt, Finalise — across six steps, built around a **hunting backlog**
fed by triggers, where each trigger becomes an "investigation abstract" that
waits its turn.

TaHiTI's distinctive contribution is the backlog: hunts are queued and
prioritised rather than run in the order intel arrives. This skill writes spawned
hypotheses to a backlog in Stage 4 for that reason.

**Use it** when the problem is programme-level — too many triggers, no way to
choose. For a single hunt, PEAK's structure is lighter.

## Hunting Maturity Model — Sqrrl / Bianco

Five levels, gated mostly on data and on who writes the procedures:

| Level | Name | Characteristic |
|---|---|---|
| HMM0 | Initial | Relies on automated alerting; little routine collection |
| HMM1 | Minimal | Searches threat intel indicators; moderate collection |
| HMM2 | Procedural | Follows analysis procedures written by others; high collection |
| HMM3 | Innovative | Creates new analysis procedures |
| HMM4 | Leading | Automates the majority of successful procedures |

The useful observation buried in it: **you cannot skip levels by trying harder**,
because each depends on data collection the level below establishes. A team at
HMM1 asking for HMM3 hunts needs telemetry, not ambition — which is precisely
what the Stage 2 gap register documents.

**Use it** to explain to leadership why the answer to "hunt better" is a
collection programme.

## MITRE ATT&CK

The shared vocabulary for behavior, and — more usefully for hunting — the
telemetry each technique page names. Those turn "hunt for this technique" into
"these are the events you need," which is the input to Stage 2.

**As of v18 (October 2025)** a technique page carries **Detection Strategies**,
which group **Analytics**, which cite **Log Sources** and **Data Components**.
The older flat *Data Sources* listing is deprecated. Survey against Data
Components: they are still the vendor-neutral unit, and they outlive whichever
agent you happen to run.

**Use it** for the technique ID in the charter, the data components in the
survey, and Categorization in a detection candidate.

**Do not** mistake technique coverage for security. A technique is "covered" at
wildly different depths, and counting covered techniques rewards shallow rules.

## ADS — Palantir

Alerting and Detection Strategy: a ten-section template for documenting a
detection. Used in Stage 4 because *Blind Spots and Assumptions* and *False
Positives* are mandatory sections, which is the discipline that makes a detection
survive production.

Detail and template: `findings-and-detections.md`.

## Diamond Model and Kill Chain

The Diamond Model (adversary, capability, infrastructure, victim) is a pivoting
aid: it prompts you, from any one corner, for the other three. Useful during
Stage 3 analysis when a single result needs expanding into everything related.

The Kill Chain matters here mainly as a scoping reminder: hunt **one or two
links**, not the whole chain. The overreach failure in
`pyramid-and-hypothesis.md` is exactly a kill-chain-sized hypothesis.

## What this skill actually follows

Hypothesis-driven hunting, structured as PEAK's Prepare / Execute / Act, with the
Pyramid of Pain deciding the rung, ABLE structuring the hypothesis, ATT&CK naming
the behavior and its data requirements, and ADS carrying the output to detection
engineering.

Baseline and model-assisted hunting are deliberately out of scope for now. When
a trigger produces no testable hypothesis, say so and propose a baseline hunt
rather than manufacturing a weak one.
