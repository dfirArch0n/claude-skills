---
name: threat-hunt
description: Hypothesis-driven threat hunting, end to end, built on the Pyramid of Pain. Use when the user wants to hunt, has a threat report or CISA advisory to act on, asks where to start with a pile of IOCs, suspects activity they cannot yet detect, wonders whether they even collect the telemetry to find something, needs hunt queries in Sigma / SPL / KQL / ES|QL / CrowdStrike NG-SIEM, wants hunt logic turned into a detection candidate, or has to write up a hunt that found nothing. Trigger on "look for", "search our logs for", "are we exposed to", and "did we get hit by" as readily as on the word "hunt".
---

# Threat hunting

A hunt that only asks "is the badness here?" wastes four of its five possible
outcomes. Run every hunt so it produces all five:

1. Previously unknown badness.
2. **Signals you do not collect** but need to find that badness.
3. **Searches that become detections.**
4. **Systems issues** discovered along the killchain — misconfiguration, missing
   controls, shadow IT.
5. A sharper hunter.

Outcomes 2, 3 and 4 arrive only if they have a stage and a file. That is what
this skill is: four stages, each producing a file, all of them written into one
**package** on disk.

## Standing conditions

- **You write queries; the human runs them.** No SIEM is wired to this session.
  Produce the query, say what a hit looks like, and ask for the results.
- **Ask once, up front**, for the two things you cannot infer: which platforms
  hold the logs, and which log sources are live. Then proceed. Where an answer
  never comes, state the assumption in the charter and keep going.
- **A missing input never stops the hunt.** An absent log source, an empty field,
  a conversion that fails — record it, record the confidence it costs, continue.
  A step that quietly did nothing must never read as a step that succeeded.

## Stage 0 — Frame the trigger

Name what started this, because it decides how much of the hypothesis already
exists:

| Trigger | What it gives you | What you must build |
|---|---|---|
| Threat report / advisory | Indicators, sometimes behaviors | The climb, and local relevance |
| ATT&CK coverage gap | A technique | Actor, location, evidence |
| Incident lesson | Real observed behavior | Generalisation beyond the one host |
| Anomaly or hunch | A feeling | All of it — and the so-what gate bites hardest here |
| Executive question | A deadline | Everything, fast |

**Done when** the trigger and its source are written into the charter.

## Stage 1 — Design

### Climb the pyramid

Triggers arrive at the bottom of Bianco's pyramid — hashes, addresses, domains.
Those are free for an adversary to change, so a hunt that stops there expires the
moment they rotate infrastructure. **Climb** before writing any query:

> artifact → which **tool** produced it → what **behavior** does that tool
> require → which **TTP** does the behavior serve

Hunt at the highest rung your telemetry actually reaches, and **record that rung
in the charter**.

Then say plainly what you have. If the only rung reachable is hash, address or
domain, this is an **IOC sweep** — still worth running, often urgent, but it buys
days rather than years. Name it as a sweep in the charter and say what would be
needed to climb. A sweep sold as a hunt is how a programme convinces itself it is
maturing while it churns indicators.

Worked climbs, including the ones that fail: `references/pyramid-and-hypothesis.md`.

### State the hypothesis with ABLE

- **Actor** — who, or what class of actor. Often unknown, and that is fine.
- **Behavior** — the specific TTP. One or two links of the killchain, not all of it.
- **Location** — where in the estate this would show up.
- **Evidence** — which data sources would carry it, and what it looks like there.

### Pass three gates

A hypothesis proceeds only once all three hold. Write the answers down; they are
what the retro is graded against.

1. **Falsifiable** — what result would make you abandon this? If no result would,
   it is a mood, not a hypothesis.
2. **So-what** — if confirmed, which decision or action changes? If none, spend
   the time elsewhere.
3. **Bounded** — systems, time window, and a maximum duration, with explicit
   abort criteria. A hunt without a clock runs until the hunter gets bored, and
   then reports nothing.

**Done when** `00-charter.md` holds the trigger, the climb with its rung named,
an ABLE hypothesis, and an answer to each gate.

## Stage 2 — Survey the data

Before queries. This is the stage everyone skips, and it is the one that produces
outcome 2.

Take each Evidence item from the hypothesis and establish six things: the source
exists; the field is **populated** rather than merely present in the schema;
retention covers the hypothesis window; what share of the Location is actually
reporting; parsing is correct; and which blind spots are already known.

The checklist, the ATT&CK data-source mapping, and the register schema:
`references/data-survey.md`.

Every failure becomes a **register** entry — the gap, the hypothesis it weakens,
the team that owns the fix, and the specific ask. Then the hunt **continues** on
the evidence that does exist, with the reduced confidence written down. A gap is
a finding, delivered whether or not the hunt finds anything else.

**Done when** every Evidence item is marked available, partial or absent, and
every partial and absent one has a register entry with an owner.

## Stage 3 — Execute

### Write the logic once

Express hunt logic as Sigma YAML, lint it, then convert it to every platform the
human runs:

```sh
skills/threat-hunt/scripts/setup_sigma.sh --check     # one time, verifies backends
uv run python skills/threat-hunt/scripts/convert.py \
    hunts/<hunt>/queries/<name>.sigma.yml \
    --targets splunk kusto elasticsearch crowdstrike
```

### Know where Sigma stops

Sigma is a **detection-rule** language: a filter over one log source. A great
deal of hunting is not that.

| Logic | Write it as |
|---|---|
| Filter over one log source | Sigma, converted to every target |
| Stack counting, rare-value or frequency analysis | Native query per platform |
| Joins across sources, sessionisation | Native query per platform |
| Time-series baseline, outlier scoring | Native query per platform |

When you drop to native, say in the query file **why** Sigma could not carry it.
That note is what stops the next hunter re-litigating the choice.

Per-platform pipelines, field-mapping traps, and the NG-SIEM specifics:
`references/sigma-and-queries.md`.

### Run, analyse, refine

Hand the queries over, take the results back, and read them. Refinement loops
back to Stage 1 when results show the hypothesis was wrong, and to Stage 2 when
they show the evidence assumption was wrong. The Stage 1 clock caps the loop.

### Triage into buckets

Every result lands in exactly one **bucket**:

| Bucket | Meaning | Goes to |
|---|---|---|
| **A** | Confirmed malicious | Incident response, now |
| **B** | Benign but unexpected — shadow IT, policy violation, forgotten service | System or business owner |
| **C** | Systems issue on the killchain — misconfiguration, missing patch, weak control | Owning engineering team |
| **D** | Explained and normal | Documented, closed |

B and C are outcome 4, and on most hunts they are the bulk of the value. Chase
them with the same rigour as A; an unexplained-but-probably-fine result is a C
until someone proves otherwise.

**Done when** every result sits in a bucket and every A, B and C names its owner.

## Stage 4 — Act

**A negative result is a result** — but only when it says what was ruled out,
over which data, at what coverage, and with what confidence. "We looked and found
nothing" without a coverage statement asserts nothing at all, and quietly implies
a cleanliness the data never supported. Write the coverage.

Produce:

- **`05-report.md`** — executive summary, then analyst detail.
- **`04-detections/`** — surviving logic written up as detection candidates in
  ADS format. Its mandatory *Blind Spots* and *False Positives* sections are the
  point: they force you to hand detection engineering something maintainable
  rather than a query that pages someone at 3am. Template and worked example:
  `references/findings-and-detections.md`.
- **Backlog** — hypotheses this hunt spawned and did not chase. Feed the next one.
- **`metadata.yml`** — ATT&CK technique IDs, the pyramid rung reached, dates,
  per-bucket counts, gap IDs raised. Across many hunts this file *is* the
  coverage metric. Everything as code, applied to hunting.

**Done when** the package holds a populated `02-gaps.yml`, `03-findings.md`,
`05-report.md` and `metadata.yml` — even where bucket A is empty.

## The package

Scaffold it first, then fill it as you go:

```sh
uv run python skills/threat-hunt/scripts/new_hunt.py --slug <short-slug>
```

```
hunts/YYYY-MM-DD-<slug>/
├── 00-charter.md      trigger, climb + rung, ABLE, gates, scope, clock
├── 01-data-survey.md  evidence required vs. evidence available
├── 02-gaps.yml        register: gap, owner, ask
├── queries/
│   ├── <name>.sigma.yml
│   └── generated/<name>.{spl,kql,esql,cql}
├── 03-findings.md     buckets, and the coverage statement behind any negative
├── 04-detections/     ADS-format detection candidates
├── 05-report.md       executive summary + analyst detail
└── metadata.yml       ATT&CK IDs, rung, counts, gap IDs
```

Hunt packages hold real environment detail, so they belong in the human's own
private hunt repository. This skill's repository keeps only sanitised examples
built from public reporting.

## References

- `references/pyramid-and-hypothesis.md` — worked climbs, weak-to-strong
  hypotheses, and the gates applied to real triggers.
- `references/data-survey.md` — the six-point evidence checklist, ATT&CK data
  sources, gap register schema.
- `references/sigma-and-queries.md` — Sigma-to-platform conversion, pipelines per
  backend, and the native-query patterns Sigma cannot express.
- `references/findings-and-detections.md` — bucket triage, the ADS template,
  coverage statements for negative results.
- `references/frameworks.md` — PEAK, TaHiTI, the Hunting Maturity Model and
  ATT&CK: what each is for, and when it earns its keep.
