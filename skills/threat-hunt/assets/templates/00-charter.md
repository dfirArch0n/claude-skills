# Hunt charter: {{SLUG}}

- **Date opened:** {{DATE}}
- **Hunter:** {{HUNTER}}
- **Status:** open | aborted | complete

## Trigger

- **Type:** threat report | ATT&CK gap | incident lesson | anomaly | hunch | executive question
- **Source:** <link or citation; a public source if this will ever be shared>
- **What it gave us:** <indicators, behaviors, a technique, a feeling>

### Source check

Everything below inherits this. Read the source before building on it.

- **Source read directly?** yes | no
- **If no — what it costs:** <the assumption you are proceeding on, which parts of the
  hypothesis rest on it, and what the coverage statement must say if it proves wrong>
- **What it actually contains:** <count each indicator type; "51 hashes, 0 IPs, 0 domains">
- **Where it contradicts the request:** <or "nothing; the request matched the source">
- **What it contains that nobody mentioned:** <command-line tables, TTP narrative, CVEs>

## The climb

| Rung | What the climb yielded |
|---|---|
| 1–2 hash / address | |
| 3 domain | |
| 4 network or host artifact | |
| 5 tool | |
| 6 TTP | |

- **Rung hunted at:** <1–6>
- **This is a:** hunt | **IOC sweep**
- **Shelf life (your estimate, not a measurement):** <hours / days / weeks / months / years>
- **To climb higher we would need:** <telemetry or knowledge that is missing>

## Hypothesis (ABLE)

- **Actor:** <or "unattributed">
- **Behavior:** <the TTP, one or two killchain links, with ATT&CK ID>
- **Location:** <the estate segment, named>
- **Evidence:** <data sources, and what the behavior looks like in them>

> **Statement:** <one sentence a colleague could disagree with>

## Gates

- **Falsifiable — what result makes us abandon this?**
  <the specific negative observation>
- **So-what — if confirmed, what changes?**
  <the decision, control, or detection this feeds>
- **Bounded**
  - Scope: <systems>
  - Window: <lookback, checked against real retention in the survey>
  - Clock: <maximum duration>
  - Abort criteria: <what ends this early>

## Assumptions

<Anything proceeded on without confirmation — platforms, sources, ownership.>
