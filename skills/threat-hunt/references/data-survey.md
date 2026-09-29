# Surveying the data before you query it

Reached from Stage 2 of `SKILL.md`. Read this before writing the first query.

## Contents

- [Why this stage exists](#why-this-stage-exists)
- [The six-point check](#the-six-point-check)
- [Finding the right data source](#finding-the-right-data-source)
- [The gap register](#the-gap-register)
- [Worked survey](#worked-survey)
- [Writing the confidence statement](#writing-the-confidence-statement)

## Why this stage exists

A query against a field that is present in the schema but never populated returns
zero rows. So does a query against a field that is populated, parsed correctly,
and genuinely clean. **Both look identical in the result pane**, and only one of
them means anything.

Surveying first separates "we looked and it is not there" from "we cannot see."
That separation is the whole value of a negative result, and it is the only
reliable source of outcome 2 — the signals you need but do not collect.

The survey never blocks the hunt. Gaps are recorded, confidence is reduced, and
the hunt proceeds on the evidence that does exist.

## The six-point check

Run all six against every Evidence item in the ABLE hypothesis. Answer each with
a fact, not an assumption — a query that counts rows beats a belief about the
pipeline.

1. **Existence** — is the source ingested at all, into which index, table or
   repository?
2. **Population** — is the specific field populated? Count distinct non-null
   values over the window. A schema listing a field proves nothing; vendors ship
   fields their agents never fill.
3. **Retention** — does retention cover the hypothesis window? Check the oldest
   event actually present, not the documented policy. Hot-versus-cold tiering
   turns a 400-day policy into 30 searchable days.
4. **Coverage** — what share of the Location reports? Compare distinct hosts
   seen in the source against the asset inventory. "EDR is deployed" usually
   means 94%, and the missing 6% is disproportionately servers.
5. **Fidelity** — is it parsed correctly, and at what granularity? Truncated
   command lines, normalized-away case, a timestamp in the wrong zone, and
   sampled flow records all silently change what a query means.
6. **Blind spots** — what is known to be invisible here? Encrypted traffic
   without inspection, hosts outside the domain, contractor laptops, the
   segments where the sensor was never deployed.

**Population, fidelity and coverage are the three that bite.** Existence and
retention are usually known; those three are usually assumed.

## Finding the right data source

Work from the behavior to the telemetry requirement, then to the local source:

1. Take the ATT&CK technique ID from the hypothesis.
2. On the technique page, read its **Detection Strategies**, and the
   **Analytics** under them. Each analytic names the **Log Sources** and **Data
   Components** it needs — for example `Process: Process Creation`,
   `Network Traffic: Network Connection Creation`.
3. Map each data component to what your estate actually produces: which agent,
   which event ID, which table.

**Current as of ATT&CK v19 (28 April 2026).** The old flat *Data Sources*
listing is gone; it was replaced in v18 and the replacement matured in v19, which
ships 697 Detection Strategies and 1,758 Analytics for Enterprise alone. Guidance
that sends you to a technique's "Data Sources" section is describing a page that
no longer looks like that.

Two things follow for a hunter:

- **The Analytics do some of Stage 2 for you.** Each one names its log sources,
  its tunable parameters, and *where visibility gaps remain*. That last part is
  a gap register entry written by MITRE. Start from it rather than from a blank
  table.
- **The so-what shifts.** When an Analytic already exists for your behavior, the
  hunt's value is less about inventing logic and more about whether your
  telemetry can carry it. That is exactly what this stage measures.

Step 2 matters because it decouples the hunt from a vendor. "Process creation"
is the requirement; Sysmon Event ID 1, `DeviceProcessEvents`, and
`ProcessRollup2` are three implementations of it. A hypothesis written against
the data component survives a tooling change; one written against an event ID
does not.

Where an estate has never been mapped this way, DeTT&CT is the tool that
formalises it — but a first pass in the survey table below gets you further than
waiting for a program.

## When the absence is the finding

The survey's whole job is to find missing telemetry. It is worth asking, every
time, **why** it is missing — because there are two answers and only one of them
is an engineering problem.

ATT&CK v19 split Defense Evasion into **Stealth (TA0005)** and **Defense
Impairment (TA0112)**, defined as:

> "The adversary is trying to break security mechanisms, pipelines, and tooling
> so defenders can't see or trust what's happening."

Detecting that tactic means watching for the **absence of expected signals** and
validating control integrity. Which is to say: the thing this stage produces —
a list of places you cannot see — is also the raw material for a hunt.

**The survey already computes what tells the two apart.** Coverage is a
measurement over time, so look at its shape:

| What coverage looks like | Likely cause | Where it goes |
|---|---|---|
| Host never reported | Nobody deployed the sensor | Gap register, engineering owner |
| Whole subnet never reported | Rollout missed a segment | Gap register, engineering owner |
| Host reported, then stopped | **Someone or something stopped it** | Findings — investigate before filing |
| Agent present, events thinned | Config changed, or tampering | Findings — investigate before filing |
| Logs exist but with a hole | Retention, or clearing | Findings — investigate before filing |

A host that never reported is a purchase order. A host that reported until
Tuesday is a hunt.

So every gap entry records which of the two it is, and what you did to decide.
Where you could not tell, say so — an unexamined absence is the one an adversary
is most comfortable hiding in. Relevant techniques live under TA0112, notably
**T1685 Disable or Modify Tools** and **T1070 Indicator Removal**.

This costs one column in the survey and one question per gap, and it converts
the least interesting stage of the hunt into a second place badness can surface.

## The gap register

> Every figure, team name and percentage in the examples below is **invented**
> to illustrate the shape of an entry. This is a public repository; nothing here
> describes a real estate.

Every partial or absent Evidence item becomes an entry in `02-gaps.yml`. A gap
with no owner and no ask is a complaint; the schema exists to prevent that.

```yaml
gaps:
  - id: GAP-001
    evidence: "Process command line for service installations on domain controllers"
    attack_data_component: "Process: Process Creation"
    status: partial            # partial | absent
    finding: >
      Sysmon is deployed to 61% of domain controllers. The remaining 39% carry
      the built-in audit policy only, which omits the command line.
    hypothesis_impact: >
      Cannot distinguish a service installed by the deployment system from one
      installed by hand on 39% of the Location. Reduces confidence in any
      negative result to moderate.
    cause: engineering         # engineering | adversary | undetermined
    cause_evidence: >
      These hosts have never reported Sysmon events in the retention window, and
      the gap aligns exactly with an OU the baseline GPO does not cover. No host
      in this set stopped reporting, so nothing here points at T1685.
    owner: "Windows platform engineering"
    ask: >
      Extend the Sysmon baseline GPO to the DC organizational unit, with
      config coverage for Event ID 1 command line.
    raised: 2026-09-29
    hunt: 2026-09-29-rmm-persistence
```

Fields carry weight for a reason:

- **`hypothesis_impact`** is what turns the gap from an IT grievance into a
  security argument. It states what the organization cannot see because of it.
- **`owner`** and **`ask`** make it actionable by someone who was not on the hunt.
- **`hunt`** lets you show, later, that the same gap blocked four hunts — which is
  the argument that actually gets budget.
- **`cause`** and **`cause_evidence`** force the question above to be asked and
  answered. `undetermined` is an acceptable answer and a legitimate backlog item;
  leaving the field off is not.

## Worked survey

Hypothesis: RMM agent installed on a host with no business running one
(the climb in `pyramid-and-hypothesis.md`).

| Evidence needed | Exists | Populated | Retention | Coverage | Fidelity | Verdict |
|---|---|---|---|---|---|---|
| Process creation + parent lineage | Yes | Yes | 90d | 94% workstations, 61% servers | Command line truncated at 4096 | **Partial** → GAP-001 |
| Service installation events | Yes | Yes | 90d | 61% servers | Good | **Partial** → GAP-001 |
| Network connection to RMM cloud | Yes | Yes | 30d | Perimeter only | No host attribution for NAT'd ranges | **Partial** → GAP-002 |
| Inventory of hosts sanctioned to run RMM | **No** | — | — | — | — | **Absent** → GAP-003 |

GAP-003 is the interesting one. There is no security telemetry missing — the
organization simply does not know which hosts are *supposed* to run remote-access
software, so no query can separate sanctioned from unsanctioned. The hunt
proceeds by stack-ranking installs by rarity instead, and the register carries
the real finding: an inventory nobody owns.

That is a bucket C outcome delivered before a single query ran.

## Writing the confidence statement

Carry one sentence per Evidence item into `03-findings.md`, so the negative
result means something:

> Ruled out across 61% of in-scope servers over 90 days, at high confidence
> where Sysmon is deployed. The remaining 39% were searched on service-creation
> events without command line, so an install by a renamed binary would not have
> been distinguished. Confidence there: low.

Three properties make that statement useful: it names the **share of the estate**
covered, the **window**, and the **specific evasion** that would have survived the
gap. Anything vaguer collapses into "we found nothing," which asserts nothing.
