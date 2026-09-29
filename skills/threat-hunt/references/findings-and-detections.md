# Findings, negative results, and the detection handoff

Reached from Stages 3 and 4 of `SKILL.md`. Read this when results come back.

## Contents

- [Triage into buckets](#triage-into-buckets)
- [The unexplained result](#the-unexplained-result)
- [Coverage statements](#coverage-statements)
- [The ADS template](#the-ads-template)
- [Worked detection candidate](#worked-detection-candidate)
- [What makes a candidate ready](#what-makes-a-candidate-ready)

## Triage into buckets

Every result lands in exactly one bucket. The buckets exist because a hunt that
sorts only into "bad" and "not bad" discards outcome 4 entirely.

| Bucket | Test | Goes to |
|---|---|---|
| **A** | Adversary action, confirmed | Incident response, immediately |
| **B** | Real and unsanctioned, but not adversarial — shadow IT, policy violation, a forgotten service | System or business owner |
| **C** | A weakness on the killchain — misconfiguration, missing control, absent inventory, unpatched path | Owning engineering team |
| **D** | Explained, sanctioned, normal | Documented and closed |

Two rules keep the buckets honest.

**Bucket A escalates immediately.** The moment a result is adversary action, the
hunt stops being a hunt and becomes an incident. Hand it over; do not finish the
hunt first.

**B and C usually outnumber A**, and on a well-run programme that is the normal
result, not a disappointment. A hunt that surfaces an unmanaged RMM install, a
service account with an eleven-year-old password, and a subnet no sensor covers
has paid for itself without finding an adversary.

**Bucket D still gets written down.** The explanation is the asset — it is what
stops the next hunter spending a day re-explaining the same benign pattern, and
it is what becomes the tuning filter in a detection candidate.

## The unexplained result

The hard case is the result nobody can explain and nobody is worried about.

The rule: **an unexplained result is a C until someone proves otherwise.** Not a
D. Naming an owner and getting a real answer is the work; "probably fine" from
someone with no visibility into it is not an answer.

Where the hunt clock runs out before an explanation arrives, the result goes into
the report as open, with the owner it is waiting on, and onto the backlog. It
does not quietly become a D because the hunt ended.

## Coverage statements

> The percentages below are illustrative, not measured.

A negative result is worth writing only if it says what was actually ruled out.
Three elements, every time:

1. **Share of the Location** genuinely searched.
2. **Window** genuinely searched, against real retention.
3. **The evasion that would have survived** the gaps found in Stage 2.

> **Ruled out:** RMM agent installation by a non-deployment parent, across 61% of
> in-scope Windows servers, over 90 days, at high confidence.
>
> **Not ruled out:** the remaining 39% lack command-line logging, so an install
> performed by a renamed binary would not have been distinguished from a
> sanctioned one. Confidence there: low. See GAP-001.

Compare with "we hunted for RMM persistence and found nothing," which asserts
nothing at all while sounding like reassurance. The second version is the one
that survives contact with an incident three months later — and it is also the
argument that gets GAP-001 funded.

## The ADS template

Palantir's Alerting and Detection Strategy framework, used here because its
*Blind Spots* and *False Positives* sections are mandatory. They force the hunter
to hand over what they learned about the noise, which is the part that decides
whether a detection survives its first month in production.

One file per candidate in `04-detections/`:

```markdown
# ADS-NNNN: <short name>

## Goal
Plain-language description of the behavior this detects.

## Categorization
MITRE ATT&CK tactic and technique IDs.

## Strategy Abstract
How it works end to end: data sources, the logic, enrichment applied, and the
false-positive reduction already built in.

## Technical Context
What a responder needs to understand the alert — how the underlying technology
works, which field means what, why the behavior is suspicious.

## Blind Spots and Assumptions
What this cannot see, and what must hold for it to work at all. Link the gap
register entries from Stage 2.

## False Positives
Known benign sources, how to recognise them, and which are already filtered.

## Validation
Concrete steps to generate a true positive and confirm the detection fires.

## Priority
Severity, and the reasoning behind it.

## Response
Triage steps for the responder who receives this at 3am.

## Additional Resources
Reporting, the hunt package this came from, related detections.
```

## Worked detection candidate

> Invented, like every other example in these references, and built from public
> threat reporting. No real environment is described.

Abridged, from the RMM hunt used throughout these references:

> **Goal.** Detect remote monitoring and management agents being installed by a
> process other than the sanctioned software deployment system.
>
> **Categorization.** T1543.003 (Create or Modify System Process: Windows
> Service), T1219 (Remote Access Software).
>
> **Strategy Abstract.** Process creation events where the image is a known RMM
> agent and the command line indicates installation, excluding parents belonging
> to the deployment system. Enriched with asset owner from the CMDB. Hosts in the
> IT support organisational unit are filtered, since RMM there is sanctioned.
>
> **Blind Spots and Assumptions.** Assumes command-line logging, which covers 61%
> of servers (GAP-001). Detects by image name, so an RMM agent renamed before
> installation evades it — climbing to service-creation behavior independent of
> image name is the follow-on hunt. Assumes the sanctioned RMM inventory stays
> current; there is currently no owner for it (GAP-003).
>
> **False Positives.** Sanctioned rollouts outside the deployment system during
> change windows; vendor support sessions on OT hosts, which are pre-approved per
> ticket and identifiable by the initiating user.
>
> **Validation.** Install AnyDesk unattended on a lab host with a parent of
> `cmd.exe`; confirm the alert fires within the detection window.
>
> **Priority.** Medium. High where the host is in a datacentre VLAN, since an RMM
> agent there has no legitimate workflow.
>
> **Response.** Confirm whether a change record exists; identify the installing
> user; check for outbound connections to RMM cloud infrastructure; if no change
> record, escalate to incident response.

Note that the Blind Spots section states the exact evasion that defeats it, and
points at the hunt that would close it. That is the section detection
engineering actually reads.

## What makes a candidate ready

A candidate is ready to hand over when five things are true:

1. It fired on something real during the hunt, or the Validation steps have been
   run and it fired in a lab.
2. Its false positives are **enumerated**, not estimated — with the counts the
   hunt produced.
3. Its blind spots name the specific evasion, not "a determined attacker could
   evade this."
4. A responder who was not on the hunt could action it from the Response section
   alone.
5. Its expected volume is stated. A candidate with no volume estimate is a page
   waiting to happen.

Candidates failing any of these still go into `04-detections/`, marked as drafts
with the missing piece named. An honest draft is useful; a candidate that looks
finished and is not costs someone a month of alert fatigue.
