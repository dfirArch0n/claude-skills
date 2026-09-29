# The climb, and the hypothesis it produces

Reached from Stage 1 of `SKILL.md`. Read this when a trigger needs converting
into a hypothesis worth spending a week on.

## Contents

- [The pyramid](#the-pyramid)
- [How to climb](#how-to-climb)
- [Worked climb: a ransomware advisory](#worked-climb-a-ransomware-advisory)
- [Worked climb that stalls: a phishing IOC dump](#worked-climb-that-stalls-a-phishing-ioc-dump)
- [Worked climb that overreaches](#worked-climb-that-overreaches)
- [ABLE, weak to strong](#able-weak-to-strong)
- [The three gates, applied](#the-three-gates-applied)

## The pyramid

David Bianco's Pyramid of Pain ranks indicator types by what it costs the
adversary when you detect on them. Bottom is trivial for them to change; top
forces them to relearn how they operate.

| Rung | Indicator | Cost to the adversary | Shelf life |
|---|---|---|---|
| 6 | **TTPs** | Retrain, redesign the operation | Years |
| 5 | **Tools** | Find or build a replacement | Months |
| 4 | **Network / host artifacts** | Return to the lab, reconfigure, recompile | Weeks |
| 3 | **Domain names** | Register another; minutes, and a small bill | Days |
| 2 | **IP addresses** | Move; minutes, free | Hours |
| 1 | **Hash values** | Change a byte | Seconds |

Bianco's point is that detecting across enough TTPs leaves an adversary two
options: give up, or reinvent themselves from scratch. Nothing lower does that.

The rung is not a quality score for the hunt — an IOC sweep during an active
campaign can be exactly the right call. It is a **shelf-life** estimate, and
recording it is how a hunt programme learns whether it is buying years or hours.

## How to climb

Walk the chain, one link at a time, and stop where the telemetry stops:

> artifact → which **tool** produced it → what **behavior** does that tool
> require → which **TTP** does that behavior serve

Two questions keep the climb honest:

- **"What must be true for this to work?"** drives you up. An adversary using a
  given tool must invoke it somehow, and that invocation is a behavior.
- **"Could a different tool do this same thing?"** tests whether you have
  actually climbed. If your query only finds the one binary named in the report,
  you are still on rung 5 wearing a rung 6 hat.

Stop climbing when the next rung has no evidence behind it. A TTP-level
hypothesis over telemetry you do not collect is not a hunt; it is a gap register
entry (Stage 2) plus a hunt you run next quarter.

## Worked climb: a ransomware advisory

**Trigger.** An advisory lists 40 hashes, 12 C2 addresses, and a line noting the
group uses legitimate remote-access tooling for persistence.

| Rung | What the climb yields |
|---|---|
| 1–2 | The hashes and addresses. Sweep them; they cost an hour and expire in one. |
| 5 | The named RMM tools — AnyDesk, ScreenConnect, Atera. |
| 6 | **An RMM agent installed on a host that has no business running one, by a process that is not the software deployment system.** |

Rung 6 is the hunt. It finds this group, the next group that reads the same
playbook, and the sysadmin quietly running ScreenConnect on a jump box — which is
a bucket B or C finding you would never have reached from the hash list.

**Evidence** it needs: process creation with parent lineage, service
installation, and a reliable inventory of which hosts are *supposed* to run RMM.
That last one is usually the gap this hunt discovers.

## Worked climb that stalls: a phishing IOC dump

**Trigger.** A sharing group posts 300 sender addresses and 60 URLs. No
behavioral detail.

The climb gets one rung: the URLs imply credential-harvesting pages, so the
behavior is a user submitting credentials to a newly-registered domain. But with
no proxy logging of POST bodies and no way to tell a submission from a page view,
the evidence stops.

**Correct outcome.** Run the sweep, and say so in the charter: *rung 3, IOC
sweep, shelf life days.* Then raise the gap — proxy telemetry that distinguishes
submission from browse — and put the real hunt on the backlog. The sweep took
two hours. The gap entry is worth more than the sweep.

This is the common case. Most triggers stall. Naming the stall is the discipline.

## Worked climb that overreaches

**Trigger.** One report of a malicious scheduled task.

The tempting climb goes: scheduled task → persistence → *hunt all persistence
mechanisms*. That is a programme, not a hunt. It has no falsifiable result, no
clock that holds, and it produces a result set no one will finish reading.

**Correct outcome.** Stay at one or two links: *scheduled tasks created on
servers by a non-administrative account outside change windows*. Bounded,
falsifiable, finishable in three days. Put "the rest of persistence" on the
backlog as its own hypotheses.

The climb is meant to raise the rung, not widen the scope. Those are different
axes, and conflating them is the most common way a hunt dies.

## ABLE, weak to strong

ABLE (Actor, Behavior, Location, Evidence) comes from the PEAK framework. Each
element narrows the hunt until it is finishable.

**Weak:** "Hunt for Cobalt Strike."

Not falsifiable, unbounded, and named at rung 5 — it finds Cobalt Strike and
nothing else.

**Strong:**

- **Actor** — ransomware affiliates, unattributed.
- **Behavior** — named-pipe impersonation for privilege escalation
  (ATT&CK T1134.001), which beacon-style implants need regardless of the
  implant's brand.
- **Location** — Windows servers in the datacentre VLANs.
- **Evidence** — Sysmon Event ID 17/18 (pipe created/connected), joined to
  process creation for the creating process. Present if a short-lived pipe with a
  random-looking name is created by a process that is not a known service host.

Strong because the behavior survives the tool changing its name, the location
bounds the data, and the evidence names the field you will actually query.

**Where Actor is unknown**, leave it out. Most good hunts are actor-agnostic —
and a hunt that names an actor it cannot evidence is telling itself a story.

## The three gates, applied

Run all three before writing a query. Write the answers into the charter.

### Falsifiable

> What result would make me abandon this?

"Every named-pipe creation on these servers resolves to one of four known
service binaries, across 90 days" is an answer. "I didn't find anything yet" is
not — it is a statement about effort, not evidence.

If nothing would falsify the hypothesis, it is usually because the behavior is
defined too loosely ("suspicious PowerShell"). Tighten the behavior until a
negative result becomes possible.

### So-what

> If this is confirmed, what changes?

An answer names a decision: an incident opens, a control gets funded, a
configuration changes, a detection ships. If the honest answer is "we would know
that is happening," the hunt is producing trivia. Either find the decision it
feeds, or spend the week on a hypothesis that has one.

This gate bites hardest on hunch-driven hunts, which is exactly where it earns
its keep.

### Bounded

> Which systems, which window, and how long do I get?

- **Scope** — name the estate segment, not "the environment."
- **Window** — the lookback the hypothesis needs, checked against actual
  retention in Stage 2.
- **Clock** — a maximum duration, set now. PEAK's phrasing is the right
  instinct: *"I'll hunt this for three days."*
- **Abort criteria** — the condition that ends it early. Usually: the evidence
  turns out to be absent, or the first day's results show the hypothesis was
  already wrong.

A hunt without a clock does not fail. It just never finishes, which is worse,
because nothing gets written down.
