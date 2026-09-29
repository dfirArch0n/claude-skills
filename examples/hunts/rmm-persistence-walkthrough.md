# Worked example: RMM persistence, from advisory to detection

A complete pass through the `threat-hunt` skill, built entirely from **public**
sources. No real environment appears here; the estate described is invented to
carry the method. A real hunt writes these sections as separate files in a hunt
package — see `skills/threat-hunt/assets/templates/`.

**Public source:** CISA advisory AA24-109A (Akira ransomware) and the widely
reported pattern of ransomware affiliates using legitimate remote monitoring and
management tooling for persistence (MITRE ATT&CK T1219, T1543.003).

---

## Stage 0 — Frame the trigger

- **Type:** threat report / advisory
- **What it gave us:** roughly 40 file hashes, a dozen C2 addresses, and one
  sentence noting the group installs legitimate RMM software to keep access.
- **What we must build:** the climb, and whether any of it is relevant locally.

## Stage 1 — Design

### The climb

| Rung | What the climb yielded |
|---|---|
| 1–2 hash / address | The advisory's indicator list |
| 5 tool | AnyDesk, ScreenConnect, Atera — named in the reporting |
| 6 TTP | **An RMM agent installed on a host with no business running one, by a parent that is not the software deployment system** |

- **Rung hunted at:** 6
- **This is a:** hunt
- **Shelf life:** years — the behavior holds for any affiliate using any RMM tool,
  not only the three named
- **To climb higher:** not applicable; rung 6 reached

The indicator list is still swept, separately, as an hour's work with a one-day
shelf life. That sweep is recorded as a sweep, not as this hunt.

### Hypothesis (ABLE)

- **Actor:** ransomware affiliates, unattributed
- **Behavior:** installation of remote monitoring and management software for
  persistence (T1219, T1543.003)
- **Location:** Windows servers in datacenter VLANs
- **Evidence:** process creation with parent lineage and command line; service
  installation events; outbound connections to RMM cloud infrastructure

> **Statement:** An RMM agent has been installed on at least one in-scope server
> by a process outside the software deployment chain in the last 90 days.

### Gates

- **Falsifiable:** every RMM installation event in 90 days resolves to a parent
  in the deployment chain, or to a host in the IT support OU.
- **So-what:** a hit opens an incident. A miss still produces the sanctioned-RMM
  inventory question, which is a control gap either way.
- **Bounded:** datacenter VLANs; 90-day lookback; three days of hunting; abort if
  command-line telemetry proves absent across the whole scope.

## Stage 2 — Survey the data

| Evidence needed | ATT&CK data component | Exists | Populated | Retention | Coverage | Fidelity | Verdict |
|---|---|---|---|---|---|---|---|
| Process creation + parent | Process: Process Creation | Yes | Yes | 90d | 61% of servers | Command line truncated at 4096 | Partial → GAP-001 |
| Service installation | Service: Service Creation | Yes | Yes | 90d | 61% of servers | Good | Partial → GAP-001 |
| Outbound to RMM cloud | Network Traffic: Network Connection Creation | Yes | Yes | 30d | Perimeter only | No host attribution behind NAT | Partial → GAP-002 |
| Sanctioned-RMM inventory | — | **No** | — | — | — | — | Absent → GAP-003 |

**GAP-003 is the interesting one.** No security telemetry is missing; the
organization simply does not record which hosts are *supposed* to run
remote-access software. No query can separate sanctioned from unsanctioned. The
hunt proceeds by ranking installs by rarity instead, and the register carries the
real finding: an inventory nobody owns.

That is a bucket C result delivered before a single query ran.

### Why each gap exists

| Gap | Coverage shape | Cause | What we checked |
|---|---|---|---|
| GAP-001 | Never — the 39% have no Sysmon events at any point in 90 days, and the set matches an OU the baseline GPO omits | engineering | Compared first-seen per host against the GPO's OU scope |
| GAP-002 | Never — perimeter-only by design | engineering | Sensor placement is documented |
| GAP-003 | N/A — no telemetry involved | engineering | There is no inventory to break |

All three are engineering. Worth doing anyway: had any of those hosts *stopped*
reporting rather than never started, the correct next step would have been a
hunt for Defense Impairment (TA0112) rather than a ticket — and the shape of the
coverage data is what tells them apart. See `references/data-survey.md`.

## Stage 3 — Execute

### The Sigma rule

Filter over one log source, so Sigma carries it. The shipped canary rule
(`skills/threat-hunt/assets/canary.sigma.yml`) is this rule.

```sh
python3 $SKILL/scripts/convert.py queries/rmm-install.sigma.yml
# -> rmm-install.spl, rmm-install.kql, rmm-install.esql, rmm-install.cql
```

### Where Sigma stopped

GAP-003 means "unsanctioned" cannot be expressed as a filter — there is no field
for it. Rarity substitutes, and rarity is an aggregation, so this one is native:

```kql
// Native KQL, not Sigma.
// Sigma filters; this ranks by how few hosts run each RMM binary, which needs
// summarize ... by and a sort. There is no Sigma construct for "unusual here".
DeviceProcessEvents
| where Timestamp > ago(90d)
| where FolderPath has_any ("AnyDesk", "ScreenConnect", "Atera", "TeamViewer", "Splashtop")
| summarize Hosts = dcount(DeviceName), FirstSeen = min(Timestamp) by FolderPath
| where Hosts <= 5
| order by Hosts asc
```

### Triage

| Bucket | Count | Detail |
|---|---|---|
| **A** | 0 | No adversary installation found |
| **B** | 2 | ScreenConnect on a jump box, installed by a contractor 14 months ago, still live. AnyDesk on a build server, installed by a departed engineer. |
| **C** | 3 | GAP-003 (no sanctioned-RMM inventory); 39% of servers without command-line logging; the jump box's local admin group unreviewed since installation |
| **D** | 6 | Atera on IT support workstations — sanctioned, ticketed, documented |

Zero adversary findings. Five actionable results, two of which are live
unmanaged remote-access paths into the datacenter.

## Stage 4 — Act

### Coverage statement

> **Ruled out:** RMM agent installation by a non-deployment parent, across 61% of
> in-scope Windows servers, over 90 days, at high confidence.
>
> **Not ruled out:** the remaining 39% lack command-line logging, so an install
> by a renamed binary would not have been distinguished from a sanctioned one.
> Confidence there: low. See GAP-001.

### Detection candidate

ADS-0001, summarized in `references/findings-and-detections.md`. Status: ready.
Its Blind Spots section names the exact evasion — a renamed RMM binary — and
points at the follow-on hunt that would close it.

### Backlog

1. Service creation by image-independent behavior, to survive a renamed binary.
2. Outbound connections to RMM cloud infrastructure from hosts with no RMM agent
   installed — catches portable and browser-based RMM.
3. The same hypothesis for Linux servers, which this hunt scoped out.

### metadata.yml

```yaml
pyramid:
  rung: 6
  classification: hunt
  shelf_life: years
attack:
  version: "v19"
  techniques: ["T1219", "T1543.003"]
findings: {bucket_a: 0, bucket_b: 2, bucket_c: 3, bucket_d: 6, open: 0}
gaps: ["GAP-001", "GAP-002", "GAP-003"]
detections: ["ADS-0001"]
```

---

## What this example is meant to show

The hunt found no adversary. It still produced two live unmanaged access paths,
three control gaps, a detection candidate, and three follow-on hypotheses — and
a coverage statement precise enough to be worth something to whoever reads it
after the next incident.

That is the argument for giving outcomes 2, 3 and 4 their own stage and their own
file. A hunt that reported only "no adversary activity found" would have produced
none of it, and would have looked exactly the same from the outside.
