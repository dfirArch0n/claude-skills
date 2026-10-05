# Findings: aa23-144a-volt-typhoon

**The queries in this example were never run**, so buckets A and B are empty,
and they are empty because nothing was searched, not because the hunt found
nothing. What is here is everything the hunt produced *before* the first query
ran, plus the triage guide the hunter would use once results came back.

That first part is not small. Half of this hunt's deliverables arrived during
the data survey.

## Bucket A — confirmed malicious

None. Queries not run.

## Bucket B — benign but unsanctioned

None yet. Queries not run.

## Bucket C — systems issue on the killchain

Found during the survey, before any query:

| # | What | Owner | Ask | Status |
|---|---|---|---|---|
| C-1 | 31 Windows servers were never enrolled in EDR. Nobody knew the number until the survey counted it | Endpoint engineering | Enroll them (GAP-006) | Open |
| C-2 | No record of which hosts are allowed to run a port proxy. Any proxy found cannot be judged sanctioned or not without asking around | Infrastructure | Keep a list, even a short one. The advisory recommends allowing proxies only for as long as they are needed | Open |
| C-3 | Nothing alerts when domain controllers stop sending command lines. The field has been empty for months and nobody noticed | SIEM platform team | Add a data-health check on field population, not just event volume | Open |

## Bucket D — explained and normal

None yet. Queries not run.

### Expected benign patterns (written in advance, not results)

Written down before the results arrive so that triage is consistent. They are
not counted as findings. Each one that the results confirm becomes a tuning
filter in a detection candidate.

| # | Pattern | Explanation | Source of explanation |
|---|---|---|---|
| D-1 | `ntdsutil ... ifm` run by a directory services admin, writing into a documented path, during a DC build | Install-from-media is a legitimate way to promote a new DC | Directory services change record |
| D-2 | `netsh interface portproxy` on a developer workstation, forwarding to a WSL2 or container address | A widely used workaround for reaching Linux services inside WSL2 from the network | Out of scope here (workstations), but it will appear if anyone widens the scope |
| D-3 | Several discovery tools in one burst, from a monitoring or inventory service account | Monitoring agents run `ipconfig`, `systeminfo` and similar on a schedule | Monitoring team; confirm the account and schedule |
| D-4 | Event 1102 on a newly built host | Some build processes clear logs before a host enters service | Build team; the host's build date |

## Open — unexplained when the clock ran out

| # | What | Waiting on | Backlog item |
|---|---|---|---|
| O-1 | Command lines stopped on all six DCs on the same day in May (GAP-003) | Directory services: the audit policy GPO change record for that day | If no record exists, this becomes a hunt: who edited the GPO, and what did that account do next? |
| O-2 | 17 servers stopped reporting to EDR between two and nine months ago (GAP-006) | Endpoint engineering: a reason for each one | Any server without a reason gets the port proxy state sweep and a manual review first |

## Triage guide: how results would be read

A query hit alone never lands in bucket A. The first column below means
**escalate to incident response as a suspected compromise**; it becomes A only
when incident response confirms it. Until then it is Open.

| Query hit | Escalate as suspected compromise when | Goes to D when |
|---|---|---|
| `ntdsutil` IFM, shadow-copy `ntds.dit`, or ESENT naming a non-standard path | No matching change record; launched via `wmic process call create` or with output redirected to `ADMIN$`; written to `C:\Windows\Temp`, `C:\Users\Public` or `C:\Perflogs` | A change record matches the account, host, time and path |
| Port proxy on a **server** (log or state sweep) | Listens on `0.0.0.0`; forwards to an internal address on a database or admin port; no owner claims it | An owner claims it, it matches a change, and it has an end date. **Still file a C-2 entry** so it gets written down |
| `wmiexec` pattern | Almost always. The `ADMIN$\__<epoch>` redirect is distinctive | Authorized penetration testing only, confirmed with the test's organizer |
| Discovery burst | The same account also appears in any hit above | Matches D-3 |
| Event 1102 | Any host in scope, unless D-4 explains it. Either way, that host's other empty results are recorded as **unknown** | Matches D-4 |

Anything that fits neither column is a **C** until someone proves otherwise.

## Coverage statement

This is written in advance, as it would read **if every query came back clean**.
The point is that a negative result is still a specific statement, and here is
exactly what it would and would not cover:

**Ruled out:**

- An AD database copy **driven from the command line** (`ntdsutil` with its
  arguments, or a shadow copy followed by a copy of `ntds.dit`) on 6/6 domain
  controllers over the last 30 days, at high confidence (EDR command lines).
- The same over days 31–180, at low confidence: 4688 process names show
  whether `ntdsutil.exe` ran, but not with what arguments (GAP-003).
- Any port proxy **currently configured** on servers that remote management
  reaches, at high confidence, whatever its age.

**Not ruled out:**

- `ntdsutil` used **interactively**, or under a renamed binary, at any point in
  the window. Neither leaves the arguments on a command line. ESENT events would
  show both, but they are not collected (GAP-002). An `ntdsutil.exe` process on a
  DC with no matching change is therefore escalated even without arguments.
- A port proxy created and then deleted on one of the 48 servers without EDR
  (GAP-006).
- A port proxy created and deleted within 30 days on an EDR server, if registry
  events are not all kept (GAP-004, unverified).
- Anything on a server whose logs were cleared, since 1102 is not collected from
  servers (GAP-005).
