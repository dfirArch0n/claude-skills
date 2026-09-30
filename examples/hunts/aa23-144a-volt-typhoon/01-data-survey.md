# Data survey: aa23-144a-volt-typhoon

Run before the first query. The estate is invented (see `README.md`). The results
are invented too, but they were chosen because real surveys commonly turn up
exactly these shapes: a field that exists but is empty, retention shorter than the
question, a log nobody forwards, and a coverage number nobody had checked.

| Evidence needed | ATT&CK data component | Exists | Populated | Retention | Coverage | Fidelity | Verdict |
|---|---|---|---|---|---|---|---|
| Process creation + command line (EDR) | Process Creation (DC0032) | Yes | Yes | **30 days** | 6/6 DCs; **352/400 servers** | Good; parent process recorded | Partial → GAP-001, GAP-006 |
| Process creation + command line (Windows 4688, in SIEM) | Process Creation (DC0032) | Yes, DCs only | **No: command-line field empty since a date in May** | 365 days | 6/6 DCs | Event present, command line absent | Partial → GAP-003 |
| ESENT 216/325/326/327 (DC Application log) | Application Log Content (DC0038) | On the DC only | Unknown | Local log rollover, typically days | 0/6 DCs forwarded | — | **Absent** → GAP-002 |
| Registry writes under `Services\PortProxy` | Windows Registry Key Modification (DC0063) | Yes (EDR) | **Unverified** | 30 days | Same as EDR | Vendor does not document whether every value write is kept | Partial → GAP-004 |
| Current port proxy configuration | — (state, not a log) | Yes: every host holds it | Yes | Indefinite, until removed | Any host remote management reaches | Exact | **Available** |
| Security event 1102 | Application Log Content (DC0038) | DCs only | Yes | 365 days | 6/6 DCs; **0/400 servers** | Good | Partial → GAP-005 |
| WMI activity (who ran what through WMI) | WMI Creation (DC0008) | No | — | — | 0 | Off by default, as the advisory notes | **Absent** → GAP-007 |
| Traffic through a port proxy (east-west) | Network Traffic Flow (DC0078) | No | — | — | Perimeter firewall only | — | **Absent** → GAP-008 |

The Evidence column comes straight from the charter's hypothesis. The ATT&CK
data components (checked on attack.mitre.org, 2026-09-30) give each row a
common name, so gaps can be compared across hunts.

## Why each gap exists

| Gap | Coverage shape | Cause | What we checked |
|---|---|---|---|
| GAP-001 retention | never | engineering | EDR license tier caps raw telemetry at 30 days; it has never been longer |
| GAP-002 ESENT not forwarded | never | engineering | The SIEM collection config for DCs names only the Security log |
| **GAP-003 command line empty** | **stopped** | **undetermined** | **All six DCs stopped populating the field on the same day in May. No change ticket found yet** |
| GAP-004 registry fidelity | never verified | undetermined | Vendor documentation is silent; nobody has tested it |
| GAP-005 1102 on servers | never | engineering | SIEM collects Security logs from DCs only, by design, for cost |
| **GAP-006 servers without EDR** | **never and stopped** | **engineering (31) / undetermined (17)** | **EDR console: 31 servers were never enrolled; 17 enrolled and then stopped reporting between two and nine months ago** |
| GAP-007 WMI tracing | never | engineering | Windows default; the advisory says the same |
| GAP-008 east-west traffic | never | engineering | No internal flow collection exists |

Two of these are not ordinary engineering gaps:

- **GAP-003.** A field that was populated and then went empty on every DC at once
  is most likely a Group Policy change. Changing audit policy is also exactly what
  an actor with domain admin rights would do before running `ntdsutil`. Until
  someone produces the change record, this is a lead, not a gap.
- **GAP-006, the 17 servers that stopped.** An EDR agent that stops reporting is
  either a broken agent or a removed one. ATT&CK files the second under Defense
  Impairment (TA0112).

Both go into the findings as **Open** items and are chased with the same priority
as the queries.

## Blind spots

- **Renamed `ntdsutil.exe`.** A copied, renamed binary defeats the command-line
  rules. The ESENT events would still fire, but they are not collected (GAP-002).
- **Interactive `ntdsutil`.** Commands typed at the `ntdsutil` prompt never appear
  on the process command line.
- **48 servers with no EDR at all** (GAP-006): no process or registry telemetry.
- **Anything older than 30 days** in process telemetry (GAP-001), except what the
  port proxy state sweep can still see.

## Confidence carried into findings

- **AD database copy, DCs:** high confidence across 6/6 DCs for the last 30 days
  via EDR. Low for days 31–180: 4688 events still record that `ntdsutil.exe` ran
  and under which account, but not its arguments (GAP-003), and ESENT events are
  not collected (GAP-002). A renamed `ntdsutil` run 31 or more days ago would
  survive.
- **Port proxy, servers:** high confidence for the *current* state on every
  server remote management reaches, whatever its age. Medium for proxies created
  and deleted within the last 30 days on the 352 EDR servers, because registry
  fidelity is unverified (GAP-004). None for proxies created and deleted on the
  48 servers without EDR.
- **Log clearing:** DCs only (GAP-005).

## Gaps raised

GAP-001, GAP-002, GAP-003, GAP-004, GAP-005, GAP-006, GAP-007, GAP-008. See
`02-gaps.yml`.
