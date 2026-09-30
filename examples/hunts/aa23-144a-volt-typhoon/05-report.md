# Hunt report: aa23-144a-volt-typhoon

> This is a **worked example**. The organization is invented and the queries were
> never run. The report is written at the point a real hunt hands its queries to
> the people who run them. Everything below the line is what the hunt has already
> delivered by then, and every statement traces to a filled-in field in this
> package.

- **Dates:** 2026-09-30 (planned, not executed)
- **Hunter:** worked example
- **Rung hunted at:** 6 (TTP)  |  **Hunt or sweep:** hunt, with a separate
  indicator sweep

---

## Executive summary

Leadership asked whether we are clean of Volt Typhoon, the Chinese
state-sponsored actor in CISA advisory AA23-144A. An indicator sweep cannot
answer that, because the advisory contains 11 file hashes and no IP addresses.
The actor works mostly through tools built into Windows rather than malware.
We are therefore hunting two behaviors instead:

- copying the Active Directory database off a domain controller, which would mean
  the whole domain is compromised;
- turning a server into a hidden relay.

Before running a single search, the preparation found eight blind spots, each
with an owner and a fix. The two most important:

- Our domain controllers stopped recording command details in May, and nobody
  noticed.
- 48 of our 400 servers have no endpoint monitoring, 17 of which stopped
  reporting months ago.

Both are being chased as possible signs of tampering, not just as IT problems.
The searches are written and ready to run, along with a triage guide and a draft
alert for the relay behavior.

## What we looked for

Whether, in the last 180 days, anyone copied the AD database on a domain
controller or configured a port proxy on a Windows server outside a documented
change. These two behaviors were chosen from the advisory's dozen:

- **The database copy is the worst outcome.** The advisory says that if it leaves
  the network, the entire domain should be considered compromised.
- **Port proxies are rare.** A hit is rarely noise.

## What we found

- **Malicious (A):** not yet searched.
- **Unsanctioned (B):** not yet searched.
- **Systems issues (C):** 3, all found by the survey:
  - 31 servers were never enrolled in EDR.
  - No list exists of hosts allowed to run a port proxy.
  - No alert fires when a log source stops sending a field.
- **Explained (D):** none yet. Four expected benign patterns are written down
  in advance so triage is consistent; they are not counted.
- **Open:** 2, both possible tampering:
  - DC command lines stopped on one day in May.
  - 17 servers stopped reporting to EDR.

## What we cannot see

The gap register (`02-gaps.yml`) holds eight entries. In short:

- **We can look back 30 days in detail, and the question is 180.** EDR keeps
  command lines for 30 days (GAP-001). The SIEM keeps a year, but the DCs stopped
  sending command lines in May (GAP-003).
- **The most reliable evidence of an AD database copy is not collected.** ESENT
  events on the DCs record it even if the tool was renamed. They never leave the
  DC (GAP-002).
- **A log wipe on a server would go unseen.** We collect event 1102 from DCs only
  (GAP-005).
- **48 servers are dark to EDR** (GAP-006), there is no WMI tracing (GAP-007), and
  there is no internal traffic record (GAP-008).

| Gap | Established how | Status |
|---|---|---|
| GAP-001 | measured (license terms) | verified |
| GAP-002 | measured (collection config) | verified |
| GAP-003 | measured (field population by date) | verified; **cause undetermined** |
| GAP-004 | **assumed** (vendor docs silent) | **unverified**: ten-minute test requested |
| GAP-005 | measured (collection config) | verified |
| GAP-006 | measured (EDR console) | verified; cause undetermined for 17 hosts |
| GAP-007 | measured (Windows default, confirmed on hosts) | verified |
| GAP-008 | measured (no collector exists) | verified |

We believe EDR records every registry write under the port proxy key, but
nobody has checked. GAP-004 is raised as an assumption, not a fact.

## Coverage

Not yet established, because the queries have not run. `03-findings.md` holds the
statement as it would read if every query came back clean. In one sentence: it
would rule out a command-line-driven AD database copy for 30 days, and a
*currently configured* port proxy on every server that answered the sweep. It
would not rule out `ntdsutil` run interactively or renamed, or a proxy that was
created and removed on an unmonitored server.

## Detections proposed

- **ADS-0001: port proxy configured on a Windows server.** Draft; needs volume
  numbers from the first run and the GAP-004 test.

## Backlog

- If GAP-003 has no change record: hunt the GPO edit. Who changed audit policy,
  and what else did that account do?
- **Credential harvesting beyond the AD database:** the advisory's
  `reg query` against PuTTY, RealVNC and OpenSSH keys, and `reg save hklm\sam`
  on member servers.
- **Initial access:** the advisory's edge-device CVEs (ManageEngine
  ADSelfService Plus CVE-2021-40539, FatPipe CVE-2021-27860), and webshells
  checked with its YARA rules.
- **Fast Reverse Proxy and Earthworm:** the advisory's callback ports (8080,
  8443, 8043, 8000, 10443) in perimeter firewall logs.
- Event 104 (System log cleared) alongside 1102. Not in the advisory; check
  before adding.

## Retro

- **The gates, in hindsight:**
  - Falsifiable: yes, and the survey showed exactly how much of the falsifying
    evidence we can actually see.
  - So-what: held. A positive means eviction, and a negative still funds eight
    fixes.
  - Clock: not tested.
- **What would make the next one faster:**
  - A standing data-health check (C-3), so the survey is not the first time
    anyone looks at field population.
  - A maintained list of sanctioned port proxies (C-2).
