# Hunt charter: aa23-144a-volt-typhoon

- **Date opened:** 2026-09-30
- **Hunter:** worked example (no real environment)
- **Status:** planned: queries written and handed over, not run

## Trigger

- **Type:** threat report / advisory
- **Source:** [CISA AA23-144A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a),
  *People's Republic of China State-Sponsored Cyber Actor Living off the Land to
  Evade Detection*. Released May 24, 2023 by NSA, CISA, FBI and the Australian,
  Canadian, New Zealand and UK cyber agencies. The actor is also known as Volt
  Typhoon.
- **The request, as it arrived:** "Leadership saw the Volt Typhoon news. Can you
  sweep for the IOCs and tell us whether we're clean?"

### Source check

Everything below inherits this. Read the source before building on it.

- **Source read directly?** yes, the full advisory text on cisa.gov.
- **What it actually contains:** 11 SHA-256 hashes. **0 IP addresses.** 1 domain,
  `www.ip-api[.]com`, which is a legitimate IP-geolocation service. 15 file names,
  3 directory paths, 1 user-agent string and 4 YARA rules. Also dozens of command
  lines, 19 ATT&CK technique references (mapped against ATT&CK v13), specific
  Windows event IDs, a registry path, and a section of logging recommendations.
- **Where it contradicts the request:** the request assumes an indicator list
  that answers "are we clean?" The advisory has almost none. Its C2 traffic runs
  through compromised small-office routers "in the geographic area of the victim,"
  so even address indicators would not have helped. The advisory calls itself
  hunting guidance, and it is written around command lines, not indicators.
- **What it contains that nobody mentioned:**
  - The command lines, which are the real material.
  - ESENT Application-log events 216, 325, 326 and 327, which record an AD database
    copy even where command lines are not logged.
  - The port proxy registry path.
  - An explicit warning that many of these commands "could generate false positives
    when used alone."
- **Sent back to the requester before planning:** "A clean indicator sweep will
  not tell us we're clean from this actor, because the advisory has almost no
  indicators to sweep. I'll run the sweep, since it's an hour, and propose a
  behavior hunt that can actually answer the question."

## The climb

| Rung | What the climb yielded |
|---|---|
| 1–2 hash / address | 11 hashes; no addresses. C2 comes from local ISPs via hijacked routers, so addresses would rotate anyway |
| 3 domain | One legitimate service. Not an indicator |
| 4 network or host artifact | Output files named `__<epoch timestamp>` in `ADMIN$`; an IFM folder holding `Active Directory\ntds.dit` and `registry\SYSTEM`; keys under `Services\PortProxy\v4tov4`; files in `C:\Users\Public\Appfile`, `C:\Perflogs`, `C:\Windows\Temp` |
| 5 tool | `ntdsutil`, `netsh`, `wmic`, `vssadmin`, `ldifde`, Impacket `wmiexec`, Fast Reverse Proxy, Earthworm. Nearly all are **part of Windows**, so none of them can be blocked outright |
| 6 TTP | **Copying the AD database off a domain controller** (T1003.003) and **turning a server into an internal proxy** (T1090.001), both usually delivered through WMI (T1047) |

- **Rung hunted at:** 6
- **This is a:** hunt. The indicator sweep runs separately and is labeled as a
  sweep (`queries/ioc-sweep.md`).
- **Shelf life (estimate, not a measurement):** years. `ntdsutil` IFM and
  `netsh portproxy` belong to Windows, and changing them is not the actor's call.
- **To climb higher we would need:** nothing; rung 6 is the top.

**Why these two behaviors, out of everything in the advisory:** the advisory
describes a dozen techniques, and a hunt that chases all of them finishes none.
These two combine the highest consequence with the best signal-to-noise:

- **The AD database copy is the worst outcome.** The advisory says that if the
  database and SYSTEM hive leave the network, "the entire domain should be
  considered compromised."
- **Port proxies are rare.** The advisory calls them "not common for legitimate
  system administration," which keeps the false-positive load small.

Discovery, log clearing and the rest go to the backlog or run as supporting
context.

## Hypothesis (ABLE)

- **Actor:** Volt Typhoon, or any actor using the same tradecraft. The behaviors
  are not unique to one group, so attribution is left open.
- **Behavior:** an AD database copy made through `ntdsutil` IFM or a volume shadow
  copy (T1003.003, Credential Access), and/or a `netsh` port proxy used as an
  internal relay (T1090.001, Command and Control). Both are typically launched
  remotely through WMI (T1047).
- **Location:** the 6 domain controllers for the database copy; the ~400 Windows
  servers for the port proxy.
- **Evidence:**
  - Process creation with full command line (EDR; Windows 4688).
  - ESENT events in the DC Application log.
  - Registry writes under `Services\PortProxy`.
  - The current port proxy configuration on each server.
  - Security event 1102.

> **Statement:** In the last 180 days, someone has used `ntdsutil` or a shadow
> copy to write a copy of `ntds.dit` somewhere other than its live location on a
> domain controller, or has configured a port proxy on a Windows server, outside
> any documented change.

## Gates

- **Falsifiable: what result makes us abandon this?**
  Every IFM or shadow-copy access to `ntds.dit` in the window matches a
  documented directory services change, and the port proxy state sweep returns
  no entries on any server. That result is judged against the coverage the survey
  establishes, not against the whole estate.
- **So-what: if confirmed, what changes?**
  - A database copy confirmed as malicious means treating the domain as
    compromised and invoking incident response with an eviction plan.
  - A port proxy names the next host and the traffic to follow.
  - A negative still funds the telemetry gaps raised in the survey, and hands
    detection engineering two candidates.
- **Bounded**
  - Scope: 6 domain controllers and ~400 Windows servers. Workstations are out
    of scope.
  - Window: 180 days wanted. The survey found 30 days is what command-line
    telemetry can actually reach (GAP-001).
  - Clock: 5 working days.
  - Abort criteria: stop early if neither command-line telemetry nor ESENT events
    exist for the domain controllers; that finding goes straight to the report as
    the result.

**Why 180 days:** a later advisory,
[CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
(February 7, 2024), reports this actor "maintaining access and footholds within
some victim IT environments for at least five years." No realistic log retention
reaches that far. 180 days is a practical compromise, and the port proxy state
sweep reaches past it because it reads current configuration rather than logs.

## Assumptions

- **The organization is invented.** See `README.md` for the estate this example
  assumes. Nothing here describes a real network.
- ATT&CK IDs were checked against ATT&CK v19 on 2026-09-30. The advisory's
  T1070.001 (clear Windows event logs) is T1685.005 in v19, and its general
  T1090 (proxy) is narrowed here to T1090.001 (internal proxy), whose ATT&CK
  page names `netsh portproxy` directly.
