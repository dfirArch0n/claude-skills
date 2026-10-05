# Worked example: Volt Typhoon, from CISA advisory to hunt package

A complete threat hunt plan built from one public advisory,
[CISA AA23-144A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a)
(*PRC State-Sponsored Cyber Actor Living off the Land to Evade Detection*, May
2023), using the [`threat-hunt`](../../../skills/threat-hunt/) skill.

**What this is:** the full package a hunter would hand over at the moment the
searches are ready to run.

**What this is not:** a record of a real hunt. There is no environment behind
it. The organization is invented and the queries were never run.

## The request, and why it was the wrong question

> "Leadership saw the Volt Typhoon news. Can you sweep for the IOCs and tell us
> whether we're clean?"

The advisory has **11 file hashes and 0 IP addresses**. Its one domain is a
legitimate geolocation service. Volt Typhoon works with tools that ship with
Windows, so an indicator sweep can come back clean on a fully compromised
network. The hunt starts by saying so, then hunts the behavior.

## How to read this package

| Order | File | What it shows |
|---|---|---|
| 1 | [`00-charter.md`](00-charter.md) | **The source check**: what the advisory actually contains versus what was asked. **The climb** from indicators to behavior. The hypothesis, and the three gates it must pass |
| 2 | [`01-data-survey.md`](01-data-survey.md) | Whether the logs needed to test the hypothesis actually exist. They mostly don't, and two of the gaps look like tampering |
| 3 | [`02-gaps.yml`](02-gaps.yml) | Eight blind spots, each with a cause, an owner and a specific ask |
| 4 | [`queries/`](queries/) | Seven Sigma rules converted to Splunk and Microsoft KQL, plus native queries where Sigma stops, and **what a hit looks like** for each |
| 5 | [`03-findings.md`](03-findings.md) | What was found before any query ran, the triage guide, and the coverage statement a clean result would earn |
| 6 | [`04-detections/`](04-detections/) | A detection candidate in Palantir's ADS format, with its blind spots written down |
| 7 | [`05-report.md`](05-report.md) | The executive summary: what leadership actually gets |
| — | [`metadata.yml`](metadata.yml) | The machine-readable record: techniques, rung, counts, gaps |

## The five outcomes, and where each one lives here

A hunt that only asks "is the badness here?" uses one of its five possible
outcomes. This package shows all five:

| Outcome | Where it lives |
|---|---|
| 1. Previously unknown badness | Buckets A and B in `03-findings.md`. Empty here, because nothing ran |
| 2. **Signals you do not collect** | `02-gaps.yml`: eight gaps, delivered before any search |
| 3. **Searches that become detections** | `04-detections/ADS-0001` |
| 4. **Systems issues** along the kill chain | Bucket C: servers never enrolled in EDR, no port proxy inventory, no data-health alerting |
| 5. A sharper hunter | The retro in `05-report.md`, and the backlog |

Outcomes 2, 3 and 4 were all delivered without running a single query, and
that is the point of this example.

## The invented estate

So that the data survey has something concrete to survey:

- One Active Directory domain with **6 domain controllers** and about **400
  Windows servers**. Workstations are out of scope.
- An **EDR** product on all DCs and 352 of the servers, keeping 30 days of raw
  process and registry telemetry. Queries are shown in Microsoft Defender XDR's
  KQL as one common example.
- A **SIEM** keeping 365 days, receiving the Windows Security log from DCs only.
  Queries are shown in Splunk SPL as one common example.
- No Sysmon, no WMI tracing, no internal flow logs.

Nothing here describes a real organization.

## Sources

- [CISA AA23-144A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a):
  the trigger, all command lines, indicators, event IDs and the registry path.
- [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a):
  the "at least five years" dwell time behind the 180-day window.
- [MITRE ATT&CK](https://attack.mitre.org/) v19: technique and data component
  IDs, checked 2026-09-30.
