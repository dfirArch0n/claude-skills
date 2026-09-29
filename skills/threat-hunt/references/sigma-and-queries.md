# Sigma, conversion, and the queries Sigma cannot write

Reached from Stage 3 of `SKILL.md`. Everything here was verified against
sigma-cli 3.1.0 / pySigma 1.5.1 on 2026-09-29.

## Contents

- [Setup, and the trap in it](#setup-and-the-trap-in-it)
- [Targets](#targets)
- [Pipelines](#pipelines)
- [The ES|QL pipeline gap](#the-esql-pipeline-gap)
- [One rule, five platforms](#one-rule-five-platforms)
- [Where Sigma stops](#where-sigma-stops)
- [Native patterns per platform](#native-patterns-per-platform)
- [Conversion gotchas](#conversion-gotchas)

## Setup, and the trap in it

```sh
skills/threat-hunt/scripts/setup_sigma.sh          # install
skills/threat-hunt/scripts/setup_sigma.sh --check  # verify by converting a canary rule
```

The trap the script exists to route around: **`sigma plugin install` fails inside
a `uv tool` environment.** It shells out to `python -m pip`, and uv tool
environments ship without pip, so every plugin install dies with
`No module named pip` buried under a `CalledProcessError` traceback. The backends
go in as `--with` dependencies instead:

```sh
uv tool install sigma-cli --force \
  --with pysigma-backend-splunk \
  --with pySigma-backend-kusto \
  --with pysigma-backend-elasticsearch \
  --with pysigma-backend-crowdstrike
```

`uv` puts the `sigma` executable in `~/.local/bin`, which is often not on PATH.
Run `uv tool update-shell` once, or call the binary by full path.

## Targets

Target identifiers are **not** the plugin names. Asking for `-t crowdstrike` or
`-t elasticsearch` fails; the plugin is the package, the target is the language.

| Target | Language | Platform | Pipeline required |
|---|---|---|---|
| `splunk` | SPL, and tstats via `-f data_model` | Splunk | Yes |
| `splunk_spl2` | SPL2 | Splunk | Yes |
| `kusto` | KQL | Sentinel, Defender XDR, Azure Monitor | No |
| `lucene` | Lucene | Elastic | Yes |
| `esql` | ES\|QL | Elastic | Yes |
| `eql` | EQL — sequences, behavioral chains | Elastic | Yes |
| `elastalert` | Elastalert rules | Elastic | Yes |
| `log_scale` | CQL | **CrowdStrike NG-SIEM / Falcon LogScale** | Yes |

Output formats worth knowing: `splunk` offers `default`, `savedsearches` and
`data_model` (tstats against the CIM Endpoint data model — much faster over long
windows, which is what hunting does).

## Pipelines

A pipeline maps Sigma's generic field names onto a platform's real schema.
Getting it wrong produces a query that runs and returns nothing.

| Target | Pipeline | Maps to |
|---|---|---|
| `splunk` | `splunk_windows` | Windows log source conditions |
| `splunk` | `splunk_cim` | CIM data model — pair with `-f data_model` |
| `splunk` | `splunk_sysmon_acceleration` | Sysmon search acceleration keywords |
| `kusto` | `microsoft_xdr` | Defender XDR tables (`DeviceProcessEvents`) |
| `kusto` | `sentinel_asim` | Sentinel ASIM (`imProcessCreate`) |
| `kusto` | `azure_monitor` | Azure Monitor tables |
| `lucene`, `eql` | `ecs_windows` | ECS via Winlogbeat 7+ |
| `lucene`, `eql` | `ecs_zeek_beats`, `ecs_zeek_corelight` | Zeek network data |
| `lucene`, `eql` | `ecs_macos_esf`, `ecs_kubernetes` | macOS ESF, Kubernetes audit |
| `log_scale` | `crowdstrike_falcon` | NG-SIEM native — `#event_simpleName` tagged |
| `log_scale` | `crowdstrike_fdr` | Falcon Data Replicator exports |

`crowdstrike_falcon` versus `crowdstrike_fdr` is a real choice: the Falcon
pipeline emits `#event_simpleName`, using LogScale's tag index, which is
dramatically faster. Use FDR only when reading replicated data out of a lake.

## The ES|QL pipeline gap

`sigma list pipelines esql` returns only the two CrowdStrike pipelines. The ECS
pipelines register themselves for `elasticsearch`, `eql`, `lucene` and
`opensearch` — **not for `esql`** — so the obvious command is rejected:

```
Error: The pipeline 'ecs_windows' is not intended to be used with the target esql.
```

The mapping is fine; only the registration is missing. Override the check:

```sh
sigma convert -t esql -p ecs_windows --disable-pipeline-check rule.yml
```

That produces correct ECS field names. `convert.py` applies the override for
`esql` automatically and records it in `conversion-manifest.json`, so the next
hunter does not lose an hour to it.

## One rule, five platforms

The same rule — RMM agent installed by a parent that is not the deployment
system — converted for real:

**Splunk** (`-p splunk_windows`)

```
Image IN ("*\\AnyDesk.exe", "*\\ScreenConnect.ClientService.exe", "*\\AteraAgent.exe")
CommandLine="*--install*" NOT (ParentImage IN ("*\\ccmexec.exe", "*\\msiexec.exe"))
```

**Defender XDR** (`-t kusto -p microsoft_xdr`)

```kql
DeviceProcessEvents
| where ((FolderPath endswith "\\AnyDesk.exe" or FolderPath endswith "\\ScreenConnect.ClientService.exe"
   or FolderPath endswith "\\AteraAgent.exe") and ProcessCommandLine contains "--install")
   and (not((InitiatingProcessFolderPath endswith "\\ccmexec.exe"
   or InitiatingProcessFolderPath endswith "\\msiexec.exe")))
```

**Sentinel ASIM** (`-t kusto -p sentinel_asim`) resolves to `imProcessCreate` with
`TargetProcessName` / `ActingProcessName` — different table, different fields,
same rule. This is the payoff for writing logic once.

**Elastic EQL** (`-t eql -p ecs_windows`)

```
any where ((process.executable.caseless like~ ("*\\AnyDesk.exe", "*\\ScreenConnect.ClientService.exe",
  "*\\AteraAgent.exe")) and process.command_line:"*--install*")
  and (not (process.parent.executable.caseless like~ ("*\\ccmexec.exe", "*\\msiexec.exe")))
```

**CrowdStrike NG-SIEM** (`-t log_scale -p crowdstrike_falcon`)

```
event_platform=/^Win$/i #event_simpleName=/^ProcessRollup2$/i or #event_simpleName=/^SyntheticProcessRollup2$/i
ImageFileName=/\\AnyDesk\.exe$/i or ImageFileName=/\\ScreenConnect\.ClientService\.exe$/i
or ImageFileName=/\\AteraAgent\.exe$/i CommandLine=/--install/i
not (ParentBaseFileName=/^ccmexec\.exe$/i or ParentBaseFileName=/^msiexec\.exe$/i)
```

## Where Sigma stops

Sigma describes **a filter over one log source**. Hunting frequently needs
comparison, and comparison is outside the language.

| Hunting move | Sigma? | Why |
|---|---|---|
| Match known-bad field values | **Yes** | This is what Sigma is |
| Sigma correlation rules (count, temporal) | **Partly** | Real, but backend support varies; `log_scale` supports them, others less so |
| Stack counting / least-frequency analysis | No | Requires aggregation, then ranking by rarity |
| Long-tail outliers by entity | No | Requires grouping and a distribution |
| Join across two sources | No | One log source per rule, by design |
| Sessionise then compare to a baseline | No | Requires state across events |
| Compare this week against last | No | Requires two windows and a diff |

When you drop to native, write the reason into the query file header:

```
-- Native ES|QL, not Sigma.
-- Sigma filters; this ranks by rarity across the estate, which needs
-- STATS ... BY and a sort. There is no Sigma construct for "unusual here".
```

That note stops the next hunter re-deriving the decision, and it is honest about
the cost: this query is now maintained per platform.

## Native patterns per platform

**Stack counting** — the workhorse. Count occurrences, sort ascending, read the
tail. Rare is not malicious, but malicious is very often rare.

```spl
| tstats count from datamodel=Endpoint.Processes where Processes.process_name="*.exe"
  by Processes.process_path | sort 0 count | head 50
```

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize Hosts = dcount(DeviceName), Total = count() by FolderPath
| where Hosts <= 3
| order by Total asc
```

```
// NG-SIEM (CQL)
#event_simpleName=ProcessRollup2
| groupBy([ImageFileName], function=[count(aid, distinct=true, as=hosts)])
| hosts <= 3
| sort(hosts, order=asc)
```

**First-seen analysis** — when did this binary, service or account first appear?
New plus rare is a much stronger signal than either alone.

```kql
DeviceProcessEvents
| summarize FirstSeen = min(Timestamp), Hosts = dcount(DeviceName) by SHA256, FolderPath
| where FirstSeen > ago(7d) and Hosts < 5
```

**Parent-child rarity** — score the *pair*, not either process. A shell spawning
from a document handler is unremarkable alone and damning together.

**Week-over-week diff** — build the set for last week and this week, and return
what is only in this week. Finds newly-introduced behavior without knowing what
it will be, which is how a hunt finds things nobody wrote a rule for.

## Conversion gotchas

- **`log_scale` emits regex**, so `.` and `\` must be escaped and matching is
  case-insensitive via `/i`. Reading a converted CQL query as if it were literal
  string matching will mislead you.
- **Splunk output carries no `index=`.** Pipelines map fields, not your index
  layout. Prepend the index or the search scans everything you own.
- **`kusto` needs no pipeline but still wants one.** Without it you get generic
  field names that match no table. Always pass `microsoft_xdr`, `sentinel_asim`
  or `azure_monitor`.
- **Truncated command lines defeat `CommandLine|contains`.** Sysmon truncates,
  and some EDRs truncate harder. Check field fidelity in the Stage 2 survey
  before trusting a command-line query's negative result.
- **`|contains` on a path is not `|endswith`.** `\AnyDesk.exe` as a `contains`
  match happily hits `C:\tools\AnyDesk.exe.bak`. Prefer `|endswith` for
  executables.
- **A converted rule is a draft.** Read the output before running it. The
  converter guarantees syntax, never that the fields exist in your data — that is
  what the Stage 2 survey was for.
