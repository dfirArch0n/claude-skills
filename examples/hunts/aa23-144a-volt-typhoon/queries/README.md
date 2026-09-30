# Queries

Every query here was **written, not run**. This worked example has no
environment behind it. The Sigma rules were converted with the skill's own
`convert.py` (sigma-cli, `splunk_windows` and `microsoft_xdr` pipelines), and
the generated output is in `generated/` exactly as the converter produced it.
Syntax is therefore checked; whether the fields exist in a given SIEM is not.
The Splunk queries also need your own index and sourcetype in front of them.

## What each query is for, and what a hit looks like

| Query | Part of the hypothesis | Written as | A hit looks like |
|---|---|---|---|
| `ntdsutil-ifm.sigma.yml` | Credential access on DCs | Sigma | `ntdsutil` with `ifm` or `create full`, often launched by `wmic process call create`, writing into `C:\Windows\Temp\<folder>` or `C:\Users\Public` |
| `ntds-hive-staging.sigma.yml` | Credential access on DCs | Sigma | `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\Windows\NTDS\ntds.dit`, or `reg save hklm\system` to a short file name |
| `esent-ntds-copy.sigma.yml` + `.sentinel.kql` | Credential access on DCs | Sigma; native for Sentinel | ESENT 216/325/326/327 naming `ntds.dit` **and a path that is not the live database**. The path is the lead |
| `netsh-portproxy.sigma.yml` | Internal proxy on servers | Sigma | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=<high port> connectaddress=<internal IP>` |
| `portproxy-registry.sigma.yml` | Internal proxy on servers | Sigma | Any write under `...\Services\PortProxy\v4tov4\tcp` on a server |
| `portproxy-state-sweep.md` | Internal proxy on servers | Inventory (not a log query) | Any proxy configured on a server today, however old |
| `wmiexec-admin-share.sigma.yml` | How the actor ran both of the above | Sigma | `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<epoch timestamp> 2>&1`, parent `WmiPrvSE.exe` |
| `discovery-burst.kql` / `.spl` | Supporting context | Native (aggregation) | One account running five or more different enumeration tools on one host inside ten minutes |
| `security-log-cleared.sigma.yml` + `.sentinel.kql` | Supporting context, and a check on every negative | Sigma; native for Sentinel | Event 1102 on any in-scope host. It also means that host's empty results cannot be trusted |
| `ioc-sweep.md` | Not the hunt | Indicator list | An exact hash or a named file in the advisory's paths. Short shelf life |

## Where the converter stopped

Two Sigma rules would not convert to KQL, and the reason is itself a finding:
**Defender XDR has no table for the raw Windows Application or Security log**, so
ESENT events and event 1102 have nowhere to go. Organizations that rely on
Defender XDR alone cannot see either signal. Sentinel can, if the logs are
forwarded, so those two rules have hand-written Sentinel versions. The gap is
recorded as GAP-002 and GAP-005.

## Why some queries are native

Sigma describes single events. The discovery burst counts distinct tools per
account per window, which is aggregation, and the port proxy sweep asks what is
configured *now*, which is inventory. Each native file opens with a comment
saying why Sigma could not carry it.
