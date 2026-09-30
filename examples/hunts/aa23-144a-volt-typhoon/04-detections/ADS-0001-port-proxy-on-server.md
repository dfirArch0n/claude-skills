# ADS-0001: Port proxy configured on a Windows server

- **Status:** draft. Missing: real volume numbers, which come from running the
  hunt queries, and the GAP-004 registry test.
- **From hunt:** aa23-144a-volt-typhoon
- **Expected volume:** estimated at near zero per day on servers, based on
  AA23-144A calling port proxies "not common for legitimate system
  administration." **Not measured.** The hunt's first run replaces this estimate
  with a count.

## Goal

Detect a Windows server being turned into a relay: a `netsh` port proxy that
accepts connections on one port and forwards them to another host. An attacker
uses this to reach systems that firewall rules would otherwise keep them away
from.

## Categorization

- MITRE ATT&CK (v19): Command and Control, Proxy: Internal Proxy (T1090.001)
- Public reporting: CISA AA23-144A (Volt Typhoon)

## Strategy Abstract

Two signals, either one sufficient:

1. **Process creation:** a command line containing `portproxy` together with
   `add`, `set` or `delete`
   (`queries/netsh-portproxy.sigma.yml`).
2. **Registry:** any write under
   `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4`
   (`queries/portproxy-registry.sigma.yml`). This catches proxies created without
   `netsh`, through PowerShell or the API.

Scope the alert to **servers**, using the asset inventory's server group.
Suppress hosts on the sanctioned-proxy list (bucket C-2) during their approved
window only.

The detection is paired with a weekly run of the state sweep
(`queries/portproxy-state-sweep.md`). That catches anything the event-based
signals missed, including proxies that predate the detection.

## Technical Context

- `netsh interface portproxy add v4tov4 listenaddress=A listenport=P
  connectaddress=B connectport=Q` makes the server accept TCP on `A:P` and
  forward it to `B:Q`. `0.0.0.0` means any interface.
- It requires administrator rights. Windows keeps the configuration in the
  registry, so it survives reboots.
- AA23-144A's examples forwarded `0.0.0.0:9999` → an internal host on `8443`,
  and `0.0.0.0:50100` → an internal host on `1433` (SQL Server).
- The advisory also shows the actor **deleting** a proxy with `psexec` once done,
  which is why `delete` is in the rule.
- **What a responder needs to know:** the `connectaddress` names the next host to
  examine, and the `listenport` is what to search for in firewall logs.

## Blind Spots and Assumptions

- **Servers without EDR** (48 of 400 in the example estate, GAP-006) generate
  neither signal. The weekly state sweep is the only coverage there.
- **Registry fidelity** (GAP-004): this assumes EDR records every value write
  under the key. That is untested. Until it is, a proxy created and deleted
  between sweeps on an EDR host may be missed.
- **Other proxy tools**: Fast Reverse Proxy, Earthworm, and SSH tunnels forward
  traffic without touching `PortProxy`. This detection does not cover them.
- **IPv6 variants** (`v4tov6`, `v6tov4`, `v6tov6`) live under sibling keys. The
  registry rule matches only `v4tov4`. Widening it to `\Services\PortProxy\` is
  recommended once volume is known.

## False Positives

- **Developer machines forwarding into WSL2 or containers.** Excluded by scoping
  to servers.
- **Planned migrations** that use a temporary proxy. Handled by the
  sanctioned-proxy list and its end date.
- No counts yet; see Status.

## Validation

On a lab server with EDR:

```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=127.0.0.1 connectport=80
netsh interface portproxy show all
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=9999
```

Expect: one process alert for the `add`, one for the `delete`, and a registry
event for the `add`. The registry rule watches writes (`registry_set`), not
deletions, so the `delete` is caught by the command-line rule only. Whether EDR
records the deletion at all is part of the GAP-004 test. If the `add` registry
event does not appear, GAP-004 is confirmed and the blind spot above becomes a
fact.

## Priority

High. There are few legitimate reasons to do this on a server, and the
advisory's own framing is that a proxy is "a backdoor into the network that
bypasses firewall policies." Critical when the `connectaddress` is a domain
controller or database server.

## Response

1. Record the proxy: listen address and port, connect address and port, host,
   and the account that created it.
2. Ask the host owner whether it is sanctioned. If not, or if nobody answers
   within an hour, escalate to incident response as a suspected compromise.
   Unexplained is not the same as confirmed; incident response makes that call.
3. Search firewall logs for connections to the listen port, and examine the
   connect host.
4. Pull everything else the creating account did in the last 30 days, starting
   with WMI-spawned processes and the `ADMIN$\__<epoch>` pattern.
5. Unless incident command decides to contain immediately, capture the above
   before removing the proxy. Removing it can alert the actor and destroys the
   lead.

## Additional Resources

- [CISA AA23-144A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a),
  "PortProxy" section
- [MITRE ATT&CK T1090.001](https://attack.mitre.org/techniques/T1090/001/)
- Hunt package: `examples/hunts/aa23-144a-volt-typhoon/`
