# Port proxy state sweep

Every other query in this folder searches **logs**, and logs only go back as far
as retention. A port proxy is also **state**: it sits in the registry until
somebody removes it. A proxy created fourteen months ago is outside every log
window in this hunt, and it is still in the registry today.

So this sweep asks every in-scope Windows server a direct question: *what port
proxies are configured on you right now?* It is not a Sigma rule, because Sigma
describes events, and this is a point-in-time inventory.

None of these have been run against a live fleet.

## osquery

```sql
SELECT key, name, data, mtime
FROM registry
WHERE key LIKE 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp%';
```

## PowerShell, through whatever remote management you already run

```powershell
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
if (Test-Path $key) { Get-ItemProperty -Path $key } else { 'NO PORTPROXY KEY' }
```

Errors are deliberately left visible. A host that cannot be reached or read must
show up as a failure, not as an empty answer.

## On a single host

```
netsh interface portproxy show all
```

## Reading the result

Each value is one proxy. Its **name** is the listening address and port; its
**data** is where traffic is forwarded. AA23-144A's examples forwarded
`0.0.0.0:9999` to port 8443, and `0.0.0.0:50100` to port 1433 (SQL Server) on
an internal address.

Every server lands in exactly one of three states, and the sweep's result
records all three:

- **Answered, no proxies** (`NO PORTPROXY KEY`, or the key exists but holds no
  values). This is the normal case.
- **Answered, proxies present.** Triage each one, as below.
- **Did not answer**: unreachable, access denied, or an error. This is **not**
  clean. List these servers by name; they are outside the coverage statement.
  With osquery the trap is the same: a host that returned zero rows and a host
  that never ran the query look identical unless you count who responded.

For the servers that answered:

- **Any entry on a server** is triaged. The advisory calls port proxies "not
  common for legitimate system administration."
- **The connect address** names the next host to look at, and the listen port is
  what to search for in firewall logs.
