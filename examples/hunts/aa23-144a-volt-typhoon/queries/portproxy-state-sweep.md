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
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp' `
    -ErrorAction SilentlyContinue
```

## On a single host

```
netsh interface portproxy show all
```

## Reading the result

Each value is one proxy. Its **name** is the listening address and port; its
**data** is where traffic is forwarded. AA23-144A's examples forwarded
`0.0.0.0:9999` to port 8443, and `0.0.0.0:50100` to port 1433 (SQL Server) on
an internal address.

- **An empty result** on a server is the normal case.
- **Any entry on a server** is triaged. The advisory calls port proxies "not
  common for legitimate system administration."
- **The connect address** names the next host to look at, and the listen port is
  what to search for in firewall logs.
