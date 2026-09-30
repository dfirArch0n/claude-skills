# Indicator sweep

This is an **IOC sweep, not the hunt.** It is here because it costs an hour and
it would be negligent to skip it. It is filed separately because its shelf life
is days: every indicator below is free for the actor to change.

Source: [CISA AA23-144A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a),
"Indicators of Compromise (IOCs) Summary." The same page links a STIX JSON copy of these
indicators, which is the better input for a tool.

## What the advisory contains, counted

| Type | Count | Worth sweeping? |
|---|---|---|
| SHA-256 file hashes | 11 | Yes: cheap, exact, and short-lived |
| IP addresses | **0** | Nothing to sweep |
| Domains | 1 (`www.ip-api[.]com`) | No: a legitimate IP-geolocation service. A hit is context, not evidence |
| File names | 15 | As a supporting signal only. Several imitate real Windows or vendor binaries |
| Directory paths | 3 | Yes, combined with the file names |
| User-agent string | 1 | If proxy logs keep user agents |
| YARA rules | 4 | Yes, for web servers that could host the webshell |

## Hashes

```
f4dd44bc19c19056794d29151a5b1bb76afd502388622e24c863a8494af147dd
ef09b8ff86c276e9b475a6ae6b54f08ed77e09e169f7fc0872eb1d427ee27d31
d6ebde42457fe4b2a927ce53fc36f465f0000da931cfab9b79a36083e914ceca
472ccfb865c81704562ea95870f60c08ef00bcd2ca1d7f09352398c05be5d05d
66a19f7d2547a8a85cee7a62d0b6114fd31afdee090bd43f36b89470238393d7
3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71
41e5181b9553bbe33d91ee204fe1d2ca321ac123f9147bb475c0ed32f9488597
c7fee7a3ffaf0732f42d89c4399cbff219459ae04a81fc6eff7050d53bd69b99
3a9d8bb85fbcfe92bae79d5ab18e4bca9eaf36cea70086e8d1ab85336c83945f
fe95a382b4f879830e2666473d662a24b34fccf34b6b3505ee1b62b32adafa15
ee8df354503a56c62719656fae71b3502acf9f87951c55ffd955feec90a11484
```

## Paths and names

The advisory lists `C:\Users\Public\Appfile`, `C:\Perflogs` and `C:\Windows\Temp`
(each including subdirectories) as the most common locations, and
`C:\Windows\[a-zA-Z]{8}.exe` as a pattern for randomly named files. Look for the
advisory's file names **in those paths**; `WmiPrvSE.exe` in `C:\Windows\System32\wbem`
is Windows, and the same name in `C:\Windows\Temp` is not.

## What a clean sweep means

Very little, and the report says so: it rules out *these exact files* on the
hosts the EDR covers. It says nothing about the behavior, which is why the hunt
exists.
