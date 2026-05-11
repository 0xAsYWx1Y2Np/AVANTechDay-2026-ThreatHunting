# Credentials from Web Browsers — The Chokepoint

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003/) — Credentials from Web Browsers
**Tactic:** [TA0006](https://attack.mitre.org/tactics/TA0006/) — Credential Access
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie
**Platform:** CrowdStrike Falcon (CQL / LogScale)

## Hypothesis

> **If a non-browser process opens `Login Data` — it's a stealer.**

Chrome, Edge, Firefox, Brave, and every Chromium-based browser store credentials in three SQLite files inside the user profile:

- `Login Data` — saved passwords
- `Cookies` — active session tokens (MFA bypass)
- `Web Data` — autofill, credit cards, addresses

The attacker **must** open these files to harvest browser credentials. There is no other path. Per [Splunk Threat Research, Jan 2026](https://www.splunk.com/en_us/blog/security/common-ttps-rats-malware-analysis.html), **11 of 18 documented stealer families** funnel through this chokepoint — Lumma, Vidar, RedLine, StealC, Phemedrone, Meduza, Braodo, Agent Tesla, Lokibot, and others.

## Query

```java
// Hunt: InfoStealer — non-browser process touches browser credential SQLite DBs
#event_simpleName=FileOpenInfo

// --- The credential goldmine: Chromium SQLite DBs + Mozilla equivalents ---
| TargetFileName=/(?i)\\(Login Data|Cookies|Web Data|Local State|formhistory\.sqlite|key4\.db|signons\.sqlite|logins\.json|cookies\.sqlite|places\.sqlite)$/

// --- Must live inside a real browser user-data tree ---
| TargetFileName=/(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware|Mozilla\\Firefox|Vivaldi|Opera Software|Chromium|Yandex|Arc|CocCoc)\\/

// --- Allow ONLY browsers themselves + a tiny set of OS scanners ---
| ContextBaseFileName!=/(?i)^(chrome\.exe|msedge\.exe|brave\.exe|firefox\.exe|opera\.exe|vivaldi\.exe|arc\.exe|browser\.exe|yandex\.exe|chromium\.exe|MsMpEng\.exe|MpDefenderCoreService\.exe|SearchProtocolHost\.exe|SearchIndexer\.exe|explorer\.exe|backgroundTaskHost\.exe)$/

// --- Suppress legitimate Program Files and System paths ---
| ContextImageFileName!=/(?i)\\Program Files( \(x86\))?\\/
| ContextImageFileName!=/(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\/

// --- Risk classification: process running from user-writable path = HIGH ---
| case {
    ContextImageFileName=/(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\/
      | RiskPath := "HIGH";
    *
      | RiskPath := "MEDIUM"
  }

// --- Tenant enrichment from cid_name lookup ---
| join(
    query={
      #data_source_name=cid_name
      | groupBy([cid], function=selectLast(name), limit=max)
      | CustomerName := name
    },
    field=cid,
    key=cid,
    include=[CustomerName]
  )

| groupBy(
    [CustomerName, cid, ComputerName, UserName, ContextBaseFileName, ContextImageFileName, RiskPath],
    function=[
      count(as=hit_count),
      collect(fields=[TargetFileName], separator=", "),
      min(@timestamp, as=first_seen),
      max(@timestamp, as=last_seen)
    ],
    limit=20000
  )

| files_touched := TargetFileName
| table([CustomerName, ComputerName, UserName, ContextBaseFileName,
         ContextImageFileName, RiskPath, hit_count, files_touched,
         first_seen, last_seen])
| sort(hit_count, order=desc, limit=1000)
```

## Why this works

- **The SQLite files are the only path** — no encryption, no API alternative for the attacker
- **Browser allowlist is tiny and stable** — Chrome, Edge, Firefox, Brave, Opera, Vivaldi, Arc, Chromium
- **Path-based risk scoring** prioritizes hits where the calling process itself is in a user-writable directory (typical stealer drop location)
- **Cookie theft = MFA bypass** (T1539) — same telemetry, downstream impact is enterprise-wide

## Coverage

This single rule catches every stealer family that targets browser credentials, regardless of:

- Family name (Lumma, Vidar, RedLine, StealC, Phemedrone, Meduza, Braodo, Agent Tesla, Lokibot, …)
- Loader (Donut, BaoLoader, custom)
- C2 protocol (Telegram, Discord, HTTPS, paste.rs)
- Code-signing posture
- Obfuscation level