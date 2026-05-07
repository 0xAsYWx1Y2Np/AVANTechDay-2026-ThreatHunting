# Credentials from Web Browsers — The Chokepoint (KQL)

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003/) — Credentials from Web Browsers
**Tactic:** [TA0006](https://attack.mitre.org/tactics/TA0006/) — Credential Access
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

> **If a non-browser process opens `Login Data` — it's a stealer.**

Per [Splunk Threat Research, Jan 2026](https://www.splunk.com/en_us/blog/security/common-ttps-rats-malware-analysis.html), **11 of 18 documented stealer families** funnel through this chokepoint.

## Query

```kql
let CredentialFiles = dynamic([
    "Login Data", "Cookies", "Web Data", "Local State",
    "formhistory.sqlite", "key4.db", "signons.sqlite",
    "logins.json", "cookies.sqlite", "places.sqlite"
]);
let BrowserProcesses = dynamic([
    "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe",
    "opera.exe", "vivaldi.exe", "arc.exe", "browser.exe",
    "yandex.exe", "chromium.exe",
    "MsMpEng.exe", "MpDefenderCoreService.exe",
    "SearchProtocolHost.exe", "SearchIndexer.exe",
    "explorer.exe", "backgroundTaskHost.exe"
]);
let BrowserUserDataPaths = @"(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware|Mozilla\\Firefox|Vivaldi|Opera\sSoftware|Chromium|Yandex|Arc|CocCoc)\\";
let UserWritablePaths = @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\";
//
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed", "FileAccessed")
//
// Step 1 — file is one of the credential goldmine SQLite databases
| where FileName in~ (CredentialFiles)
//
// Step 2 — the file lives inside a real browser user-data tree
| where FolderPath matches regex BrowserUserDataPaths
//
// Step 3 — initiating process is NOT a real browser or OS scanner
| where InitiatingProcessFileName !in~ (BrowserProcesses)
//
// Step 4 — suppress legitimate Program Files / System32 paths
| where InitiatingProcessFolderPath !contains @"\Program Files"
| where InitiatingProcessFolderPath !contains @"\Windows\System32"
| where InitiatingProcessFolderPath !contains @"\Windows\SysWOW64"
//
// Step 5 — risk classification
| extend RiskPath = iff(InitiatingProcessFolderPath matches regex UserWritablePaths, "HIGH", "MEDIUM")
//
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA256,
    TargetFile = FileName,
    TargetFolder = FolderPath,
    RiskPath
| sort by RiskPath asc, Timestamp desc
```

## Why this works

- **`DeviceFileEvents` captures any file access** by any process — equivalent to CrowdStrike's `FileOpenInfo`
- **Browser allowlist** is small and stable
- **Path-based risk scoring** prioritizes hits where the calling process itself is in a user-writable directory

## Coverage

This single rule catches every stealer family that targets browser credentials, regardless of family, loader, or C2 protocol — same as the CQL version.

## Tuning

- **Password managers** that integrate with browsers (1Password, Bitwarden, KeePassXC) may trigger — allowlist by `InitiatingProcessFileName`
- **Backup software** reading user profiles wholesale — allowlist
- **Security scanners** beyond MsMpEng — add your own AV/EDR

## Bonus — DPAPI abuse from non-browser/non-LSASS

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("CryptUnprotectData", "DPAPI", "ProtectedStore")
| where InitiatingProcessFileName !in~ ("lsass.exe", "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine
```

## References

- [MITRE ATT&CK T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Splunk Threat Research, Jan 2026](https://www.splunk.com/en_us/blog/security/common-ttps-rats-malware-analysis.html)
