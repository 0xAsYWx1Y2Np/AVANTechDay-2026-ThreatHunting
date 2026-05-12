# Credentials from Web Browsers — The Chokepoint (KQL)

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003/) — Credentials from Web Browsers
**Tactic:** [TA0006](https://attack.mitre.org/tactics/TA0006/) — Credential Access
**Related:** [T1539](https://attack.mitre.org/techniques/T1539/) — Steal Web Session Cookie
**Platform:** Microsoft Defender XDR (KQL)

---

## Query 1 — Non-browser process writes/modifies credential file in place

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
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FileName in~ ("Login Data", "Cookies", "Web Data", "Local State", "formhistory.sqlite", "key4.db", "signons.sqlite", "logins.json", "cookies.sqlite", "places.sqlite")
| where FolderPath matches regex BrowserUserDataPaths
| where InitiatingProcessFileName !in~ ("chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe", "arc.exe", "browser.exe", "yandex.exe", "chromium.exe", "MsMpEng.exe", "MpDefenderCoreService.exe", "SearchProtocolHost.exe", "SearchIndexer.exe", "explorer.exe", "backgroundTaskHost.exe")
| where InitiatingProcessFolderPath !contains @"\Program Files"
| where InitiatingProcessFolderPath !contains @"\Windows\System32"
| where InitiatingProcessFolderPath !contains @"\Windows\SysWOW64"
| extend RiskPath = iff(InitiatingProcessFolderPath matches regex UserWritablePaths, "HIGH", "MEDIUM")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1, TargetFile = FileName, TargetFolder = FolderPath, ActionType, RiskPath
| sort by RiskPath asc, Timestamp desc
```

## Query 2 — Defender-flagged sensitive read on credential file

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
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "SensitiveFileRead"
| where FileName in~ (CredentialFiles)
| where FolderPath matches regex BrowserUserDataPaths
| where InitiatingProcessFileName !in~ (BrowserProcesses)
| extend RiskPath = iff(InitiatingProcessFolderPath matches regex UserWritablePaths, "HIGH", "MEDIUM")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA1,
    TargetFile = FileName,
    TargetFolder = FolderPath,
    RiskPath
| sort by RiskPath asc, Timestamp desc
```

## Query 3 — Staging copy of credential filename to non-browser location

The highest-fidelity surrogate for read detection. Stealers copy `Login Data` to `%TEMP%\<random>` (or similar) to avoid the SQLite file lock held by the running browser — that copy *is* a `FileCreated` event with the same filename, just outside the browser user-data tree.

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
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName in~ (CredentialFiles)
// File created OUTSIDE any legitimate browser user-data tree
| where not(FolderPath matches regex BrowserUserDataPaths)
// Initiating process is not a real browser
| where InitiatingProcessFileName !in~ (BrowserProcesses)
| where InitiatingProcessFolderPath !contains @"\Program Files"
| where InitiatingProcessFolderPath !contains @"\Windows\System32"
| extend RiskPath = iff(InitiatingProcessFolderPath matches regex UserWritablePaths, "HIGH", "MEDIUM")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessSHA1,
    StagedFile = FileName,
    StagedFolder = FolderPath,
    RiskPath
| sort by RiskPath asc, Timestamp desc
```

## Bonus — DPAPI Vault interface loaded from user-writable path

`vaultcli.dll` is the Windows credential-vault API. Legitimate loaders are few and live in `\Windows\System32\`. A non-browser, non-system process in `\AppData\` / `\Temp\` loading `vaultcli.dll` is high-signal.

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
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "vaultcli.dll"
| where InitiatingProcessFolderPath matches regex UserWritablePaths
| where InitiatingProcessFileName !in~ (BrowserProcesses)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessSHA1
| sort by Timestamp desc
```

---

## Tuning

- **Password managers** that integrate with browsers (1Password, Bitwarden, KeePassXC) may trigger Query 3 — allowlist by `InitiatingProcessFileName`
- **Backup software** reading user profiles wholesale (Acronis, Veeam Endpoint, etc.) — allowlist
- **Security scanners** beyond `MsMpEng` — add your own AV/EDR file names to `BrowserProcesses` (yes, that label is misleading; it's "OK to ignore" in practice)
- **Browser sync utilities** may write to a Chrome profile under a non-Chrome process — allowlist by signer

## References

- [MITRE ATT&CK T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [DeviceFileEvents schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [DeviceEvents schema reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)
- [Splunk Threat Research, Jan 2026](https://www.splunk.com/en_us/blog/security/common-ttps-rats-malware-analysis.html)
