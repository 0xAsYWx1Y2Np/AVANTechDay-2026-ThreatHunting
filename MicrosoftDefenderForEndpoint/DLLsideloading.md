# DLL Sideloading — Trusted Binary + Unsigned DLL (KQL)

**MITRE ATT&CK:** [T1574.002](https://attack.mitre.org/techniques/T1574/002/) — Hijack Execution Flow: DLL Side-Loading
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

InfoStealers ship a **legitimate signed binary** (e.g., `msedge.exe`, `OneDrive.exe`, `vlc.exe`) alongside a **malicious unsigned DLL** with a name the binary loads at startup. When the trusted binary executes from a user-writable path, Windows loads the malicious DLL from the same directory before searching system paths.

## Detection invariant

> **Trusted, signed EXE in a user-writable path** + **unsigned DLL in the same directory** + **same process** = sideloading.

---

## Query 1 — Trusted binary in anomalous path + module load join

Joins `DeviceProcessEvents` (trusted binary in anomalous location) with `DeviceImageLoadEvents` (non-system DLLs loaded into that same process). Join keys are explicit on both sides — no `$left` / `$right` shorthand mixing.

```kql
let TrustedBinaries = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "onedrive.exe", "onedrivestandaloneupdater.exe",
    "teams.exe", "slack.exe", "zoom.exe",
    "vlc.exe", "notepad++.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe",
    "wermgr.exe", "dbgsrv.exe", "rdpclip.exe",
    "anydesk.exe", "teamviewer.exe"
]);
let UserWritablePaths = @"(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp|PerfLogs)\\";
let SuspiciousBinaries =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ (TrustedBinaries)
    // Binary is NOT renamed — keeps its real PE name (DeviceFileCertificateInfo.OriginalFilename equivalent)
    | where FolderPath matches regex UserWritablePaths
    | project ProcStartTime = Timestamp,
              DeviceId,
              ProcessId = ProcessId,
              ProcessCreationTime = ProcessCreationTime,
              DeviceName,
              AccountName,
              InitiatingProcessFileName,
              FileName,
              FolderPath,
              ProcessCommandLine,
              ProcessSHA1 = SHA1;
let SuspiciousModules =
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where FileName endswith ".dll"
    | where FolderPath matches regex UserWritablePaths
    | project ModuleLoadTime = Timestamp,
              DeviceId,
              InitiatingProcessId,
              InitiatingProcessCreationTime,
              DLL_FileName = FileName,
              DLL_FolderPath = FolderPath,
              DLL_SHA1 = SHA1;
SuspiciousBinaries
| join kind=inner SuspiciousModules
    on DeviceId,
       $left.ProcessId == $right.InitiatingProcessId,
       $left.ProcessCreationTime == $right.InitiatingProcessCreationTime
| extend DetectionType = "TrustedBinary_AnomalousPath"
| project ProcStartTime, ModuleLoadTime, DeviceName, AccountName,
          InitiatingProcessFileName, FileName, FolderPath,
          DLL_FileName, DLL_FolderPath, DLL_SHA1,
          ProcessCommandLine, ProcessSHA1, DetectionType
| sort by ProcStartTime desc
```

```kql
// Add signer truth (optional)
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | project DLL_SHA1 = SHA1, IsSigned, IsTrusted, Signer, Issuer
  ) on DLL_SHA1
| where (IsSigned == false) or (IsTrusted == false)
```

---

## Query 2 — Renamed signed binary

Catches the inverse: a trusted EXE has been **renamed** by the attacker but still has its original PE-header `OriginalFilename`. Lower volume, very high fidelity. Use `DeviceFileCertificateInfo` to confirm the binary's signed identity.

```kql
let TrustedOriginalFilenames = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe",
    "onedrive.exe", "teams.exe", "slack.exe", "zoom.exe",
    "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "anydesk.exe", "teamviewer.exe"
]);
let UserWritablePaths = @"(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp|PerfLogs)\\";
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex UserWritablePaths
| join kind=inner (
    DeviceFileCertificateInfo
    | where IsSigned == true
    | project SHA1, Signer, Issuer
  ) on SHA1
// Process FileName differs from its true PE OriginalFilename
| where FileName !in~ (TrustedOriginalFilenames)
// But the certificate's signer subject is a known browser/app vendor
| where Signer has_any ("Microsoft Corporation", "Google LLC", "Mozilla Corporation",
                        "Brave Software, Inc", "Zoom Video Communications",
                        "Slack Technologies", "AnyDesk Software")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, ProcessCommandLine, Signer, Issuer, SHA1
| sort by Timestamp desc
```

> This is a heuristic — it triggers when a process running from `\AppData\` matches a known-vendor signer but has been renamed away from the canonical filename. Allowlist your portable apps (e.g., a portable Notepad++ under `\AppData\` is legitimate but matches the shape).

---

## Sideloading targets (HijackLibs reference)

See [HijackLibs](https://hijacklibs.net/) for the full catalog of documented sideloading pairs.

## Known TamperedChef / Vidar sideload pairs

| Trusted binary | Sideloaded DLL | SHA-256 |
| :--- | :--- | :--- |
| `msedge.exe` | `msedge_elf.dll` | `cc482813e22e8163d60982340dd4ec13e316565f0e6cf455d07550ccf348858a` |
| Chromium-based | `libGLESv2.dll` | see `IOCs/hashes.txt` |
| Chromium-based | `libEGL.dll` | see `IOCs/hashes.txt` |
| Chromium-based | `vk_swiftshader.dll` | see `IOCs/hashes.txt` |

## Tuning

- Some legit installers run from `\Downloads\` briefly during install — exclude installer parents
- Portable apps (legitimate, but technically sideloading-shaped) — allowlist by hash

## References

- [MITRE ATT&CK T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [HijackLibs](https://hijacklibs.net/)
- [DeviceImageLoadEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table)
- [DeviceFileCertificateInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table)
