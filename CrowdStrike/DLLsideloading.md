# DLL Sideloading — Trusted Binary + Unsigned DLL

**MITRE ATT&CK:** [T1574.002](https://attack.mitre.org/techniques/T1574/002/) — Hijack Execution Flow: DLL Side-Loading
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

InfoStealers ship a **legitimate signed binary** (e.g., `msedge.exe`, `OneDrive.exe`, `vlc.exe`) alongside a **malicious unsigned DLL** with a name the binary loads at startup (e.g., `msedge_elf.dll`, `version.dll`).

When the trusted binary executes from a user-writable path, Windows loads the malicious DLL from the same directory **before** searching system paths. The attacker's code now runs inside a fully-trusted process.

## Detection invariant

> **Trusted, signed EXE in a user-writable path** + **unsigned DLL in the same directory** + **same process** = sideloading.

---

## Query 1 — Trusted binary in anomalous path + unsigned DLL load

The durable detection. Targets [HijackLibs](https://hijacklibs.net/)-documented binaries running from user-writable locations, joined to unsigned DLL loads inside the same process.

```java
#event_simpleName=ProcessRollup2
| FileNameLower := lower(FileName)
| in(FileNameLower, values=[
    "msedge.exe","chrome.exe","firefox.exe","iexplore.exe",
    "onedrive.exe","onedrivestandaloneupdater.exe",
    "teams.exe","slack.exe","zoom.exe",
    "vlc.exe","notepad++.exe","code.exe",
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
    "python.exe","pythonw.exe","java.exe","javaw.exe",
    "wermgr.exe","dbgsrv.exe","rdpclip.exe",
    "anydesk.exe","teamviewer.exe","gup.exe"
  ])
| ImageFileName=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop|Temp)|ProgramData|Windows\\Temp|PerfLogs|Intel|Recovery)\\/
| !(FileNameLower="onedrive.exe" and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\OneDrive\\/)
| !(FileNameLower="teams.exe"    and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\Teams\\/)
| !(FileNameLower="slack.exe"    and ImageFileName=/(?i)\\AppData\\Local\\slack\\/)
| !(FileNameLower="code.exe"     and ImageFileName=/(?i)\\AppData\\Local\\Programs\\Microsoft VS Code\\/)
| !(FileNameLower="msedge.exe"   and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\Edge\\/)
| !(FileNameLower="chrome.exe"   and ImageFileName=/(?i)\\AppData\\Local\\Google\\Chrome\\/)
// Extract parent directory of the trusted binary
| regex("^(?<ProcDir>.+)\\\\[^\\\\]+$", field=ImageFileName, strict=false)
| ProcDirLower := lower(ProcDir)
| join(
    query={
      #event_simpleName=/ClassifiedModuleLoad|UnsignedModuleLoad/i
      | ImageFileName=/(?i)\.dll$/
      | DLL_FileName := FileName
      | DLL_Path     := ImageFileName
      | DLL_SHA256   := SHA256HashData
      | regex("^(?<DLL_Dir>.+)\\\\[^\\\\]+$", field=ImageFileName, strict=false)
      | DLL_DirLower := lower(DLL_Dir)
    },
    field=[aid, TargetProcessId],
    key=[aid, ContextProcessId],
    include=[DLL_FileName, DLL_Path, DLL_SHA256, DLL_DirLower],
    limit=200000
  )
| DLL_DirLower = ProcDirLower
| DetectionType := "TrustedBinary_AnomalousPath"
| groupBy(
    [ComputerName, UserName, FileName, ImageFileName, MD5HashData, SHA256HashData,
     DLL_FileName, DLL_Path, DLL_SHA256, DetectionType],
    function=[
      count(as=LoadCount),
      min(@timestamp, as=FirstSeen),
      max(@timestamp, as=LastSeen)
    ]
  )
| sort(LastSeen, order=desc)
```

---

## Query 2 — Renamed signed binary (low-volume, high-fidelity)

Catches the inverse pattern: a trusted EXE has been **renamed** by the attacker (e.g. `msedge.exe` → `update.exe`) but still keeps its original PE-header `OriginalFilename`. Rarer but extremely high-fidelity.

```java
#event_simpleName=ProcessRollup2
| OriginalFilename=*
| FileNameLower := lower(FileName)
| OriginalFilenameLower := lower(OriginalFilename)
// Name on disk DIFFERS from PE-header OriginalFilename → renamed binary
| FileNameLower != OriginalFilenameLower
| in(OriginalFilenameLower, values=[
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "onedrive.exe", "microsoft.onedrive.exe",
    "teams.exe", "ms-teams.exe",
    "slack.exe", "zoom.exe", "zoom.us.exe",
    "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "powerpoint.exe", "outlook.exe",
    "python.exe", "pythonw.exe",
    "anydesk.exe", "teamviewer.exe", "teamviewer_service.exe"
  ])
| ImageFileName=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop|Temp)|ProgramData|Windows\\Temp|PerfLogs|Intel|Recovery)\\/
// Exclude legitimate AppData-resident installs (kill FP from PE-name quirks)
| !(FileNameLower="onedrive.exe" and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\OneDrive\\/)
| !(FileNameLower="teams.exe"    and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\Teams\\/)
| !(FileNameLower="ms-teams.exe" and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\/)
| !(FileNameLower="slack.exe"    and ImageFileName=/(?i)\\AppData\\Local\\slack\\/)
| !(FileNameLower="code.exe"     and ImageFileName=/(?i)\\AppData\\Local\\Programs\\Microsoft VS Code\\/)
| !(FileNameLower="msedge.exe"   and ImageFileName=/(?i)\\AppData\\Local\\Microsoft\\Edge\\/)
| !(FileNameLower="chrome.exe"   and ImageFileName=/(?i)\\AppData\\Local\\Google\\Chrome\\/)
| !(FileNameLower="zoom.exe"     and ImageFileName=/(?i)\\AppData\\Roaming\\Zoom\\/)
// Triage classification
| case {
    OriginalFilenameLower=/^(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/i
      | RenameType := "lolbas_rename_critical";
    OriginalFilenameLower=/^(msedge|chrome|firefox|iexplore|opera)\.exe$/i
      | RenameType := "browser_rename";
    OriginalFilenameLower=/^(teams|slack|zoom|onedrive|ms-teams|microsoft\.onedrive)\.exe$/i
      | RenameType := "collab_app_rename";
    OriginalFilenameLower=/^(winword|excel|powerpnt|powerpoint|outlook)\.exe$/i
      | RenameType := "office_rename";
    OriginalFilenameLower=/^(anydesk|teamviewer|teamviewer_service)\.exe$/i
      | RenameType := "rmm_rename";
    *
      | RenameType := "other_signed_rename"
  }
| DetectionType := "RenamedSignedBinary"
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
         FileName, OriginalFilename, ImageFileName, SHA256HashData, CommandLine,
         DetectionType, RenameType])
| sort(@timestamp, order=desc)
```

---

## Sideloading targets (HijackLibs reference)

25+ documented targets, including: `msedge.exe`, `chrome.exe`, `firefox.exe`, `teams.exe`, `OneDrive.exe`, `slack.exe`, `zoom.exe`, `vlc.exe`, `notepad++.exe`, `code.exe`, `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `Acrobat.exe`, `AnyDesk.exe`, `TeamViewer.exe`.

See [HijackLibs](https://hijacklibs.net/) for the full catalog.

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
