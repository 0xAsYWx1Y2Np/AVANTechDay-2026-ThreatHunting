# DLL Sideloading — Trusted Binary + Unsigned DLL

**MITRE ATT&CK:** [T1574.002](https://attack.mitre.org/techniques/T1574/002/) — Hijack Execution Flow: DLL Side-Loading
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** CrowdStrike Falcon (CQL / LogScale)

## Hypothesis

InfoStealers ship a **legitimate signed binary** (e.g., `msedge.exe`, `OneDrive.exe`, `vlc.exe`) alongside a **malicious unsigned DLL** with a name the binary loads at startup (e.g., `msedge_elf.dll`, `version.dll`).

When the trusted binary executes from a user-writable path, Windows loads the malicious DLL from the same directory **before** searching system paths. The attacker's code now runs inside a fully-trusted process.

## Detection invariant

> **Trusted, signed EXE in a user-writable path** + **unsigned DLL in the same directory** + **same process** = sideloading.

---

## Query 1 — Trusted binary in anomalous path + unsigned DLL load

This is the durable detection. Targets [HijackLibs](https://hijacklibs.net/)-documented binaries running from user-writable locations, joined to unsigned DLL loads inside the same process.

```java
#event_simpleName=ProcessRollup2
| OriginalFilename=*
| FileNameLower := lower(FileName)
| OriginalFilenameLower := lower(OriginalFilename)
// Binary is NOT renamed — keeps its real PE name
| FileNameLower = OriginalFilenameLower
// Curated list of signed binaries with documented sideloading abuse
| in(FileNameLower, values=[
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "onedrive.exe", "onedrivestandaloneupdater.exe",
    "teams.exe", "slack.exe", "zoom.exe",
    "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe",
    "wermgr.exe", "dbgsrv.exe", "rdpclip.exe",
    "anydesk.exe", "teamviewer.exe"
  ])
// Running from a user-writable / non-standard path (regex, not in() — in() is exact-match)
| ImageFileName=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp|PerfLogs)\\/
// Pivot: non-system DLL loaded INTO this process from the same kind of suspicious path
| join(
    query={
      #event_simpleName=/ClassifiedModuleLoad|UnsignedModuleLoad/i
      | PrimaryModule=0
      | ImageFileName=/(?i)\.dll$/
      | ImageFileName=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp|PerfLogs)\\/
      | DLL_FileName  := FileName
      | DLL_Path      := ImageFileName
      | DLL_SHA256    := SHA256HashData
    },
    field=[aid, TargetProcessId],
    key=[aid, ContextProcessId],
    include=[DLL_FileName, DLL_Path, DLL_SHA256]
  )
| DetectionType := "TrustedBinary_AnomalousPath"
| groupBy(
    [ComputerName, UserName, ParentBaseFileName,
     FileName, OriginalFilename, ImageFileName,
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

Catches the inverse pattern: a trusted EXE has been **renamed** by the attacker (e.g. `msedge.exe` → `update.exe`) but still keeps its original PE-header `OriginalFilename`. This is rarer but extremely high-fidelity.

```java
#event_simpleName=ProcessRollup2
| OriginalFilename=*
| FileNameLower := lower(FileName)
| OriginalFilenameLower := lower(OriginalFilename)
// Name on disk DIFFERS from PE-header OriginalFilename → renamed binary
| FileNameLower != OriginalFilenameLower
| in(OriginalFilenameLower, values=[
    "msedge.exe", "chrome.exe", "firefox.exe",
    "onedrive.exe", "teams.exe", "slack.exe", "zoom.exe",
    "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "anydesk.exe", "teamviewer.exe"
  ])
| ImageFileName=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp|PerfLogs)\\/
| DetectionType := "RenamedSignedBinary"
| table([@timestamp, ComputerName, UserName, ParentBaseFileName,
         FileName, OriginalFilename, ImageFileName, CommandLine, DetectionType])
| sort(@timestamp, order=desc)
```

> **OriginalFilename reliability:** Populated reliably on `ProcessRollup2`. **Not reliable on `ClassifiedModuleLoad` / `UnsignedModuleLoad`** — so don't filter on it there.

---

## Sideloading targets (HijackLibs reference)

25+ documented targets, including: `msedge.exe`, `chrome.exe`, `firefox.exe`, `teams.exe`, `OneDrive.exe`, `slack.exe`, `zoom.exe`, `vlc.exe`, `notepad++.exe`, `code.exe`, `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `Acrobat.exe`, `AnyDesk.exe`, `TeamViewer.exe`.

See [HijackLibs](https://hijacklibs.net/) for the full catalog.