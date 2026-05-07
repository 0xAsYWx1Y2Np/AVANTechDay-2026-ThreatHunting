# DLL Sideloading — Trusted Binary + Unsigned DLL

**MITRE ATT&CK:** [T1574.002](https://attack.mitre.org/techniques/T1574/002/) — Hijack Execution Flow: DLL Side-Loading
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** CrowdStrike Falcon (CQL / LogScale)

## Hypothesis

InfoStealers ship a **legitimate signed binary** (e.g., `msedge.exe`, `OneDrive.exe`, `vlc.exe`) alongside a **malicious unsigned DLL** with a name the binary loads at startup (e.g., `msedge_elf.dll`, `version.dll`).

When the trusted binary executes from a user-writable path, Windows loads the malicious DLL from the same directory **before** searching system paths. The attacker's code now runs inside a fully-trusted process.

## Detection invariant

> **Trusted, signed EXE in a user-writable path** + **unsigned DLL in the same directory** + **same process** = sideloading.

## Query

```java
// CQL: DLL sideloading — trusted binary loads unsigned DLL from user-writable path
// Step 1 — process executions of known sideload-target binaries
| target := { #event_simpleName = ProcessRollup2 }
| target.FileName = /(?i)\\(msedge|chrome|firefox|teams|onedrive|slack|zoom|vlc|notepad\+\+|code|winword|excel|powerpnt|outlook|acrobat|anydesk|teamviewer)\.exe$/
// Step 2 — running from a user-writable path (NOT Program Files / System32)
| target.ImageFileName = /(?i)\\(Users\\[^\\]+\\(Downloads|Desktop|Documents|AppData)|Users\\Public|ProgramData|Windows\\Temp)\\/
// Step 3 — joined with module load events (selfJoin on aid + ProcessId)
| selfJoin(
    field=[aid, TargetProcessId],
    where=[
      { #event_simpleName = ProcessRollup2 },
      { #event_simpleName = ImageHash AND PrimaryModule = 0 AND SignInfoFlags != 0 }
    ]
  )
// Step 4 — file metadata: name mismatches PE header OriginalFileName (manipulated DLL)
| FileName != OriginalFilename
// Step 5 — Mark-of-the-Web (downloaded from internet — extra suspicion)
| ZoneIdentifier = 3
| table([
    @timestamp,
    ComputerName,
    UserName,
    target.FileName,
    target.ImageFileName,
    DLL.FileName,
    DLL.SignInfoFlags,
    OriginalFilename
  ])
```

## Sideloading targets (HijackLibs reference)

25+ documented targets, including: `msedge.exe`, `chrome.exe`, `firefox.exe`, `teams.exe`, `OneDrive.exe`, `slack.exe`, `zoom.exe`, `vlc.exe`, `notepad++.exe`, `code.exe`, `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `Acrobat.exe`, `AnyDesk.exe`, `TeamViewer.exe`.

See [HijackLibs](https://hijacklibs.net/) for the full catalog.

```java
// Hunt: Trusted Signed Binary Executing from Anomalous Path
// Scenario: legitimate signed binary (e.g. msedge.exe) dropped into a user-writable
// location next to a malicious DLL — classic DLL sideloading.
#event_simpleName=ProcessRollup2 event_platform=Win
| OriginalFilename=*
| FileNameLower := lower(FileName)
| OriginalFilenameLower := lower(OriginalFilename)
// Binary is NOT renamed — keeps its real PE name
| FileNameLower = OriginalFilenameLower
// Curated list of signed binaries with documented sideloading abuse
// (sources: HijackLibs, MITRE ATT&CK, public CTI reports)
| in(field="FileNameLower", values=[
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
    "onedrive.exe", "onedrivestandaloneupdater.exe",
    "teams.exe", "slack.exe", "zoom.exe",
    "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe",
    "wermgr.exe", "dbgsrv.exe", "rdpclip.exe",
    "anydesk.exe", "teamviewer.exe"
  ])
// Running from a user-writable / non-standard path
| in(field="FilePath", values=[
    "*\\Users\\Public\\*",
    "*\\Users\\*\\AppData\\Local\\Temp\\*",
    "*\\Users\\*\\AppData\\Roaming\\*",
    "*\\Users\\*\\AppData\\Local\\*",
    "*\\Users\\*\\Downloads\\*",
    "*\\Users\\*\\Desktop\\*",
    "*\\ProgramData\\*",
    "*\\Windows\\Temp\\*",
    "*\\PerfLogs\\*"
  ])
// Pivot: non-system DLL loaded INTO this process from the same kind of suspicious path
| join(
    query={
      #event_simpleName=/^(ClassifiedModuleLoad|UnsignedModuleLoad)$/ event_platform=Win
      | PrimaryModule=0
      | ImageFileName=/(?i)\.dll$/
      | in(field="ImageFileName", values=[
          "*\\Users\\Public\\*",
          "*\\Users\\*\\AppData\\Local\\Temp\\*",
          "*\\Users\\*\\AppData\\Roaming\\*",
          "*\\Users\\*\\AppData\\Local\\*",
          "*\\Users\\*\\Downloads\\*",
          "*\\Users\\*\\Desktop\\*",
          "*\\ProgramData\\*",
          "*\\Windows\\Temp\\*",
          "*\\PerfLogs\\*"
        ])
      | rename(field="FileName", as="DLL_FileName")
      | rename(field="ImageFileName", as="DLL_Path")
      | rename(field="SHA256HashData", as="DLL_SHA256")
    },
    field=[aid, TargetProcessId],
    key=[aid, ContextProcessId],
    include=[DLL_FileName, DLL_Path, DLL_SHA256]
  )
| DetectionType := "TrustedBinary_AnomalousPath"
| groupBy([
    ComputerName, UserName, ParentBaseFileName,
    FileName, OriginalFilename, FilePath,
    DLL_FileName, DLL_Path, DLL_SHA256, DetectionType
  ])
```