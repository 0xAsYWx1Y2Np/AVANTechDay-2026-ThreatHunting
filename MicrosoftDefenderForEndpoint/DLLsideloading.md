# DLL Sideloading — Trusted Binary + Unsigned DLL (KQL)

**MITRE ATT&CK:** [T1574.002](https://attack.mitre.org/techniques/T1574/002/) — Hijack Execution Flow: DLL Side-Loading
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

InfoStealers ship a **legitimate signed binary** alongside a **malicious unsigned DLL** with a name the binary loads at startup. When the trusted binary executes from a user-writable path, Windows loads the malicious DLL from the same directory before searching system paths.

> **KQL Limitation Note:** Defender's `DeviceImageLoadEvents` does NOT expose `OriginalFilename` from the PE header, and Mark-of-the-Web (`ZoneIdentifier=3`) is not directly attached to image-load events. The KQL detection is therefore weaker than the equivalent CQL — we approximate via path-based heuristics and signer mismatch.

## Detection invariant

> **Trusted, signed EXE in a user-writable path** + **unsigned DLL in the same directory** = sideloading.

## Query

```kql
let TrustedBinaries = dynamic([
    "msedge.exe", "chrome.exe", "firefox.exe", "teams.exe", "OneDrive.exe",
    "slack.exe", "zoom.exe", "vlc.exe", "notepad++.exe", "code.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "Acrobat.exe",
    "AnyDesk.exe", "TeamViewer.exe"
]);
let UserWritablePaths = @"(?i)\\(Users\\[^\\]+\\(Downloads|Desktop|Documents|AppData)|Users\\Public|ProgramData|Windows\\Temp)\\";
//
// Step 1 — trusted binaries running from user-writable paths
let SuspectProcs =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ (TrustedBinaries)
    | where FolderPath matches regex UserWritablePaths
    | extend ProcDir = strcat_array(array_slice(split(FolderPath, @"\"), 0, -2), @"\")
    | project
        ProcTime = Timestamp,
        DeviceId,
        DeviceName,
        ProcessId,
        ProcessCreationTime = ProcessCreationTime,
        ProcessFileName = FileName,
        ProcessFolderPath = FolderPath,
        ProcDir,
        AccountName;
//
// Step 2 — DLLs loaded by those processes from the SAME directory
let SideloadCandidates =
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where FileName endswith ".dll"
    | extend DllDir = strcat_array(array_slice(split(FolderPath, @"\"), 0, -2), @"\")
    | join kind=inner SuspectProcs on DeviceId,
        $left.InitiatingProcessId == $right.ProcessId,
        $left.InitiatingProcessCreationTime == $right.ProcessCreationTime
    | where DllDir =~ ProcDir;
//
// Step 3 — enrich with cert info, keep unsigned / untrusted / non-Microsoft DLLs
SideloadCandidates
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, IsSigned, IsTrusted, IsRootSignerMicrosoft, Signer, Issuer) by SHA1
) on SHA1
| where isempty(Signer) or IsSigned == false or IsTrusted == false or IsRootSignerMicrosoft == false
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessFileName,
    ProcessFolderPath,
    DllName = FileName,
    DllFolderPath = FolderPath,
    DllSigner = Signer,
    DllIssuer = Issuer,
    DllIsSigned = IsSigned,
    DllIsTrusted = IsTrusted,
    DllSHA256 = SHA256
| sort by Timestamp desc
```

## Why this works (and where it's limited)

| Aspect | CQL (CrowdStrike) | KQL (MDE) |
| :--- | :--- | :--- |
| Trusted EXE in user path | ✅ | ✅ |
| Unsigned DLL alongside | ✅ | ✅ (via `SignerType` check) |
| PE header `OriginalFilename` mismatch | ✅ | ❌ Not exposed in DLL load events |
| Mark-of-the-Web on DLL | ✅ | ⚠️ Available on file events, not DLL load |
| Process+DLL correlation | ✅ `selfJoin` | ✅ `join` on `InitiatingProcessId` |

## Sideloading targets (HijackLibs reference)

25+ documented targets — see [HijackLibs](https://hijacklibs.net/).

## Known TamperedChef / Vidar sideload pairs

| Trusted binary | Sideloaded DLL | VirusTotal SHA256 |
| :--- | :--- | :--- |
| `msedge.exe` | `msedge_elf.dll` | `cc482813e22e8163d60982340dd4ec13e316565f0e6cf455d07550ccf348858a` |
| Chromium-based | `libGLESv2.dll` | (see `IOCs/hashes.txt`) |
| Chromium-based | `libEGL.dll` | (see `IOCs/hashes.txt`) |
| Chromium-based | `vk_swiftshader.dll` | (see `IOCs/hashes.txt`) |

## Tuning

- Some legit installers run from `\Downloads\` briefly during install — exclude installer parents
- Portable apps (legitimate, but technically sideloading-shaped) — allowlist by hash

## References

- [MITRE ATT&CK T1574.002](https://attack.mitre.org/techniques/T1574/002/)
- [HijackLibs](https://hijacklibs.net/)
