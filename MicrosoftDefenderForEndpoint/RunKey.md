# Run/RunOnce Key Persistence (KQL)

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) — Registry Run Keys / Startup Folder
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

InfoStealers persist via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and `RunOnce`). Defender for Endpoint emits `DeviceRegistryEvents` for any registry write — capturing the durable artifact regardless of which process did the write.

---

## Query 1 — Any process writing Run / RunOnce with user-writable target

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
// Suspicious indicator: value points to a user-writable path
| where RegistryValueData matches regex @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    RegistryKey,
    RegistryValueName,
    RegistryValueData
| sort by Timestamp desc
```

## Query 1B — Inventory mode (no path filter)

Run as a daily inventory. Allowlist legit patterns (`OneDriveSetup`, `MicrosoftEdgeAutoLaunch_*`, vendor updaters); promote anything else to Query 1.

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    @"Software\Microsoft\Windows\CurrentVersion\Run",
    @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )
| summarize Hits = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Devices = make_set(DeviceName, 20)
    by RegistryValueName, RegistryValueData
| sort by FirstSeen desc
```

## Query 2 — `reg.exe` modifying Run / RunOnce (process angle)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "reg.exe"
| where ProcessCommandLine matches regex @"(?i)\b(add|delete)\b"
| where ProcessCommandLine matches regex @"(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?"
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    ProcessCommandLine
| sort by Timestamp desc
```

---

## Why this works

- **`DeviceRegistryEvents` is sensor-side** — fires regardless of which userland process did the write
- **Path-based suspicion filter** in Query 1 reduces noise without losing real stealer drops

## Tuning

- Expect noise from legitimate installers — baseline with a 30-day rolling FP review
- Allowlist known-good `RegistryValueName` patterns (e.g., `OneDriveSetup`, `MicrosoftEdgeAutoLaunch_*`)
- For CrowdStrike equivalent, see [`CrowdStrike/RunKey.md`](../CrowdStrike/RunKey.md)

## References

- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Truesec — TamperedChef / The Bad PDF Editor](https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor)
