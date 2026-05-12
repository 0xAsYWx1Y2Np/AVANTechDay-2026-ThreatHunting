# ClickFix — RunMRU Paste Detection (KQL)

**MITRE ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) — User Execution: Malicious Copy and Paste
**Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002/) — Execution
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

When a user is tricked into pressing `Win+R` and pasting a payload (the "ClickFix" / fake-CAPTCHA technique), Windows automatically writes the pasted command into the `RunMRU` registry key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`.

---

## Query 1 — RunMRU write with suspicious payload

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where strlen(RegistryValueData) > 50
| where RegistryValueData matches regex @"(?i)(powershell|pwsh|cmd|mshta|wscript|cscript|certutil|bitsadmin|curl|wget|msbuild|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|hidden|encodedcommand|nslookup|odbcad32)"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    RegistryValueName,
    RegistryValueData,
    RegistryValueDataLength = strlen(RegistryValueData)
| sort by Timestamp desc
```

## Query 1B — Optional sibling (developer / power-user shells)

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where strlen(RegistryValueData) > 50
| where RegistryValueData matches regex @"(?i)(wt\.exe|conhost\.exe|pwsh\.exe)"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryValueData
| sort by Timestamp desc
```

---

## Query 2 — Confirmation pivot: matching child process

When Query 1 hits, this finds the LOLBin spawn within ±60s on the same host. A RunMRU write **plus** an `explorer.exe → powershell.exe` (or similar) within seconds is high-confidence ClickFix.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
                      "wscript.exe", "cscript.exe", "certutil.exe",
                      "bitsadmin.exe", "curl.exe", "msbuild.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|https?://)"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| sort by Timestamp desc
```

## Pairing Query 1 + Query 2

Combine in scheduled detection logic:

1. Trigger only when **both** Query 1 AND Query 2 fire on the same host within a 60-second window.
2. Severity = `HIGH` when paired; `LOW` when only Query 1 fires (registry write without confirming spawn is often legitimate user activity).

Example join:

```kql
let RunMRUWrites =
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType == "RegistryValueSet"
    | where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    | where strlen(RegistryValueData) > 50
    | where RegistryValueData matches regex @"(?i)(powershell|pwsh|cmd|mshta|wscript|cscript|certutil|bitsadmin|curl|wget|msbuild|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|hidden|encodedcommand)"
    | project MRU_Time = Timestamp, DeviceId, AccountName = InitiatingProcessAccountName,
              RegistryValueData;
let LOLBinSpawns =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe",
                          "wscript.exe", "cscript.exe", "certutil.exe",
                          "bitsadmin.exe", "curl.exe", "msbuild.exe")
    | project Spawn_Time = Timestamp, DeviceId, FileName, ProcessCommandLine;
RunMRUWrites
| extend TimeKey = bin(MRU_Time, 2m)
| join kind=inner (
    LOLBinSpawns
    | extend TimeKey = bin(Spawn_Time, 2m)
) on DeviceId, TimeKey
| where Spawn_Time >= MRU_Time and Spawn_Time <= MRU_Time + 60s
| project MRU_Time, Spawn_Time, DeviceId, AccountName, RegistryValueData, FileName, ProcessCommandLine
| sort by MRU_Time desc
```

---

## Why this works

- **Registry write is forced** — Windows logs every Run-dialog entry, no user / process can suppress it
- **Length filter** weeds out legitimate short Run-dialog use (e.g., `cmd`, `regedit`, `services.msc`)
- **LOLBin regex** narrows to malicious-looking command lines
- **Process pivot** confirms execution actually followed the paste

## Tuning

- Allowlist your IT admins' frequently-used Run commands if they trigger noise
- Adjust `strlen(RegistryValueData) > 50` if your environment uses longer legitimate commands
- For 24×7 SOCs, only alert on **Query 1 ∧ Query 2** pairing — drastically reduces FP rate

## References

- [MITRE ATT&CK T1204.004 — Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)
