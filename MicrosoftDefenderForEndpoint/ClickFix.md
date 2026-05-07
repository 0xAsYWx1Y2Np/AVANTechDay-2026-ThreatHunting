# ClickFix — RunMRU Paste Detection (KQL)

**MITRE ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) — User Execution: Malicious Copy and Paste
**Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002/) — Execution
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

When a user is tricked into pressing `Win+R` and pasting a payload (the "ClickFix" / fake-CAPTCHA technique), Windows automatically writes the pasted command into the `RunMRU` registry key under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`.

## Query

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
| where strlen(RegistryValueData) > 50
| where RegistryValueData matches regex @"(?i)(powershell|pwsh|cmd|mshta|wscript|cscript|certutil|bitsadmin|curl|wget|msbuild|conhost|wt\.exe|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|hidden|encodedcommand|nslookup|odbcad32)"
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

## Why this works

- **Registry write is forced** — Windows logs every Run-dialog entry, no user/process can suppress it
- **Length filter** weeds out legitimate short Run-dialog use
- **LOLBin regex** narrows to malicious-looking command lines

## Tuning

- Allowlist your IT admins' frequently-used Run commands if they trigger noise
- Adjust `strlen(RegistryValueData) > 50` if your environment uses longer legitimate commands
- Pair with downstream `DeviceProcessEvents` searching for PowerShell with `-WindowStyle Hidden`

## References

- [MITRE ATT&CK T1204.004 — Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)
