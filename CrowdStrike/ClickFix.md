# ClickFix — RunMRU Paste Detection

**MITRE ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) — User Execution: Malicious Copy and Paste
**Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002/) — Execution
**Platform:** CrowdStrike Falcon (CQL / LogScale)

## Hypothesis

When a user is tricked into pressing `Win+R` and pasting a payload (the "ClickFix" / fake-CAPTCHA technique), Windows automatically writes the pasted command into the `RunMRU` registry key. **There is no other code path** — the registry write is a forced telemetry artifact.

This makes RunMRU the durable detection invariant for ClickFix, regardless of:

- Which LOLBin the attacker chooses (`powershell`, `cmd`, `mshta`, `cscript`, `curl`, `wget`, …)
- How the payload is obfuscated (Base64, string-concat, etc.)
- Whether the execution is fileless

## Query

```java
#event_simpleName=RegSystemConfigValueUpdate
| RegObjectName=/\\REGISTRY\\USER\\.+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU/i
| RunCommand := RegStringValue
| RunCommandLength := length(RunCommand)
| RunCommandLength > 50
// LOLBin / common ClickFix payload markers
| RunCommand=/(?i)(powershell|pwsh|cmd|mshta|wscript|cscript|certutil|bitsadmin|curl|wget|msbuild|conhost|wt\.exe|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|hidden|encodedcommand|nslookup|odbcad32)/
| table([@timestamp, ComputerName, UserName, RunCommand, RunCommandLength])
| sort(@timestamp, order=desc)
```