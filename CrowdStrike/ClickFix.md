# ClickFix — RunMRU Paste Detection

**MITRE ATT&CK:** [T1204.004](https://attack.mitre.org/techniques/T1204/004/) — User Execution: Malicious Copy and Paste
**Tactic:** [TA0002](https://attack.mitre.org/tactics/TA0002/) — Execution
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

When a user is tricked into pressing `Win+R` and pasting a payload (the "ClickFix" / fake-CAPTCHA technique), Windows automatically writes the pasted command into the `RunMRU` registry key. **There is no other code path** — the registry write is a forced telemetry artifact.

This makes RunMRU the durable detection invariant for ClickFix, regardless of:

- Which LOLBin the attacker chooses (`powershell`, `cmd`, `mshta`, `cscript`, `curl`, `wget`, …)
- How the payload is obfuscated (Base64, string-concat, etc.)
- Whether the execution is fileless

---

## Query 1 — RunMRU write with suspicious payload

```java
#event_simpleName=RegSystemConfigValueUpdate
| RegObjectName=/\\REGISTRY\\USER\\.+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU/i
| RunCommand := RegStringValue
| RunCommandLength := length(RunCommand)
| RunCommandLength > 50
// LOLBin / common ClickFix payload markers
| RunCommand=/(?i)(powershell|pwsh|cmd|mshta|wscript|cscript|certutil|bitsadmin|curl|wget|msbuild|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|hidden|encodedcommand|nslookup|odbcad32)/
| table([@timestamp, ComputerName, UserName, RunCommand, RunCommandLength])
| sort(@timestamp, order=desc)
```

## Query 1B — Optional sibling (developer / power-user shells)

```java
#event_simpleName=RegSystemConfigValueUpdate
| RegObjectName=/\\REGISTRY\\USER\\.+\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU/i
| RunCommand := RegStringValue
| CmdLen := length("RunCommand")
| CmdLen > 50
| RunCommand=/(?i)(wt\.exe|conhost\.exe|pwsh\.exe)/
| table([@timestamp, ComputerName, UserName, RunCommand, CmdLen])
| sort(@timestamp, order=desc)
```

---

## Query 2 — Confirmation pivot: matching child process

When Query 1 hits, this finds the LOLBin spawn within ±60s on the same host. A RunMRU write **plus** an `explorer.exe → powershell.exe` (or similar) within seconds is high-confidence ClickFix.

```java
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/^explorer\.exe$/i
| ImageFileName=/\\(powershell\.exe|pwsh\.exe|cmd\.exe|mshta\.exe|wscript\.exe|cscript\.exe|certutil\.exe|bitsadmin\.exe|curl\.exe|msbuild\.exe)$/i
| CommandLine=/(?i)(-enc|-encodedcommand|-w\s+hidden|-windowstyle\s+hidden|iex|invoke-expression|invokewebrequest|downloadstring|frombase64string|http(s)?:\/\/)/
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---

## Why this works

- **RunMRU is forced telemetry** — Windows writes every Run-dialog entry, no process can suppress it
- **Length filter** weeds out legitimate short Run-dialog use (e.g., `cmd`, `regedit`, `services.msc`)
- **LOLBin regex** narrows to malicious-looking command lines
- **Process pivot** confirms execution actually followed the paste

## Tuning

- Allowlist your IT admins' frequently-used Run commands if they trigger noise
- Adjust `length > 50` if your environment uses longer legitimate commands

## References

- [MITRE ATT&CK T1204.004 — Malicious Copy and Paste](https://attack.mitre.org/techniques/T1204/004/)