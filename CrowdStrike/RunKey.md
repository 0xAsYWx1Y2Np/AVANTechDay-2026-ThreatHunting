# Run/RunOnce Key Persistence

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) — Registry Run Keys / Startup Folder
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Platform:** CrowdStrike Falcon (CQL / LogScale)

## Hypothesis

InfoStealers persist via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and `RunOnce`) to survive logoff/reboot. The attacker has multiple code paths to write this key — `reg.exe`, PowerShell `Set-ItemProperty`, .NET `Microsoft.Win32.Registry`, direct syscalls.

**Two queries cover both surfaces:**

- **Query 1** — catches `reg.exe` invocations (the obvious path)
- **Query 2** — catches the registry write itself, regardless of how it was triggered (the durable invariant)

---

## Query 1 — `reg.exe` modifying Run / RunOnce

Catches the explicit `reg.exe add` / `reg.exe delete` invocation.

```java
#event_simpleName = ProcessRollup2
| ImageFileName = /\\reg\.exe$/i
| CommandLine = /\b(add|delete)\b/i
| CommandLine = /\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
```

**Limitation:** Misses every other write path (PowerShell, .NET, syscalls).

---

## Query 2 — `AsepValueUpdate` on Run / RunOnce

CrowdStrike emits `AsepValueUpdate` whenever **any** Auto-Start Extensibility Point is written, regardless of the calling process. **This is the durable detection.**

```java
#event_simpleName = AsepValueUpdate
| RegObjectName = /\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/i
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue])
```