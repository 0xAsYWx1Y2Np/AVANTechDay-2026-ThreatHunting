# Run/RunOnce Key Persistence

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) — Registry Run Keys / Startup Folder
**Tactic:** [TA0003](https://attack.mitre.org/tactics/TA0003/) — Persistence
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

InfoStealers persist via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (and `RunOnce`) to survive logoff / reboot. The attacker has multiple code paths to write this key — `reg.exe`, PowerShell `Set-ItemProperty`, .NET `Microsoft.Win32.Registry`, direct syscalls.

**Two queries cover both surfaces:**

- **Query 1** — catches the registry write itself, regardless of how it was triggered (the durable invariant)
- **Query 2** — catches the explicit `reg.exe` invocation (the obvious path)

---

## Query 1 — `AsepValueUpdate` on Run / RunOnce with user-writable target

CrowdStrike emits `AsepValueUpdate` whenever **any** Auto-Start Extensibility Point is written, regardless of the calling process. **This is the durable detection.** The path filter on `RegStringValue` cuts the bulk of legitimate installer noise (which writes to `Program Files` / `System32`).

```java
#event_simpleName=AsepValueUpdate
| RegObjectName=/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/i
// Target value points to a user-writable path
| RegStringValue=/(?i)\\(Users\\Public|Users\\[^\\]+\\(AppData|Downloads|Desktop)|ProgramData|Windows\\Temp)\\/
| table([@timestamp, ComputerName, UserName, RegObjectName, RegValueName, RegStringValue])
| sort(@timestamp, order=desc)
```

## Query 1B — `AsepValueUpdate` on Run / RunOnce (no path filter, inventory mode)

Run as a daily inventory; allowlist the legit patterns (`OneDriveSetup`, `MicrosoftEdgeAutoLaunch_*`, `iCloudServices`, vendor updater patterns); promote anything else to Query 1.

```java
#event_simpleName=AsepValueUpdate
| RegObjectName=/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/i
| groupBy([RegValueName, RegStringValue, ComputerName],
          function=[count(as=Hits), min(@timestamp, as=FirstSeen), max(@timestamp, as=LastSeen)])
| sort(FirstSeen, order=desc)
```

## Query 2 — `reg.exe` modifying Run / RunOnce

Catches the explicit `reg.exe add` / `reg.exe delete` invocation. Misses every other write path — but the command line is great for investigation.

```java
#event_simpleName=ProcessRollup2
| ImageFileName=/\\reg\.exe$/i
| CommandLine=/\b(add|delete)\b/i
| CommandLine=/\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?/i
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc)
```

---

## Why this works

- **`AsepValueUpdate` is sensor-side** — fires regardless of which userland process did the write
- **Path-based suspicion filter** in Query 1 reduces installer noise without sacrificing coverage
- **`reg.exe` Query 2** captures the cmdline context for investigation

## Tuning

- Expect noise from legitimate installers — baseline with a 30-day rolling FP review
- Allowlist known-good `RegValueName` patterns (e.g., `OneDriveSetup`, `MicrosoftEdgeAutoLaunch_*`)
- For Defender XDR equivalent, see [`MicrosoftDefenderForEndpoint/RunKey.md`](../MicrosoftDefenderForEndpoint/RunKey.md)

## References

- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Truesec — TamperedChef / The Bad PDF Editor](https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor)
