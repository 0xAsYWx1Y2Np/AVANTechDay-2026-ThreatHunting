# Malicious Code-Signing Certificates — Shell-Company Publishers

**MITRE ATT&CK:** [T1553.002](https://attack.mitre.org/techniques/T1553/002/) — Subvert Trust Controls: Code Signing
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

Attackers obtain valid Authenticode certificates from CAs by registering shell companies in jurisdictions like Panama, Malaysia, Hong Kong, the UK, and the US. The certificate is technically valid, but the publisher is a paper company that exists only on the certificate.

Per Expel's research, the **BaoLoader** developer alone has cycled through at least **26 code-signing certificates** in 7 years. The canonical publisher list lives in [`IOCs/code-signing.txt`](../IOCs/code-signing.txt) (45 entries) and [`IOCs/csv/code-signing.csv`](../IOCs/csv/code-signing.csv).

## Detection invariants

1. **Known shell-company publishers** — `match()` against the uploaded lookup file
2. **First-time-seen publisher in tenant** — anomaly detection on new signers (immune to bad-list staleness)
3. **Cert age < 90 days + executable run from user-writable path** — combined risk signal

---

## Query 1 — Block-list via `match()` (recommended)

Single source of truth: the uploaded `code-signing.csv` lookup. Add new publishers to the CSV; the query picks them up on next run.

> **Prerequisite:** Upload `IOCs/csv/code-signing.csv` to your Falcon tenant as a Lookup File. See [`UsingIOCFiles.md`](UsingIOCFiles.md) for one-shot upload, GitHub Actions auto-sync, or the `falconpy` Python option.

```java
#event_simpleName=Event_ModuleSummaryInfoEvent
| SubjectCN=*
| match(file="code-signing.csv", column="signer", field=SubjectCN, strict=true, ignoreCase=true)
| table([@timestamp, ComputerName, aid, SubjectCN, IssuerCN, SHA256HashData, FileName])
| sort(@timestamp, order=desc)
```

`ignoreCase=true` handles CA-side casing drift (`ECHO INFINI SDN. BHD.` ↔ `Echo Infini Sdn. Bhd.` ↔ `echo infini sdn. bhd.`) — no need to maintain three variants of the same publisher.

## Query 2 — Block-list hit → process execution pivot

Same lookup, joined back to `ProcessRollup2` so you see *who* ran the signed binary, with what command line, under which user.

```java
#event_simpleName=ProcessRollup2
| join(
    query={
      #event_simpleName=Event_ModuleSummaryInfoEvent
      | SubjectCN=*
      | match(file="code-signing.csv", column="signer", field=SubjectCN, strict=true, ignoreCase=true)
      | groupBy([SHA256HashData], function=[selectLast(SubjectCN), selectLast(IssuerCN)])
    },
    field=SHA256HashData,
    include=[SubjectCN, IssuerCN],
    mode=inner
  )
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, CommandLine, SubjectCN, IssuerCN, SHA256HashData])
| sort(@timestamp, order=desc)
```

---

## Query 3 — First-seen publisher anomaly (the durable detection)

Run with a **90-day lookback** (or longer). Returns publishers whose `FirstSeen` falls inside the last 7 days — i.e. never observed in the tenant before that. **The block-list catches *known* bad publishers. This query catches tomorrow's shell-company before it's on anyone's list.**

Suppression filters reduce one-off ISV-update noise without blunting coverage:

- `ModuleLoads > 1` — strip single-observation flukes
- `UniqueDevices >= 2` — strip per-device personal-software installs
- `IssuerCN!=...` — narrow exclude for legitimate Microsoft module loads (keep this list short — shell-company certs are issued by mainstream public CAs like DigiCert, Sectigo, GlobalSign, so don't exclude those)

```java
#event_simpleName=Event_ModuleSummaryInfoEvent
| SubjectCN=*
| IssuerCN!=/Microsoft (Windows|Code Signing|Root|Time-Stamp)/i
| FileName=/\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\/i
| groupBy([SubjectCN],
          function=[
            min(@timestamp, as=FirstSeen),
            max(@timestamp, as=LastSeen),
            count(as=ModuleLoads),
            count(field=aid, distinct=true, as=UniqueDevices),
            count(field=SHA256HashData, distinct=true, as=UniqueBinaries),
            collect(fields=[FileName], limit=10),
            collect(fields=[IssuerCN], limit=5),
            collect(fields=[ComputerName], limit=10)
          ])
| Cutoff := now() - duration("7d")
| test(FirstSeen > Cutoff)
| ModuleLoads > 1
| UniqueDevices >= 2
| sort(UniqueDevices, order=desc, limit=200)
```

---

## Why this works

- **Shell-company names are reused** — once burned, the same operator often re-registers similar names
- **Block-list via `match()`** — single source of truth, zero query edits when the list changes
- **First-seen publisher anomaly** is a generic detection — works for unknown future campaigns
- **Campaign-specific filename / cmdline matching** is high-confidence for **historical hunting**, low-yield for proactive detection (rotates fast)

## Operational notes

- `Event_ModuleSummaryInfoEvent` fires on module load — expect signed DLLs/EXEs from legit installers (Electron updaters, third-party signed payloads in user temp) to show up. Build a per-tenant allowlist of legit vendors after the first run.
- The `IssuerCN` collect in Query 3 is the TamperedChef / EvilAI tell at a glance: Certum EV, SSL.com EV, GlobalSign GCC R45 EV, Microsoft Trusted Signing.
- To pivot from any hit back to process execution context, join `SHA256HashData` against `ProcessRollup2`.

## References

- [MITRE ATT&CK T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [Expel — The certs of the BaoLoader developer](https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/)
- [`UsingIOCFiles.md`](UsingIOCFiles.md) — how to feed `code-signing.csv` into `match()`
