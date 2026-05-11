# Malicious Code-Signing Certificates — Shell-Company Publishers

**MITRE ATT&CK:** [T1553.002](https://attack.mitre.org/techniques/T1553/002/) — Subvert Trust Controls: Code Signing
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** CrowdStrike Falcon (CQL / LogScale)

---

## Hypothesis

Attackers obtain valid Authenticode certificates from CAs by registering shell companies in jurisdictions like Panama, Malaysia, Hong Kong, the UK, and the US. The certificate is technically valid, but the publisher is a paper company that exists only on the certificate.

Per Expel's research, the **BaoLoader** developer alone has cycled through at least **26 code-signing certificates** in 7 years. Common publishers include:

- ECHO INFINI SDN. BHD.
- GLINT SOFTWARE SDN. BHD.
- SUMMIT NEXUS HOLDINGS LLC
- Apollo Technologies Inc.
- Caerus Media LLC
- Onestart Technologies LLC
- (see `IOCs/code-signing.txt` for the full list)

> **Schema note:** Signer subject/issuer data lives on `Event_ModuleSummaryInfoEvent` (module-load summary), not on `ProcessRollup2`. Fields used: `SubjectCN`, `IssuerCN`, `SHA256HashData`, `FileName`. To pivot from a hit back to process execution context, join on `SHA256HashData` against `ProcessRollup2`.

## Detection invariants

1. **Known shell-company publishers** — block-list of confirmed-bad signers
2. **First-time-seen publisher in tenant** — anomaly detection on new signers
3. **Cert age < 90 days + executable run from user-writable path** — combined risk signal

---

## Query 1 — Block-list of known-bad publishers

```java
#event_simpleName=Event_ModuleSummaryInfoEvent
| SubjectCN=/ECHO INFINI|GLINT SOFTWARE|SUMMIT NEXUS|APOLLO TECHNOLOGIES|CAERUS MEDIA|ONESTART TECHNOLOGIES|DIGITAL PROMOTIONS|ECLIPSE MEDIA|ASTRAL MEDIA|INTERLINK MEDIA|MILLENNIAL MEDIA|BLAZE MEDIA|DRAKE MEDIA|INCREDIBLE MEDIA|REALISTIC MEDIA|AMARYLLIS SIGNAL|SHERLOCK TECH|WHATECH MOBILE|MY TECH MEDIA|SORBET LIVE|BLUE TAKIN|CANDY TECH|RED ROOT|A1A MARKETING|CROWN SKY|CROWD SYNC|BYTE MEDIA|LUME NETWORK|TAU CENTAURI|SPARROW TIDE|TECHNODENIS|BLACK INDIGO|LONG SOUND|OR KAHOL|ASTRO BRIGHT|MAINSTAY CRYPTO|GRASSROOTS CONSULTING|WORK PRODUCT|PIXEL CATALYST|GLOBAL TECH ALLIES|SIRIUS ONE|SELA LINES|BONY INNOVATION/i
| table([@timestamp, ComputerName, aid, SubjectCN, IssuerCN, SHA256HashData, FileName])
| sort(@timestamp, order=desc)
```

### Pivot to executions

Paste SHA256s from Query 1 into the `values=[...]` list:

```java
#event_simpleName=ProcessRollup2
| in(SHA256HashData, values=["<sha1>", "<sha2>"])
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, CommandLine, SHA256HashData])
| sort(@timestamp, order=desc)
```

### Or join in one shot

```java
#event_simpleName=ProcessRollup2
| join(
    query={
      #event_simpleName=Event_ModuleSummaryInfoEvent
      | SubjectCN=/ECHO INFINI|GLINT SOFTWARE|SUMMIT NEXUS|APOLLO TECHNOLOGIES|CAERUS MEDIA|ONESTART TECHNOLOGIES|DIGITAL PROMOTIONS|ECLIPSE MEDIA|ASTRAL MEDIA|INTERLINK MEDIA|MILLENNIAL MEDIA|BLAZE MEDIA|DRAKE MEDIA|INCREDIBLE MEDIA|REALISTIC MEDIA|AMARYLLIS SIGNAL|SHERLOCK TECH|WHATECH MOBILE|MY TECH MEDIA|SORBET LIVE|BLUE TAKIN|CANDY TECH|RED ROOT|A1A MARKETING|CROWN SKY|CROWD SYNC|BYTE MEDIA|LUME NETWORK|TAU CENTAURI|SPARROW TIDE|TECHNODENIS|BLACK INDIGO|LONG SOUND|OR KAHOL|ASTRO BRIGHT|MAINSTAY CRYPTO|GRASSROOTS CONSULTING|WORK PRODUCT|PIXEL CATALYST|GLOBAL TECH ALLIES|SIRIUS ONE|SELA LINES|BONY INNOVATION/i
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

## Query 2 — First-seen publisher anomaly

Run over a **90-day lookback** (or longer). Returns publishers whose `FirstSeen` falls inside the last 7 days — i.e. never observed in the tenant prior to that. The `ModuleLoads > 1` filter strips one-off noise; raise to 3+ if results are still too chatty.

The Microsoft-issuer exclusion strips the bulk of legitimate Windows module loads. Keep this exclusion **narrow** — don't add DigiCert/Sectigo/GlobalSign here, since shell-company certs are issued by exactly those public CAs.

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
| sort(UniqueDevices, order=desc, limit=200)
```

---

## Why this works

- **Shell-company names are reused** — once burned, the same operator often re-registers similar names
- **First-seen publisher anomaly** is a generic detection — works for unknown future campaigns
- **Campaign-specific filename / cmdline matching** is high-confidence for **historical hunting**, low-yield for proactive detection (rotates fast)

## Operational notes

- `Event_ModuleSummaryInfoEvent` fires on module load — expect signed DLLs/EXEs from legit installers (Electron updaters, third-party signed payloads in user temp) to show up. Build a per-tenant allowlist of legit vendors after the first run.
- The `IssuerCN` collect in Query 2 is the TamperedChef/EvilAI tell at a glance: Certum EV, SSL.com EV, GlobalSign GCC R45 EV, Microsoft Trusted Signing.
- To pivot from any hit back to process execution context, join `SHA256HashData` against `ProcessRollup2`.