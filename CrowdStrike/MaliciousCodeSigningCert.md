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

> **Schema note:** `AuthenticodeAccount` is populated on `ProcessRollup2` when the sensor enriches Authenticode metadata. If coverage is sparse in your tenant, enrich via `ImageHash`/`ImageHashIOC` joined on `SHA256HashData` — analogous to the KQL `DeviceFileCertificateInfo` SHA1 join.

## Detection invariants

1. **Known shell-company publishers** — block-list of confirmed-bad signers
2. **First-time-seen publisher in tenant** — anomaly detection on new signers
3. **Cert age < 90 days + executable run from user-writable path** — combined risk signal

---

## Query 1 — Block-list of known-bad publishers

```
#event_simpleName=ProcessRollup2 event_platform=Win
| AuthenticodeAccount=/(?i)(ECHO\s*INFINI|GLINT\s*SOFTWARE|SUMMIT\s*NEXUS|APOLLO\s*TECHNOLOGIES|CAERUS\s*MEDIA|ONESTART\s*TECHNOLOGIES|DIGITAL\s*PROMOTIONS|ECLIPSE\s*MEDIA|ASTRAL\s*MEDIA|INTERLINK\s*MEDIA|MILLENNIAL\s*MEDIA|BLAZE\s*MEDIA|DRAKE\s*MEDIA|INCREDIBLE\s*MEDIA|REALISTIC\s*MEDIA|AMARYLLIS\s*SIGNAL|SHERLOCK\s*TECH|WHATECH\s*MOBILE|MY\s*TECH\s*MEDIA|SORBET\s*LIVE|BLUE\s*TAKIN|CANDY\s*TECH|RED\s*ROOT|A1A\s*MARKETING|CROWN\s*SKY|CROWD\s*SYNC|BYTE\s*MEDIA|LUME\s*NETWORK|TAU\s*CENTAURI|SPARROW\s*TIDE|TECHNODENIS|BLACK\s*INDIGO|LONG\s*SOUND|OR\s*KAHOL|ASTRO\s*BRIGHT|MAINSTAY\s*CRYPTO|GRASSROOTS\s*CONSULTING|WORK\s*PRODUCT|PIXEL\s*CATALYST|GLOBAL\s*TECH\s*ALLIES|SIRIUS\s*ONE|SELA\s*LINES|BONY\s*INNOVATION)/
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, AuthenticodeAccount, SHA256HashData])
| sort(@timestamp, order=desc)
```

---

## Query 2 — First-seen publisher anomaly

Run over a **90-day lookback** (or longer). Returns publishers whose `FirstSeen` falls inside the last 7 days — i.e. never observed in the tenant prior to that. The `>1` execution filter strips one-off noise; raise to 3+ if results are still too chatty.

```
#event_simpleName=ProcessRollup2 event_platform=Win
| AuthenticodeAccount=*
| ImageFileName=/(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\/
| groupBy([AuthenticodeAccount],
          function=[
            min(@timestamp, as=FirstSeen),
            max(@timestamp, as=LastSeen),
            count(as=ExecutionCount),
            count(field=aid, distinct=true, as=UniqueDevices),
            count(field=SHA256HashData, distinct=true, as=UniqueBinaries),
            collect(fields=[FileName], limit=10),
            collect(fields=[ComputerName], limit=10)
          ])
// Publisher first observed within the last 7 days of the search window
| FirstSeen > (now() - 7*24*60*60*1000)
| ExecutionCount > 1
| sort(UniqueDevices, order=desc, limit=200)
```

---

## Why this works

- **Shell-company names are reused** — once burned, the same operator often re-registers similar names
- **First-seen publisher anomaly** is a generic detection — works for unknown future campaigns
- **Campaign-specific filename / cmdline matching** is high-confidence for **historical hunting**, low-yield for proactive detection (rotates fast)