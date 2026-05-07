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

## Detection invariants

1. **Known shell-company publishers** — block-list of confirmed-bad signers
2. **First-time-seen publisher in tenant** — anomaly detection on new signers
3. **Cert age < 90 days + executable run from user-writable path** — combined risk signal

---

## Query 1 — Block-list of known-bad publishers

```java
#event_simpleName = ProcessRollup2 event_platform=Win
// Suspicious shell-company signers (TamperedChef / BaoLoader / EvilAI cluster)
| AuthenticodeHashData = *
| AuthenticodeAccount = /(?i)(ECHO\s*INFINI|GLINT\s*SOFTWARE|SUMMIT\s*NEXUS|APOLLO\s*TECHNOLOGIES|CAERUS\s*MEDIA|ONESTART\s*TECHNOLOGIES|DIGITAL\s*PROMOTIONS|ECLIPSE\s*MEDIA|ASTRAL\s*MEDIA|INTERLINK\s*MEDIA|MILLENNIAL\s*MEDIA|BLAZE\s*MEDIA|DRAKE\s*MEDIA|INCREDIBLE\s*MEDIA|REALISTIC\s*MEDIA|AMARYLLIS\s*SIGNAL|SHERLOCK\s*TECH|WHATECH\s*MOBILE|MY\s*TECH\s*MEDIA|SORBET\s*LIVE|BLUE\s*TAKIN|CANDY\s*TECH|RED\s*ROOT|A1A\s*MARKETING|CROWN\s*SKY|CROWD\s*SYNC|BYTE\s*MEDIA|LUME\s*NETWORK)/
| table([@timestamp, ComputerName, UserName, FileName, ImageFileName, AuthenticodeAccount, SHA256HashData])
| sort(@timestamp, order=desc)
```

---

## Query 2 — First-seen publisher anomaly

Detects executables signed by publishers never previously seen in your tenant.

```java
#event_simpleName = ProcessRollup2 event_platform=Win
| AuthenticodeAccount = *
// Build a 90-day baseline of known publishers
| join(
    query={
      #event_simpleName = ProcessRollup2 event_platform=Win
      | bucket(span=90d, function=count())
      | groupBy([AuthenticodeAccount], function=[count(as=baseline_count)])
      | baseline_count > 5
    },
    field=AuthenticodeAccount,
    include=baseline_count,
    mode=left
  )
// Surface only the publishers we have NEVER seen before
| baseline_count = ""
// Suspicious paths only
| ImageFileName = /(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\/
| table([@timestamp, ComputerName, UserName, AuthenticodeAccount, FileName, ImageFileName, SHA256HashData])
```

---

## Why this works

- **Shell-company names are reused** — once burned, the same operator often re-registers similar names
- **First-seen publisher anomaly** is a generic detection — works for unknown future campaigns
- **Campaign-specific filename / cmdline matching** is high-confidence for **historical hunting**, low-yield for proactive detection (rotates fast)
