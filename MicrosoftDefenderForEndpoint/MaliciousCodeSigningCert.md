# Malicious Code-Signing Certificates — Shell-Company Publishers (KQL)

**MITRE ATT&CK:** [T1553.002](https://attack.mitre.org/techniques/T1553/002/) — Subvert Trust Controls: Code Signing
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

Attackers obtain valid Authenticode certificates from CAs by registering shell companies in jurisdictions like Panama, Malaysia, Hong Kong, the UK, and the US. The certificate is technically valid, but the publisher is a paper company that exists only on the certificate.

Per Expel's research, the **BaoLoader** developer alone has cycled through at least **26 code-signing certificates** in 7 years. The canonical publisher list lives in [`IOCs/code-signing.txt`](../IOCs/code-signing.txt) (45 entries) and [`IOCs/csv/code-signing.csv`](../IOCs/csv/code-signing.csv).

---

## Query 1 — Block-list via `externaldata` (recommended)

Use [`externaldata`](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator) to read the canonical CSV directly from GitHub on each query run. Single source of truth — edit the CSV, the query picks up new entries.

```kql
let BadSigners =
    externaldata(signer: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/code-signing.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project signer = tolower(trim(@"\s+", signer))
    | summarize by signer;
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where IsSigned == true
| extend SignerLower = tolower(trim(@"\s+", Signer))
| where SignerLower in (BadSigners)
| project Timestamp, DeviceName, Signer, Issuer, SignatureType,
          IsTrusted, IsRootSignerMicrosoft, CertificateExpirationTime,
          SHA1
| sort by Timestamp desc
```

Lower-casing both sides ensures `ECHO INFINI SDN. BHD.` matches `echo infini sdn. bhd.` — handles CA-side casing drift without maintaining variants. This is the KQL equivalent of LogScale's `match(ignoreCase=true)`.

## Query 2 — Block-list hit → process execution pivot

```kql
let BadSigners =
    externaldata(signer: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/code-signing.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project signer = tolower(trim(@"\s+", signer))
    | summarize by signer;
let SuspectHashes =
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | where IsSigned == true
    | extend SignerLower = tolower(trim(@"\s+", Signer))
    | where SignerLower in (BadSigners)
    | summarize arg_max(Timestamp, Signer, Issuer) by SHA1;
DeviceProcessEvents
| where Timestamp > ago(30d)
| where isnotempty(SHA1)
| lookup kind=inner SuspectHashes on SHA1
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, ProcessCommandLine, Signer, Issuer, SHA1
| sort by Timestamp desc
```

---

## Query 3 — First-seen publisher anomaly (the durable detection)

Runs with a 30-day baseline and surfaces publishers first observed inside the last 7 days. The block-list catches *known* bad publishers; this query catches tomorrow's shell-company.

Suppression filters keep one-off ISV-update noise out without blunting coverage:
- `ModuleLoads > 1` — strip single-observation flukes
- `UniqueDevices >= 2` — strip per-device personal-software installs
- `UniqueBinaries > 1` — a single hash signed by a brand-new publisher is often a legitimate vendor update; multiple distinct binaries from one new publisher in user-writable paths is the stealer pattern

```kql
let Baseline =
    DeviceFileCertificateInfo
    | where Timestamp between (ago(30d) .. ago(30d))
    | where IsSigned == true
    | summarize by Signer;
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where IsSigned == true
| where isnotempty(Signer)
| where Issuer !contains "Microsoft Windows" and Issuer !contains "Microsoft Code Signing" and Issuer !contains "Microsoft Root" and Issuer !contains "Microsoft Time-Stamp"
| where not(Signer in (Baseline))
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FolderPath matches regex @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\"
    | project SHA1, DeviceId, FolderPath, FileName
  ) on SHA1
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            ModuleLoads = count(),
            UniqueDevices = dcount(DeviceId),
            UniqueBinaries = dcount(SHA1),
            SampleFiles = make_set(FileName, 10),
            SampleIssuers = make_set(Issuer, 5),
            SampleDevices = make_set(DeviceId, 10)
    by Signer
| where ModuleLoads > 1 and UniqueDevices >= 2 and UniqueBinaries > 1
| sort by UniqueDevices desc
```

---

## Why this works

- **Shell-company names are reused** — once burned, the same operator often re-registers similar names
- **Block-list via `externaldata`** — single source of truth, zero query edits when the list changes
- **First-seen publisher anomaly** is a generic detection — works for unknown future campaigns
- **Suppression filters** kill one-off vendor-update noise without blunting coverage of real stealer patterns`

## References

- [MITRE ATT&CK T1553.002](https://attack.mitre.org/techniques/T1553/002/)
- [Expel — The certs of the BaoLoader developer](https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/)
- [DeviceFileCertificateInfo schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefilecertificateinfo-table)
- [`externaldata` operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)
- [`UsingIOCFiles.md`](UsingIOCFiles.md) — how to feed CSVs into KQL
