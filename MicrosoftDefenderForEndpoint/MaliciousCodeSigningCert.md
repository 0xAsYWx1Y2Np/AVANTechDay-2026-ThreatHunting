# Malicious Code-Signing Certificates — Shell-Company Publishers (KQL)

**MITRE ATT&CK:** [T1553.002](https://attack.mitre.org/techniques/T1553/002/) — Subvert Trust Controls: Code Signing
**Tactic:** [TA0005](https://attack.mitre.org/tactics/TA0005/) — Defense Evasion
**Platform:** Microsoft Defender XDR (KQL)

---

## Hypothesis

Attackers obtain valid Authenticode certificates from CAs by registering shell companies in jurisdictions like Panama, Malaysia, Hong Kong, the UK, and the US. Per Expel's research, the **BaoLoader** developer alone has cycled through at least **26 code-signing certificates** in 7 years.

## Query 1 — Block-list of known-bad publishers

```kql
let SuspiciousSigners = dynamic([
    "ECHO INFINI SDN. BHD.",
    "GLINT SOFTWARE SDN. BHD.",
    "Summit Nexus Holdings LLC",
    "Apollo Technologies Inc.",
    "Caerus Media LLC",
    "Onestart Technologies LLC",
    "Digital Promotions Sdn. Bhd.",
    "Eclipse Media Inc.",
    "Astral Media Inc",
    "Interlink Media Inc.",
    "Millennial Media Inc.",
    "Blaze Media Inc.",
    "Drake Media Inc",
    "Incredible Media Inc",
    "Realistic Media Inc.",
    "Amaryllis Signal Ltd",
    "Sherlock Tech Ltd",
    "Whatech Mobile Co., Limited",
    "My Tech Media Ltd",
    "Sorbet Live Ltd",
    "Blue Takin Ltd",
    "Candy Tech Ltd",
    "Red Root Ltd",
    "A1A Marketing Ltd.",
    "Crown Sky LLC",
    "Crowd Sync LLC",
    "Byte Media",
    "Lume Network Sdn Bhd"
]);
let SuspiciousBinaries =
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | where Signer in~ (SuspiciousSigners)
    | where IsRootSignerMicrosoft == false
    | summarize arg_max(Timestamp, Signer, SignerHash, IsTrusted, IsSigned) by SHA1;
DeviceProcessEvents
| where Timestamp > ago(30d)
| join kind=inner SuspiciousBinaries on SHA1
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    Signer,
    SignerHash,
    IsTrusted,
    SHA256
| sort by Timestamp desc
```

## Query 2 — First-seen publisher anomaly

```kql
let baseline =
    DeviceFileCertificateInfo
    | where Timestamp between (ago(120d) .. ago(30d))
    | where isnotempty(Signer)
    | summarize baseline_count = count() by Signer
    | where baseline_count > 5
    | project Signer;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"(?i)\\(Users\\[^\\]+\\(AppData|Downloads|Desktop)|Users\\Public|ProgramData|Windows\\Temp)\\"
| join kind=inner (
    DeviceFileCertificateInfo
    | where Timestamp > ago(7d)
    | where isnotempty(Signer)
    | summarize arg_max(Timestamp, Signer, IsSigned, IsTrusted) by SHA1
) on SHA1
| where Signer !in (baseline)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, Signer, IsSigned, IsTrusted, SHA256
| sort by Timestamp desc
```