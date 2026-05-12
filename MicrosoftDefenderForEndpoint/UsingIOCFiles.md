# Using the `IOCs/csv/*.csv` files in KQL hunts

**Platform:** Microsoft Defender XDR (KQL — Advanced Hunting)

This guide shows how to feed the [`IOCs/csv/`](../IOCs/csv/) files into Defender XDR Advanced Hunting queries without pasting hundreds of values into a regex by hand.

---

## The good news — KQL has `externaldata`

Unlike LogScale, [Defender XDR KQL supports `externaldata`](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator) — an operator that fetches a CSV directly from any HTTPS URL on every query execution. No upload, no API, no scheduled refresh — just a URL.

```text
GitHub raw URL  →  externaldata in query  →  evaluated on each run
```

The trade-off vs an uploaded lookup: every query execution fetches the file. For a 100-row CSV that's negligible; for the 130-entry `hashes-sha256.csv` it's still fine. Pin to a specific commit if you want reproducibility.

---

## The eight CSV files

| CSV | Column | Rows | KQL table | KQL field |
| :--- | :--- | ---: | :--- | :--- |
| `code-signing.csv` | `signer` | 45 | `DeviceFileCertificateInfo` | `Signer` |
| `chrome-extensions.csv` | `extension_id` | 112 | `DeviceFileEvents` (FolderCreated under `\Extensions\<id>`) | extracted via regex from `FolderPath` |
| `domains.csv` | `domain` | 133 | `DeviceNetworkEvents` | `RemoteUrl` (extract hostname) |
| `c2.csv` | `domain` | 17 | `DeviceNetworkEvents` | `RemoteUrl` (extract hostname) |
| `ips.csv` | `ip` | 13 | `DeviceNetworkEvents` | `RemoteIP` |
| `hashes-sha256.csv` | `sha256` | 131 | `DeviceProcessEvents` | `SHA256` (less reliable) — **prefer SHA1** |
| `hashes-sha1.csv` | `sha1` | 32 | `DeviceProcessEvents` | `SHA1` |
| `hashes-md5.csv` | `md5` | 1 | `DeviceProcessEvents` | `MD5` |

> **SHA1 vs SHA256:** Microsoft documents that `SHA256` on `DeviceProcessEvents` "is usually not populated — use the `SHA1` column when available." The split CSVs let you stay in the right column.

> **C2 vs domains:** `c2.csv` and `domains.csv` are **disjoint** — domains that are also confirmed C2 (`9mdp5f.com`, `banifuri.com`, `dcownil.com`) live in `c2.csv` only.

---

## The canonical `externaldata` pattern

Use this once at the top of any query. Trim and lowercase to handle whitespace and CA-side casing drift.

```kql
let RawUrl = @"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/code-signing.csv";
let BadSigners =
    externaldata(signer: string) [RawUrl]
    with (format="csv", ignoreFirstRecord=true)
    | project signer = tolower(trim(@"\s+", signer))
    | summarize by signer;
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where IsSigned == true
| extend SignerLower = tolower(trim(@"\s+", Signer))
| where SignerLower in (BadSigners)
| project Timestamp, DeviceName, Signer, Issuer, SHA1, SHA256
| sort by Timestamp desc
```

> Pin to a specific commit (`/<sha>/IOCs/csv/…`) instead of `main` for reproducibility once you've tested the query.

---

## One-stop query cookbook

### Code-signing — block-list of bad publishers

See `MaliciousCodeSigningCert.md` — Query 1 above.

### Code-signing → execution pivot

```kql
let BadSigners =
    externaldata(signer: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/code-signing.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project signer = tolower(trim(@"\s+", signer));
let SuspectHashes =
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | where IsSigned == true
    | extend SignerLower = tolower(trim(@"\s+", Signer))
    | where SignerLower in (BadSigners)
    | project SHA1, Signer, Issuer;
DeviceProcessEvents
| where Timestamp > ago(30d)
| join kind=inner SuspectHashes on SHA1
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, FolderPath, ProcessCommandLine, Signer, Issuer, SHA1
| sort by Timestamp desc
```

### Chrome extensions — bad-ID extension folder created

```kql
let BadExtensionIds =
    externaldata(extension_id: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/chrome-extensions.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project extension_id = tolower(trim(@"\s+", extension_id));
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FolderCreated"
| where FolderPath matches regex @"(?i)\\(Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser|Chromium|Vivaldi|Opera\sSoftware|Yandex)\\.*\\Extensions\\[a-p]{32}$"
| extend ExtensionId = tolower(extract(@"\\Extensions\\([a-p]{32})$", 1, FolderPath))
| where ExtensionId in (BadExtensionIds)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), DeviceCount = dcount(DeviceId)
    by ExtensionId
| sort by LastSeen desc
```

### Lure domains — DNS / HTTP lookups against the PDF-tool cluster

```kql
let LureDomains =
    externaldata(domain: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/domains.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project domain = tolower(trim(@"\s+", domain));
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| extend Hostname = tolower(extract(@"https?://([^/:]+)", 1, RemoteUrl))
| where Hostname in (LureDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, Hostname, RemoteUrl, RemotePort
| sort by Timestamp desc
```

> `DeviceNetworkEvents` exposes hostname only via the `RemoteUrl` field — the regex extracts it. For DNS query telemetry, also check `DeviceEvents` where `ActionType == "DnsQueryResponse"` (parses `AdditionalFields`).

### C2 domains — separate file so you can promote sooner

```kql
let C2Domains =
    externaldata(domain: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/c2.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project domain = tolower(trim(@"\s+", domain));
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| extend Hostname = tolower(extract(@"https?://([^/:]+)", 1, RemoteUrl))
| where Hostname in (C2Domains)
| extend Severity = "HIGH"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, Hostname, RemoteUrl, RemotePort, Severity
| sort by Timestamp desc
```

### IPs — outbound connections to known infrastructure

```kql
let BadIPs =
    externaldata(ip: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/ips.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project ip = trim(@"\s+", ip);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (BadIPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc
```

> Many entries in `ips.csv` are Cloudflare-fronted shared ranges (`104.21.x.x`, `172.67.x.x`). Expect false positives — pair with the domain or hash hits before promoting to alert.

### File hashes — execution of known bad PEs (three separate files)

```kql
// SHA-256 — 131 entries (less reliably populated on DeviceProcessEvents; prefer SHA1)
let BadSHA256 =
    externaldata(sha256: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/hashes-sha256.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project sha256 = tolower(trim(@"\s+", sha256));
DeviceProcessEvents
| where Timestamp > ago(30d)
| where isnotempty(SHA256)
| extend SHA256Lower = tolower(SHA256)
| where SHA256Lower in (BadSHA256)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256
| sort by Timestamp desc
```

```kql
// SHA-1 — 32 entries (more reliably populated)
let BadSHA1 =
    externaldata(sha1: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/hashes-sha1.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project sha1 = tolower(trim(@"\s+", sha1));
DeviceProcessEvents
| where Timestamp > ago(30d)
| where isnotempty(SHA1)
| extend SHA1Lower = tolower(SHA1)
| where SHA1Lower in (BadSHA1)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA1
| sort by Timestamp desc
```

```kql
// MD5 — 1 entry, included for completeness
let BadMD5 =
    externaldata(md5: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/hashes-md5.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project md5 = tolower(trim(@"\s+", md5));
DeviceProcessEvents
| where Timestamp > ago(30d)
| where isnotempty(MD5)
| extend MD5Lower = tolower(MD5)
| where MD5Lower in (BadMD5)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, MD5
| sort by Timestamp desc
```

### Hash hit → signer enrichment (optional add-on)

```kql
let BadSHA1 =
    externaldata(sha1: string)
    [@"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/main/IOCs/csv/hashes-sha1.csv"]
    with (format="csv", ignoreFirstRecord=true)
    | project sha1 = tolower(trim(@"\s+", sha1));
DeviceProcessEvents
| where Timestamp > ago(30d)
| extend SHA1Lower = tolower(SHA1)
| where SHA1Lower in (BadSHA1)
| join kind=leftouter (
    DeviceFileCertificateInfo
    | where Timestamp > ago(30d)
    | project SHA1 = tolower(SHA1), Signer, Issuer, IsSigned, IsTrusted
  ) on $left.SHA1Lower == $right.SHA1
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          SHA1, Signer, Issuer, IsSigned, IsTrusted
| sort by Timestamp desc
```

---

## Reproducibility — pin to a commit SHA

`main` is convenient for testing. For production scheduled detections, pin to an immutable commit:

```kql
let RawUrl = @"https://raw.githubusercontent.com/0xAsYWx1Y2Np/AVANTechDay-2026-ThreatHunting/<commit-sha>/IOCs/csv/code-signing.csv";
```

`<commit-sha>` is any 40-char or 7-char abbreviation of a git commit. The query becomes byte-stable until you intentionally re-pin.

---

## Cheat sheet — which CSV → which table → which field

| Lookup file | Column | KQL table | KQL field |
| :--- | :--- | :--- | :--- |
| `code-signing.csv` | `signer` | `DeviceFileCertificateInfo` | `Signer` (issuer enrichment via `Issuer`) |
| `chrome-extensions.csv` | `extension_id` | `DeviceFileEvents` (FolderCreated under `\Extensions\<id>`) | extracted via regex from `FolderPath`; also `RegistryValueData` for force-install policy, `RemoteUrl` for CRX download |
| `domains.csv` | `domain` | `DeviceNetworkEvents`, `DeviceEvents` (DnsQueryResponse) | hostname extracted from `RemoteUrl`; `AdditionalFields` for DNS |
| `c2.csv` | `domain` | `DeviceNetworkEvents`, `DeviceEvents` (DnsQueryResponse) | hostname extracted from `RemoteUrl`; `AdditionalFields` for DNS |
| `ips.csv` | `ip` | `DeviceNetworkEvents` | `RemoteIP` |
| `hashes-sha256.csv` | `sha256` | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents` | `SHA256` (often empty) |
| `hashes-sha1.csv` | `sha1` | (same as above) | `SHA1` (preferred) |
| `hashes-md5.csv` | `md5` | (same as above) | `MD5` |

---

## References

- [`externaldata` operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)
- [Advanced Hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceProcessEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) — SHA256 reliability caveat
