<div align="center">

# 🎯 Threat Hunting — AVANTech Day 2026

![AVANTECLogo](https://www.avantec.ch/wp-content/uploads/2018/11/logo_avantec.png)


**Hunt pack and detection engineering reference for the InfoStealer ecosystem and the fake-PDF-tool delivery cluster.**

`BaoLoader` · `TamperedChef` · `AppSuite-PDF` · `ManualFinder` · `OneStart` · `EvilAI` · `cloudapi.stream`

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![CrowdStrike](https://img.shields.io/badge/CrowdStrike-LogScale-FA0F00)](https://www.crowdstrike.com/)
[![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender_XDR-0078D4)](https://learn.microsoft.com/en-us/defender-xdr/)
[![Sigma](https://img.shields.io/badge/Sigma-Rules-orange)](https://github.com/SigmaHQ/sigma)

</div>

---

## 💡 Why this exists

> **Your data left. You just haven't noticed yet.**

Signatures and IOCs rotate in days. Behaviour doesn't. This repo focuses on the **durable detection invariants** that survive payload, family, and certificate changes — and gives you the IOC plumbing to chase the rotating artefacts at the same time.

---

## 🔍 Quick access — jump to a query

| Phase | Hunt | CrowdStrike (CQL) | Defender (KQL) |
| :---: | :--- | :---: | :---: |
| 🎯 Execution | ClickFix — RunMRU paste | [✓](CrowdStrike/ClickFix.md) | [✓](MicrosoftDefenderForEndpoint/ClickFix.md) |
| 🔁 Persistence | Run/RunOnce key writes | [✓](CrowdStrike/RunKey.md) | [✓](MicrosoftDefenderForEndpoint/RunKey.md) |
| 🔁 Persistence | Malicious extensions ⭐ | [✓](CrowdStrike/MaliciousExtensions.md) | [✓](MicrosoftDefenderForEndpoint/MaliciousExtensions.md) |
| 🥷 Defense Evasion | DLL sideloading pattern | [✓](CrowdStrike/DLLsideloading.md) | [✓](MicrosoftDefenderForEndpoint/DLLsideloading.md) |
| 🥷 Defense Evasion | Malicious code-signing certs | [✓](CrowdStrike/MaliciousCodeSigningCert.md) | [✓](MicrosoftDefenderForEndpoint/MaliciousCodeSigningCert.md) |
| 🔑 Credential Access | The Browser-Credential Chokepoint ⭐ | [✓](CrowdStrike/CredentialAccess.md) | [✓](MicrosoftDefenderForEndpoint/CredentialAccess.md) |
| 🔑 Credential Access | DCSync via Replication Rights | [Sigma rule](Sigma/dcsync_nonmachine.yml) | — |
| 🧰 **How-to** | **Use the `IOCs/*.txt` files in your queries** ⭐ | [✓](CrowdStrike/UsingIOCFiles.md) | [✓](MicrosoftDefenderForEndpoint/UsingIOCFiles.md) |
| 🕵️ OSINT | urlscan.io pivot on the React-app fingerprint | [Guide](OSINT/urlscan-pivot.md) | [Guide](OSINT/urlscan-pivot.md) |

---

## 📂 What's inside

```text
AVANTechDay-2026-ThreatHunting/
│
├── 📄 README.md                          ← you are here
│
├── 📁 CrowdStrike/                       ← CQL queries (LogScale / CQL)
│   ├── ClickFix.md                       # T1204.004 — RunMRU paste detection
│   ├── RunKey.md                         # T1547.001 — Run/RunOnce persistence
│   ├── DLLsideloading.md                 # T1574.002 — trusted binary + unsigned DLL
│   ├── CredentialAccess.md               # T1555.003 — the FileOpenInfo chokepoint
│   ├── MaliciousCodeSigningCert.md       # T1553.002 — shell-company publishers
│   ├── MaliciousExtensions.md      # T1176    — malicious browser extensions
│   └── UsingIOCFiles.md                  # how to wire the CSVs into match()
│
├── 📁 MicrosoftDefenderForEndpoint/      ← KQL queries (Defender XDR / KQL)
│   ├── ClickFix.md
│   ├── RunKey.md
│   ├── DLLsideloading.md
│   ├── CredentialAccess.md               # 3 complementary surfaces (FileOpenInfo has no MDE equivalent)
│   ├── MaliciousCodeSigningCert.md
│   ├── MaliciousExtensions.md
│   └── UsingIOCFiles.md                  # how to wire the CSVs into externaldata
│
├── 📁 Sigma/                             ← cross-platform Sigma rules
│   └── dcsync_nonmachine.yml             # T1003.006 — DCSync from a non-machine account
│
├── 📁 OSINT/
│   └── urlscan-pivot.md                  # pivoting from one hash to a full campaign
│
└── 📁 IOCs/                              ← historical anchors — see disclaimer
    ├── domains.txt                       # 133 lure / hosting domains
    ├── c2.txt                            #  17 C2 domains (disjoint from domains.txt)
    ├── ips.txt                           #  13 IPs (most Cloudflare-fronted — see notes)
    ├── hashes.txt                        # 164 hashes (131 SHA-256 + 32 SHA-1 + 1 MD5)
    ├── code-signing.txt                  #  45 canonical shell-company publishers
    ├── chrome-extensions.txt             # 112 malicious extension IDs (with campaign notes)
    └── 📁 csv/                           ← Falcon Lookup-File–ready CSVs (header rows)
        ├── domains.csv         (133)
        ├── c2.csv              ( 17)
        ├── ips.csv             ( 13)
        ├── hashes-sha256.csv   (131)
        ├── hashes-sha1.csv     ( 32)
        ├── hashes-md5.csv      (  1)
        ├── code-signing.csv    ( 45)
        └── chrome-extensions.csv (112)


```

---

## Design philosophy — durable invariants over campaign artifacts

The questions every detection in this repo had to answer:

1. **What is the smallest forced-telemetry artifact the attacker cannot avoid producing?**
2. **Does the query target that artifact, or does it target a campaign-of-the-week's filename / cmdline / hash?**

The answer drives where each rule sits on the [Pyramid of Pain](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html). Examples in this pack:

| Detection | Durable invariant | Coverage half-life |
|---|---|---|
| ClickFix | RunMRU registry write — Windows logs every Run-dialog entry | Years (forced by Explorer) |
| Browser credential theft (CQL) | Non-browser process opens `Login Data` SQLite | Years (only path to harvest) |
| DLL sideloading | Trusted EXE in user-writable path + unsigned DLL in same dir | Years (Windows DLL search order) |
| Code-signing publisher | Shell-company name in Authenticode subject | Months (operators rotate) |
| Chrome extension ID | 32-char SHA-256 of the public key | Forever (deterministic) |

The IOC files exist because operational teams need lookup tables to feed `match()` and `externaldata`; they are not the primary detection surface.

---

## 🚀 How to use

| Step | Action |
| :---: | :--- |
| **1️⃣** | Read the threat landscape and MITRE chain to understand the *why*. |
| **2️⃣** | Pick hunts relevant to your stack — `MDE = KQL`, `CrowdStrike = CQL`. |
| **3️⃣** | Wire the [`IOCs/`](IOCs/) files into your queries via [`UsingIOCFiles.md`](CrowdStrike/UsingIOCFiles.md) ([KQL](MicrosoftDefenderForEndpoint/UsingIOCFiles.md)) so updates land automatically. |
| **4️⃣** | Run as hunts first, baseline FPs, then promote to scheduled detections. |
| **5️⃣** | **Pair detections across phases** — single signals will drown your analysts. |
| **6️⃣** | Pin detections to the durable invariants, not the IOCs. |

---

## 🔌 Using the IOC files in your queries

### CrowdStrike (CQL / LogScale)

1. Upload all eight CSVs from `IOCs/csv/` to your tenant under **Falcon Console → Next-Gen SIEM → Lookup files** → **Create file** → **Import file** (or use the GitHub Actions auto-sync in [`CrowdStrike/UsingIOCFiles.md`](CrowdStrike/UsingIOCFiles.md))
2. Open any `CrowdStrike/*.md` and paste the first query into Advanced Event Search
3. Adjust the time window to your tenant's retention
4. See [`CrowdStrike/UsingIOCFiles.md`](CrowdStrike/UsingIOCFiles.md) for the `match()` cheat sheet — which CSV → which event → which field

### Microsoft Defender for Endpoint (KQL)

1. No upload needed — KQL has [`externaldata`](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator) and fetches CSVs directly from the GitHub raw URLs
2. Open any `MicrosoftDefenderForEndpoint/*.md` and paste a query into Defender XDR → Advanced Hunting
3. For reproducibility, pin the `externaldata` URL to a commit SHA (see [`MicrosoftDefenderForEndpoint/UsingIOCFiles.md`](MicrosoftDefenderForEndpoint/UsingIOCFiles.md))

### Sigma

`Sigma/dcsync_nonmachine.yml` — drop into any [sigma-cli](https://github.com/SigmaHQ/sigma-cli)-supported pipeline (Splunk, Sentinel, Elastic, Wazuh, …). Backend translation handles the EventID 4662 + Properties / SubjectUserName filter logic.

---

## 🔒 The durable invariants

> These do **not** rotate.

- 🔑 **Credential access** — non-browser process opens browser credential SQLite + DPAPI call
- 📋 **ClickFix** — RunMRU registry write with long encoded LOLBin command
- 🧬 **DLL sideloading** — trusted EXE loads non-trusted DLL from user-writable directory
- 🧩 **Malicious extensions** — deterministic Web-Store ID written under `…\User Data\<Profile>\Extensions\<id>\`
- ⏱️ **Sandbox evasion** — scheduled task with >24h delayed first run from non-system parent
- 🌐 **C2 fronting** — TLS to newly-registered Cloudflare-fronted domain from non-browser PID
- 🔐 **DCSync** — non-machine, non-service account invokes DS-Replication-Get-Changes(-All)

---

## 📊 IOCs — historical anchors

> ⚠️ **These rotate constantly.** Block them, but invest your detection-engineering hours in the [durable invariants](#-the-durable-invariants) above.

| Type | Count | File | Notes |
| :--- | :---: | :--- | :--- |
| Domains (lure / hosting) | 130 | [`IOCs/domains.txt`](IOCs/domains.txt) | urlscan.io pivot — `main.<hex>.js` + `/report` fingerprint |
| C2 domains | 17 | [`IOCs/c2.txt`](IOCs/c2.txt) | Cloudflare-fronted, newly-registered |
| IP addresses | 13 | [`IOCs/ips.txt`](IOCs/ips.txt) | Cloudflare-fronted ranges — high collateral if blocked |
| File hashes (SHA256/SHA1/MD5) | 164 | [`IOCs/hashes.txt`](IOCs/hashes.txt) | PDF Editor, ManualFinder, EpiBrowser, Vidar `msedge_elf.dll` |
| Code-signing publishers | **51** | [`IOCs/code-signing.txt`](IOCs/code-signing.txt) | shell-company EV certs (Malaysia, Panama, UK, HK) — **+15 added 2026-05** |
| Chrome extension IDs | **111** | [`IOCs/chrome-extensions.txt`](IOCs/chrome-extensions.txt) | Socket cloudapi.stream MaaS (108) + Unit42 MCP RAT + VKfeed + CL Suite |
| **Falcon-ready CSVs** | **8 files** | [`IOCs/csv/`](IOCs/csv/) | Same data, one-column-with-header for `match()` — see [`CrowdStrike/UsingIOCFiles.md`](CrowdStrike/UsingIOCFiles.md) |

**Source attribution:**
[Truesec (2025-08-27)](https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor) ·
[Expel](https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/) ·
[Heimdal](https://heimdalsecurity.com/blog/heimdal-tamperedchef-investigation/) ·
[WithSecure](https://labs.withsecure.com/publications/tamperedchef) ·
[Socket — 108 Chrome extensions](https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2) ·
[Palo Alto Unit 42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel) ·
[LindenSec IoC repo](https://github.com/LindenSec/IoC/tree/main/PDFEditorManualFinder)

---

## ⚠️ Disclaimer

> Hunt queries are **starting points**, not drop-in detections.  
> Tune to your environment before promoting to scheduled rules.  
> IOCs are **historical anchors** — the actor cluster rotates infrastructure constantly.  

---

## Talks & references

- [TamperedChef / The Bad PDF Editor — Truesec](https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor)
- [The certs of the BaoLoader developer — Expel](https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/)
- [108 Chrome extensions linked to data exfil & session theft — Socket](https://socket.dev/blog/108-chrome-ext-linked-to-data-exfil-session-theft-shared-c2)
- [Common TTPs of RATs & Stealers — Splunk Threat Research, Jan 2026](https://www.splunk.com/en_us/blog/security/common-ttps-rats-malware-analysis.html)
- [LindenSec InfoStealer IOC repo](https://github.com/LindenSec/InfoStealer-IOCs) — many of the SHA-256 entries
- [HijackLibs](https://hijacklibs.net/) — DLL sideloading target catalog
- [MITRE ATT&CK](https://attack.mitre.org/)

---

<div align="center">

📝 Blog · [tec-bite.ch](https://www.tec-bite.ch/)

</div>

---

<div align="center">

### 🎯 *Hunt behaviour, not hashes.*

</div>