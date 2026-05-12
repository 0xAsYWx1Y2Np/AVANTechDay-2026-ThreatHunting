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
| 🔁 Persistence | Malicious Chrome extensions ⭐ | [✓](CrowdStrike/MaliciousChromeExtensions.md) | [✓](MicrosoftDefenderForEndpoint/MaliciousChromeExtensions.md) |
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
├── 📁 CrowdStrike/                       ← CQL queries (LogScale / Falcon)
│   ├── ClickFix.md
│   ├── RunKey.md
│   ├── DLLsideloading.md
│   ├── CredentialAccess.md
│   ├── MaliciousCodeSigningCert.md
│   ├── MaliciousChromeExtensions.md      ← 
│   └── UsingIOCFiles.md                  ← feed IOCs/*.txt into match()
│
├── 📁 MicrosoftDefenderForEndpoint/      ← KQL queries (Defender XDR / Sentinel)
│   ├── ClickFix.md
│   ├── RunKey.md
│   ├── DLLsideloading.md
│   ├── CredentialAccess.md
│   ├── MaliciousCodeSigningCert.md
│   ├── MaliciousChromeExtensions.md      ← 
│   └── UsingIOCFiles.md                  ← feed IOCs/*.txt into externaldata()
│
├── 📁 Sigma/                             ← cross-platform Sigma rules
│   └── dcsync_nonmachine.yml
│
├── 📁 OSINT/
│   └── urlscan-pivot.md                  ← unmask the lure cluster
│
└── 📁 IOCs/                              ← historical anchors — see disclaimer
    ├── domains.txt                       (130 lure / hosting domains)
    ├── c2.txt                            (17 C2 domains)
    ├── ips.txt                           (13 IP addresses)
    ├── hashes.txt                        (131 SHA256 + 32 SHA1 + 1 MD5)
    ├── code-signing.txt                  (51 shell-company publishers — UPDATED)
    ├── chrome-extensions.txt             (111 Chrome extension IDs — NEW)
    │
    └── 📁 csv/                           ← Falcon Lookup-File–ready CSVs (header rows)
        ├── code-signing.csv              (51 rows · column: signer)
        ├── chrome-extensions.csv         (111 rows · column: extension_id)
        ├── domains.csv                   (130 rows · column: domain)
        ├── c2.csv                        (17 rows · column: domain)
        ├── ips.csv                       (13 rows · column: ip)
        ├── hashes-sha256.csv             (131 rows · column: sha256)
        ├── hashes-sha1.csv               (32 rows · column: sha1)
        └── hashes-md5.csv                (1 row · column: md5)
```

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

| Platform | Mechanism | File source | Guide |
| :--- | :--- | :--- | :--- |
| Microsoft Defender XDR | `externaldata` operator (URL fetch at query time, always-fresh) | `IOCs/*.txt` raw GitHub URLs | [`MicrosoftDefenderForEndpoint/UsingIOCFiles.md`](MicrosoftDefenderForEndpoint/UsingIOCFiles.md) |
| CrowdStrike Falcon | `match(file="…")` against an uploaded Lookup File | `IOCs/csv/*.csv` uploaded via UI or Files API | [`CrowdStrike/UsingIOCFiles.md`](CrowdStrike/UsingIOCFiles.md) |

> **Heads-up — CQL cannot pull from a URL at query time.** Unlike KQL's `externaldata`, LogScale has no inline HTTP fetcher. The `IOCs/csv/` files are pre-built (one column with a header row) so you can `POST` them straight to the [Lookup API](https://library.humio.com/logscale-api/api-lookup.html). The CQL guide includes a **GitHub Actions workflow** that auto-syncs `IOCs/csv/**` to your tenant on every push — same end result as `externaldata`, one indirection step.

Both guides include shell one-liners, full working examples for code-signing publishers, Chrome extension IDs, lure domains, C2 domains, IPs, and file hashes, plus a cheat-sheet mapping each file to the right schema field.

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

<div align="center">

| 📝 Blog | [tec-bite.ch](https://www.tec-bite.ch/) |

</div>

---

<div align="center">

### 🎯 *Hunt behaviour, not hashes.*

</div>