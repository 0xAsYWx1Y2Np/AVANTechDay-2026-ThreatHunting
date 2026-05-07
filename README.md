<div align="center">

# 🎯 Threat Hunting — AVANTech Day 2026

**Hunt pack and detection engineering reference for the InfoStealer ecosystem and the fake-PDF-tool delivery cluster.**

`BaoLoader` · `TamperedChef` · `AppSuite-PDF` · `ManualFinder` · `OneStart` · `EvilAI`

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![CrowdStrike](https://img.shields.io/badge/CrowdStrike-LogScale-FA0F00)](https://www.crowdstrike.com/)
[![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender_XDR-0078D4)](https://learn.microsoft.com/en-us/defender-xdr/)
[![Sigma](https://img.shields.io/badge/Sigma-Rules-orange)](https://github.com/SigmaHQ/sigma)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 💡 Why this exists

> **Your data left. You just haven't noticed yet.**

Signatures and IOCs rotate in days. Behaviour doesn't. This repo focuses on the **durable detection invariants** that survive payload, family, and certificate changes.

---

## 🔍 Quick access — jump to a query

| Phase | Hunt | CrowdStrike (CQL) | Defender (KQL) |
| :---: | :--- | :---: | :---: |
| 🎯 Execution | ClickFix — RunMRU paste | [✓](CrowdStrike/ClickFix.md) | [✓](MicrosoftDefenderForEndpoint/ClickFix.md) |
| 🔁 Persistence | Run/RunOnce key writes | [✓](CrowdStrike/RunKey.md) | [✓](MicrosoftDefenderForEndpoint/RunKey.md) |
| 🥷 Defense Evasion | DLL sideloading pattern | [✓](CrowdStrike/DLLsideloading.md) | [✓](MicrosoftDefenderForEndpoint/DLLsideloading.md) |
| 🥷 Defense Evasion | Malicious code-signing certs | [✓](CrowdStrike/MaliciousCodeSigningCert.md) | [✓](MicrosoftDefenderForEndpoint/MaliciousCodeSigningCert.md) |
| 🔑 Credential Access | The Browser-Credential Chokepoint ⭐ | [✓](CrowdStrike/CredentialAccess.md) | [✓](MicrosoftDefenderForEndpoint/CredentialAccess.md) |
| 🔑 Credential Access | DCSync via Replication Rights (Sigma) | [Sigma rule](Sigma/dcsync_nonmachine.yml) | — |

---

## 📂 What's inside

```text
AVANTechDay-2026-ThreatHunting/
│
├── 📄 README.md                          ← you are here
├── 📄 LICENSE                            ← MIT
│
├── 📁 CrowdStrike/                       ← CQL queries (LogScale / Falcon)
│   ├── ClickFix.md
│   ├── RunKey.md
│   ├── DLLsideloading.md
│   ├── CredentialAccess.md
│   └── MaliciousCodeSigningCert.md
│
├── 📁 MicrosoftDefenderForEndpoint/      ← KQL queries (Defender XDR)
│   ├── ClickFix.md
│   ├── RunKey.md
│   ├── DLLsideloading.md
│   ├── CredentialAccess.md
│   └── MaliciousCodeSigningCert.md
│
├── 📁 Sigma/                             ← cross-platform Sigma rules
│   └── dcsync_nonmachine.yml
│
├── 📁 OSINT/
│   └── urlscan-pivot.md                  ← unmask the lure cluster
│
└── 📁 IOCs/                              ← historical anchors only — see disclaimer
    ├── domains.txt                       (119 lure / hosting domains)
    ├── c2.txt                            (16 C2 domains)
    ├── ips.txt                           (14 IP addresses)
    ├── hashes.txt                        (131 SHA256, 32 SHA1, 1 MD5)
    └── code-signing.txt                  (35 shell-company publishers)
```

---

## 🚀 How to use

| Step | Action |
| :---: | :--- |
| **1️⃣** | Read the threat landscape and MITRE chain to understand the *why*. |
| **2️⃣** | Pick hunts relevant to your stack — `MDE = KQL`, `CrowdStrike = CQL`. |
| **3️⃣** | Run as hunts first, baseline FPs, then promote to scheduled detections. |
| **4️⃣** | **Pair detections across phases** — single signals will drown your analysts. |
| **5️⃣** | Pin detections to the durable invariants, not the IOCs. |

---

## 🔒 The durable invariants

> These do **not** rotate.

- 🔑 **Credential access** — non-browser process opens browser credential SQLite + DPAPI call
- 📋 **ClickFix** — RunMRU registry write with long encoded LOLBin command
- 🧬 **DLL sideloading** — trusted EXE loads non-trusted DLL from user-writable directory
- ⏱️ **Sandbox evasion** — scheduled task with >24h delayed first run from non-system parent
- 🌐 **C2 fronting** — TLS to newly-registered Cloudflare-fronted domain from non-browser PID
- 🔐 **DCSync** — non-machine, non-service account invokes DS-Replication-Get-Changes(-All)

---

## 📊 IOCs — historical anchors

> ⚠️ **These rotate constantly.** Block them, but invest your detection-engineering hours in the [durable invariants](#-the-durable-invariants) above.

| Type | Count | File | Notes |
| :--- | :---: | :--- | :--- |
| Domains (lure / hosting) | 119 | [`IOCs/domains.txt`](IOCs/domains.txt) | urlscan.io pivot — `main.<hex>.js` + `/report` fingerprint |
| C2 domains | 16 | [`IOCs/c2.txt`](IOCs/c2.txt) | Cloudflare-fronted, newly-registered |
| IP addresses | 14 | [`IOCs/ips.txt`](IOCs/ips.txt) | Cloudflare-fronted ranges — high collateral if blocked |
| File hashes (SHA256/SHA1/MD5) | 164 | [`IOCs/hashes.txt`](IOCs/hashes.txt) | PDF Editor, ManualFinder, EpiBrowser, Vidar `msedge_elf.dll` |
| Code-signing publishers | 35 | [`IOCs/code-signing.txt`](IOCs/code-signing.txt) | shell-company EV certs (Malaysia, Panama, UK, HK) |

**Source attribution:** [Truesec (2025-08-27)](https://www.truesec.com/hub/blog/tamperedchef-the-bad-pdf-editor) · [Expel](https://expel.com/blog/the-history-of-appsuite-the-certs-of-the-baoloader-developer/) · [Heimdal](https://heimdalsecurity.com/blog/heimdal-tamperedchef-investigation/) · [WithSecure](https://labs.withsecure.com/publications/tamperedchef) · [LindenSec IoC repo](https://github.com/LindenSec/IoC/tree/main/PDFEditorManualFinder)

---

## ⚠️ Disclaimer

> Hunt queries are **starting points**, not drop-in detections.
> Tune to your environment before promoting to scheduled rules.
> IOCs are **historical anchors** — the actor cluster rotates infrastructure constantly.

---

| 📝 Blog | [tec-bite.ch](https://www.tec-bite.ch/) |

---

<div align="center">

### 🎯 *Hunt behaviour, not hashes.*

</div>