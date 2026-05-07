<div align="center">

# 🎯 Threat Hunting — AVANTech Day 2026

**Hunt pack and detection engineering reference for the InfoStealer ecosystem and the fake-PDF-tool delivery cluster.**

`BaoLoader` · `TamperedChef` · `AppSuite-PDF` · `ManualFinder`

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![CrowdStrike](https://img.shields.io/badge/CrowdStrike-LogScale-FA0F00)](https://www.crowdstrike.com/)
[![Microsoft Defender](https://img.shields.io/badge/Microsoft-Defender_XDR-0078D4)](https://learn.microsoft.com/en-us/defender-xdr/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

---

## 💡 Why this exists

> **Your data left. You just haven't noticed yet.**

Signatures and IOCs rotate in days. Behaviour doesn't. This repo focuses on the **durable detection invariants** that survive payload, family, and certificate changes.

---

## 🔍 Quick access — jump to a query

| Phase | Hunt | Platform |
| :------------------: | :--- | :---: |
| 🎯 Execution         | [ClickFix — RunMRU paste](CrowdStrike/ClickFix.md) | CQL |
| 🔁 Persistence       | [Run/RunOnce key writes](CrowdStrike/RunKey.md) | CQL |
| 🥷 Defense Evasion | [DLL sideloading pattern](CrowdStrike/DLLsideloading.md) | CQL |
| 🥷 Defense Evasion | [Malicious code-signing certs](MicrosoftDefenderForEndpoint/MaliciousCodeSigningCert.md) | KQL |
| 🔑 Credential Access | [The Browser-Credential Chokepoint](CrowdStrike/CredentialAccess.md) | CQL |

---

## 📂 What's inside

```text
AVANTechDay-2026-ThreatHunting/
│
├── 📄 README.md                          ← you are here
├── 📄 IOCs.csv                           ← historical anchors (see disclaimer)
│
├── 📁 CrowdStrike/                       ← CQL queries (LogScale)
│   ├── ClickFix.md
│   ├── CredentialAccess.md
│   ├── DLLsideloading.md
│   └── RunKey.md
│
└── 📁 MicrosoftDefenderForEndpoint/      ← KQL queries (Defender XDR)
    └── MaliciousCodeSigningCert.md
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

---

## 📊 IOCs

Historical anchors only. See [`IOCs.csv`](IOCs.csv) for the full list with timestamps and source attribution.

| Type | Count | Notes |
| :--- | :---: | :--- |
| Domains (PDF-tool cluster) | TBD | urlscan.io pivot — `main.<hex>.js` + `/report` fingerprint |
| C2 domains | TBD | Cloudflare-fronted, newly-registered |
| File hashes (DLL sideload) | TBD | `msedge_elf.dll`, `CoreMessaging.dll` variants |
| Code-signing publishers | TBD | shell-company EV certs (LEGION LLC, etc.) |

> ⚠️ **These rotate constantly.** Block them, but invest your detection-engineering hours in the [durable invariants](#-the-durable-invariants) above.

---

## ⚠️ Disclaimer

> Hunt queries are **starting points**, not drop-in detections.
> Tune to your environment before promoting to scheduled rules.
> IOCs are **historical anchors** — the actor cluster rotates infrastructure constantly.

---

## 🤝 Stay in touch

Got a hypothesis from your backlog? **Bring it to the AVANTEC apéro** — we'll build a Sigma rule together before you leave. No sales call, no follow-up pitch. Just hands-on.

| | |
| :--- | :--- |
| 📧 Email | [salucci@avantec.ch](mailto:salucci@avantec.ch) |
| 💼 LinkedIn | [Alessandro Salucci](https://www.linkedin.com/in/alessandro-salucci/) |
| 📝 Blog | [tec-bite.ch](https://www.tec-bite.ch/) |

---

<div align="center">

### 🎯 *Hunt behaviour, not hashes.*

</div>