# 🛡️ DIS — Device Intelligence System
### IrsanAI Security Stack v1.0

> Autonomous cross-platform security — Anti-Surveillance · Malware Detection · Zero-Day · LLM-Native · DSGVO-compliant

[![IrsanAI](https://img.shields.io/badge/IrsanAI-Security%20Stack-ff2d55?style=flat-square)](https://github.com/IrsanAI)
[![License](https://img.shields.io/badge/License-MIT-30d158?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Windows%20%7C%20Linux%20%7C%20iOS-60b4ff?style=flat-square)]()

---

## ⚡ Quick Start

### Android / Termux
```bash
pkg install git nodejs -y
git clone https://github.com/IrsanAI/IrsanAI-dis-core
cd IrsanAI-dis-core
bash install.sh
node server.js
```
Then open in browser: **http://localhost:3001**

### Linux / macOS
```bash
git clone https://github.com/IrsanAI/IrsanAI-dis-core
cd IrsanAI-dis-core
bash install.sh
node server.js
```

### Windows (PowerShell)
```powershell
git clone https://github.com/IrsanAI/IrsanAI-dis-core
cd IrsanAI-dis-core
npm install
npm run build
node server.js
```
Then open: **http://localhost:3001**

---

## 🧠 Architecture

```
┌─────────────────────────────────────────────────────────┐
│  LAYER 4 — INTELLIGENCE                                 │
│  Claude AI · CVE Matching · Zero-Day Intel              │
├─────────────────────────────────────────────────────────┤
│  LAYER 3 — CONTROL CENTER                               │
│  React Dashboard · Auto-OS-Detect · WebSocket           │
├─────────────────────────────────────────────────────────┤
│  LAYER 2 — SCOUT AGENTS                                 │
│  Termux · PowerShell · Bash · ADB                       │
├─────────────────────────────────────────────────────────┤
│  LAYER 1 — SENSORS                                      │
│  Android · iPhone · Windows · Linux · Router            │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Threat Coverage

| Category | Threats |
|---|---|
| 🕵️ Anti-Surveillance | SIM-Swap · IMSI-Catcher · Stalkerware · Phone Clone · MITM |
| 🦠 Malware | APK-RAT · Zero-Day · Ransomware |
| 🔧 OS Security | Patch Status · Knox · Boot Integrity |
| 🪟 Windows | RAT/Backdoor · Ransomware · Spyware |
| 🐧 Linux | Rootkit · Cryptominer |

---

## 📁 Repo Structure

```
IrsanAI-dis-core/
├── package.json          ← Dependencies
├── vite.config.js        ← React build config
├── index.html            ← Entry point
├── server.js             ← Auto-OS-Detector + WebSocket
├── install.sh            ← One-line installer
├── src/
│   ├── main.jsx          ← React entry
│   └── App.jsx           ← Full dashboard
└── scripts/
    ├── android/          ← Termux Scout Agents
    ├── windows/          ← PowerShell Agents
    └── linux/            ← Bash Agents
```

---

## 🔒 DSGVO / Privacy

All scout scripts collect **technical metadata only**:
- ✅ App package names, build properties, security settings
- ✅ Hardware specs, network config (anonymized)
- ❌ No contacts, messages, photos, location, account data

---

## 🚀 IrsanAI Stack Roadmap

- [ ] `dis-agent-ios` — iOS Shortcuts Agent
- [ ] `dis-api` — REST API for multi-device orchestration
- [ ] `dis-monitor` — Continuous background monitoring
- [ ] Auto-patch engine — automated remediation
- [ ] Threat feed — live CVE matching via web search

---

**[github.com/IrsanAI](https://github.com/IrsanAI)** · MIT License
