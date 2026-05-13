# 🛡️ Safe-Surf v3.5: Next-Gen Phishing Intelligence & AI Security Agent

Safe-Surf is a powerful, production-ready Cybersecurity Intelligence platform designed to combat modern phishing, identity theft, and malicious network activity. It combines **Deep Machine Learning**, **Real-Time Heuristics**, and a **ReAct-based AI Reasoning Agent** to provide comprehensive threat protection.

---

## 💎 Key Product Pillars

### 🤖 1. Smart ReAct Intelligence Agent
The crown jewel of Safe-Surf. A deep-reasoning AI agent that performs live security audits:
- **Live WHOIS Analysis**: Real-time domain registration integrity checks.
- **SSL Chain Verification**: Validates certificate transparency and trust levels.
- **Dynamic Content Sandbox**: Launches a browser sandbox to detect **Cloaking**, **Redirection Loops**, and **Hidden Data Harvesting**.

### 🛡️ 2. Multi-Layer Defense Core
Safe-Surf utilizes a resilient 4-tier engine to ensure no threat goes undetected:
1.  **Neural Core**: High-speed ML structural analysis (98%+ Accuracy).
2.  **Heuristic Telemetry**: 30+ forensic markers for zero-day detection.
3.  **Ensemble Intelligence**: Optimized **70/30 Hybrid Voting** system for zero false positives.
4.  **Live Briefing**: AI-generated reports explaining exactly "why" a target is dangerous.

### 🌐 3. Safe-Surf Browser Extension
A professional Chrome/Edge extension that brings real-time threat intelligence directly to your browsing session.
- **Instant Tab Scanning**: One-click analysis of any active website.
- **Live Risk Badge**: Visual status indicators (Secure/Suspicious/Danger).

---

## 🛠️ Technical Capabilities
- **Zero-Day Detection**: Identifies malicious sites based on behavioral patterns, not just blacklists.
- **Hindi Phishing Guard**: Specialized detection for Hinglish and Indian brand impersonation.
- **Quishing Defense**: Detects visual-only payloads and QR code scams.
- **Evasive Routing Tracker**: De-obfuscates multi-hop redirect chains.

For a full technical audit of strengths and constraints, see [PROJECT_CAPABILITIES.md](./PROJECT_CAPABILITIES.md).

---

## 🚦 Quick Start

### 1. Local Deployment
```bash
# Activate Environment
.nsvenv\Scripts\activate

# Install Core Dependencies
pip install -r requirements.txt

# Launch Safe-Surf Hub
streamlit run streamlit_app.py
```

### 2. Browser Extension Setup
1. Ensure the **Safe-Surf API** is running (`python app.py`).
2. Open Chrome/Edge and navigate to `chrome://extensions`.
3. Enable **Developer Mode**.
4. Click **Load Unpacked** and select the `SafeSurf_Extension` folder.

### 3. Simulation & Stress Testing
Run the built-in mock phishing server to test the system's resilience:
```bash
python mock_phishing_server.py
```

---

## 📂 Project Architecture
- `networksecurity/`: Core security engine and AI Agent logic.
- `SafeSurf_Extension/`: Frontend browser extension source code.
- `Network_data/`: Master phishing and whitelist intelligence datasets.
- `scripts/`: Advanced verification and optimization tools.

---
**Safe-Surf | Advanced Cyber-Intelligence 2026** 🛡️✨
