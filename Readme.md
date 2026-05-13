# 🛡️ Safe-Surf v3.5: Advanced Phishing Intelligence & AI Security Agent

Safe-Surf is a next-generation Cybersecurity Intelligence platform designed to detect sophisticated phishing attacks, identity theft, and malicious network activity. It combines **Machine Learning Pipelines**, **Heuristic Research Scanners**, and a **Self-Healing AI Reasoning Agent** (powered by Gemini 2.0/2.5) to provide world-class threat analysis.

---

## 🔥 NEW: Safe-Surf v3.5 Hardened Core (Detailed Breakdown)
The v3.5 update represents a major leap in detection precision and adversarial resilience. This hardened core is built on three scientific pillars:

### 🤖 1. ReAct Reasoning Agent (Live Forensics)
Unlike static classifiers, the Safe-Surf Agent uses a **Reasoning + Action (ReAct)** loop to perform multi-stage security audits:
- **Phase 1: Metadata Audit**: Real-time extraction of domain age (WHOIS) and SSL trust scores.
- **Phase 2: Dynamic Sandbox**: Spawns a headless Playwright instance to trace **Redirection Chains** and detect **Cloaking Evasion**.
- **Phase 3: AI Synthesis**: Combines technical telemetry into a human-readable security briefing.

### 📊 2. Optimized Ensemble Logic (The 70/30 Split)
Through systematic experimentation, we have implemented a mathematically optimal weighted voting system:
- **ML confidence (70%)**: Focuses on structural patterns and historical threat signatures.
- **Heuristic Score (30%)**: Provides "Ground Truth" via forensic markers (Entropy, TLD risk, Path keywords).
- **The Result**: Significant reduction in False Positives while maintaining high recall for zero-day threats.

### 🛡️ 3. Adversarial Resilience Matrix
Safe-Surf v3.5 is specifically hardened against modern evasion techniques:
- **Character Substitution**: Catches domains using visually similar Unicode characters.
- **Subdomain Abuse**: Identifies phishing forms hosted on reputable cloud platforms (AWS/Azure/Google).
- **TLD Swapping**: Monitors high-risk top-level domains often used in ephemeral attack campaigns.

---

## 🚀 Key Features

### 🛡️ 1. Smart Intelligence Agent (v3.2/v3.5)
A deep-reasoning AI agent that translates complex security data into human-readable briefings.
- **Self-Healing Model Discovery**: Automatically identifies the best available model (Gemini 2.0/2.5) for your specific API permissions.
- **Native Gemini Integration**: Built-in support for **Google Gemini 2.0 Flash** via direct REST API for high-speed analysis.
- **Zero-Day Reasoning**: Analyzes "why" a site looks dangerous, even if it's never been seen before.

### 🛡️ 2. Multi-Layer Defense Engine
- **Layer 1: Machine Learning**: Random Forest classifier trained on 11,000+ phishing samples.
- **Layer 2: Heuristics**: Detects **Homograph (Punycode)** attacks, High-Risk TLDs, and Typosquatting.
- **Layer 3: Dynamic Analysis Suite**: 
  - **Cross-Origin Auditor**: Detects forms stealing data to external servers.
  - **Open Redirect Scanner**: Identifies hidden malicious tunnels.
  - **Subdomain Takeover**: Monitors DNS for abandoned cloud resources.
  - **Behavioral Script Auditor**: Flags suspicious third-party JavaScript.
  - **Visual Quishing Detector**: Detects zero-text, visual-only payloads (QR codes/Image abuse).
  - **Evasive Routing Tracer**: De-obfuscates multi-hop ephemeral redirect chains.
  - **Trusted Host Scanner**: Catches compromised reputable domains hosting covert phishing forms.

### 🌐 3. Safe-Surf Browser Extension
A professional Chrome/Edge extension that brings real-time threat intelligence directly to your browsing session.
- **Instant Tab Scanning**: One-click analysis of any active website.
- **Decoupled Architecture**: Communicates with the FastAPI backend for light-speed performance.
- **Live Risk Badge**: Visual status indicators (Secure/Suspicious/Danger).

### 🌌 4. Premium Cyber-Dashboard
- **Dark Mode UI**: Professional "Glassmorphism" aesthetic.
- **Real-Time Gauges**: Neon threat probability indicators.
- **Confidence Scoring**: Dynamic assessment of scan reliability.

---

## 🛠️ Tech Stack
- **AI Intelligence**: Google Gemini 2.0/2.5 (Native API), Llama 3.1 8B (Ollama Fallback)
- **Backend Architecture**: Python 3.11+, FastAPI, Streamlit
- **Database**: MongoDB Atlas (Cloud)
- **ML Engine**: Scikit-learn, Random Forest, Logistic Regression
- **Network Scanning**: Playwright, BeautifulSoup4, WHOIS, Dnspython, Requests
- **Explainability**: SHAP (Summary/Waterfall Plots), MLflow, DagsHub

---

## 🚦 Quick Start

### 1. Prerequisites
- Python 3.9+
- MongoDB Connection String
- Gemini API Key (Optional but recommended)

### 2. Local Development
```bash
# Activate Environment
.nsvenv\Scripts\activate

# Install Dependencies
pip install -r requirements.txt

# Launch Safe-Surf Hub
streamlit run streamlit_app.py
```

### 3. Local Research & Simulation (Mock Phishing)
To test the advanced zero-day threat detection (Quishing, Data Harvest, etc.), you can run the built-in mock server before launching the Safe-Surf Hub.
```bash
# In a new terminal, activate environment
.nsvenv\Scripts\activate

# Run the mock phishing server
python mock_phishing_server.py
```

### 4. Browser Extension Setup
1. Ensure the **FastAPI Backend** is running (`python app.py`).
2. Open Chrome/Edge and navigate to `chrome://extensions`.
3. Enable **Developer Mode** (top-right toggle).
4. Click **Load Unpacked**.
5. Select the `SafeSurf_Extension` folder from this project directory.

---

## 📂 Project Structure
- `networksecurity/` (Core Logic)
  - `component/` (ML Pipeline & Data Ingestion)
  - `utils/` (AI Agent, ReAct Tools, Feature Extraction)
- `scripts/` (Validation Matrix, Ablation, Adversarial Testing)
- `templates/` (Premium Cyber-Grok UI)
- `Network_data/` (Original Datasets & Whitelists)
- `SafeSurf_Extension/` (Chrome/Edge Extension Files)
- `app.py` (FastAPI Server & Extension API)

---
**Safe-Surf | Advanced Cyber-Intelligence 2026** 🛡️✨
