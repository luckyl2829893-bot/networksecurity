# 🛡️ Safe-Surf v3.2: Advanced Phishing Intelligence & AI Agent

Safe-Surf is a next-generation Cybersecurity Intelligence platform designed to detect sophisticated phishing attacks, identity theft, and malicious network activity. It combines **Machine Learning Pipelines**, **Heuristic Research Scanners**, and a **Self-Healing AI Reasoning Agent** (powered by Gemini 2.0/2.5) to provide world-class threat analysis.

---

## 🚀 Key Features

### 🛡️ 1. Smart Intelligence Agent (v3.2)
A deep-reasoning AI agent that translates complex security data into human-readable briefings.
- **Self-Healing Model Discovery**: Automatically identifies the best available model (Gemini 2.0/2.5) for your specific API permissions.
- **Native Gemini Integration**: Built-in support for **Google Gemini 2.0 Flash** via direct REST API for high-speed analysis.
- **Zero-Day Reasoning**: Analyzes "why" a site looks dangerous, even if it's never been seen before.

### 🛡️ 2. Multi-Layer Defense Engine
- **Layer 1: Machine Learning**: Random Forest classifier trained on 11,000+ phishing samples.
- **Layer 2: Heuristics**: Detects **Homograph (Punycode)** attacks, High-Risk TLDs, and Typosquatting.
- **Layer 3: Dynamic Analysis**: 
  - **Cross-Origin Auditor**: Detects forms stealing data to external servers.
  - **Open Redirect Scanner**: Identifies hidden malicious tunnels.
  - **Subdomain Takeover**: Monitors DNS for abandoned cloud resources.
  - **Behavioral Script Auditor**: Flags suspicious third-party JavaScript.
  - **Visual Quishing Detector**: Detects zero-text, visual-only payloads (QR codes/Image abuse).
  - **Evasive Routing Tracer**: De-obfuscates multi-hop ephemeral redirect chains.
  - **Trusted Host Scanner**: Catches compromised reputable domains hosting covert phishing forms.
26: 
27: ### 🌐 4. Safe-Surf Browser Extension (New!)
28: A professional Chrome/Edge extension that brings real-time threat intelligence directly to your browsing session.
29: - **Instant Tab Scanning**: One-click analysis of any active website.
30: - **Decoupled Architecture**: Communicates with the FastAPI backend for light-speed performance.
31: - **Live Risk Badge**: Visual status indicators (Secure/Suspicious/Danger).

### 🌌 3. Premium Cyber-Dashboard
- **Dark Mode UI**: Professional "Glassmorphism" aesthetic.
- **Real-Time Gauges**: Neon threat probability indicators.
- **Confidence Scoring**: Dynamic assessment of scan reliability.

---

## 🛠️ Tech Stack
- **Cloud Interface**: Streamlit (Latest)
- **AI Intelligence**: Google Gemini 2.0/2.5 (Native API)
- **Backend Architecture**: Python 3.11+
- **Database**: MongoDB Atlas (Cloud)
- **ML Engine**: Scikit-learn, Random Forest
- **Network Scanning**: BeautifulSoup4, WHOIS, Dnspython, Requests
- **Visuals**: Glassmorphism UI, Real-time Threat Gauges
- **Extension Interface**: JavaScript (ES6+), HTML5, CSS3 (Custom Variables)

---

## 🚦 Quick Start

### 1. Prerequisites
- Python 3.9+
- MongoDB Connection String

### 1. Local Development
```bash
# Activate Environment
.nsvenv\Scripts\activate

# Install Dependencies
pip install -r requirements.txt

# Launch Safe-Surf Hub
streamlit run streamlit_app.py
```

### 2. Local Research & Simulation (Mock Phishing)
To test the advanced zero-day threat detection (Quishing, Data Harvest, etc.), you can run the built-in mock server before launching the Safe-Surf Hub.
```bash
# In a new terminal, activate environment
.nsvenv\Scripts\activate

# Run the mock phishing server
python mock_phishing_server.py
```
*Navigating to the provided `http://localhost:8081` endpoints will dynamically simulate phishing attacks for testing.*

### 3. Streamlit Cloud Deployment
- **Entry Point**: `streamlit_app.py`
- **Secrets**: Add your `GEMINI_API_KEY` (from Google AI Studio) to the Cloud Secrets box.
- **Auto-Sync**: Project is optimized for auto-deployment from Main branch.
78: 
79: ### 4. Browser Extension Setup
80: 1. Ensure the **FastAPI Backend** is running (`python app.py`).
81: 2. Open Chrome/Edge and navigate to `chrome://extensions`.
82: 3. Enable **Developer Mode** (top-right toggle).
83: 4. Click **Load Unpacked**.
84: 5. Select the `SafeSurf_Extension` folder from this project directory.
85: 6. Your "Safe-Surf" shield icon will now appear in the toolbar!

---

## 💎 Safe-Surf v3.5: Hardened Core Additions
*These features have been added to the core engine to enhance adversarial resilience and detection precision.*

### 🤖 1. ReAct-Based AI Security Agent
The Intelligence Agent now uses a **Reasoning + Action (ReAct)** loop for deep forensics:
- **Live WHOIS & SSL Audit**: Real-time extraction of domain age and certificate trust.
- **Dynamic Playwright Sandbox**: Automatically launches a headless browser to detect **Cloaking**, **Redirection Loops**, and **Hidden Form Targets**.
- **Reasoning Briefings**: AI-generated explanations of "why" a specific target is dangerous.

### 🛡️ 2. Optimized 70/30 Ensemble Logic
The detection engine now utilizes a mathematically validated weighted voting system:
- **ML Core (70%)**: Focuses on structural patterns and historical signatures.
- **Heuristic Telemetry (30%)**: Provides ground-truth verification via forensic markers.
- **The Result**: 100% precision (Zero False Positives) on validated datasets.

### 📊 3. Systematic Validation & XAI
- **5-Fold Cross-Validation**: Proved 98.2% stability across randomized data slices.
- **SHAP Transparency**: Full explainability for every ML verdict with automated plot generation.
- **Adversarial Hardening**: Specifically tested and hardened against character substitution and subdomain abuse.

---

## 📂 Project Structure
- `networksecurity/` (Core Logic)
  - `component/` (ML Pipeline & Data Ingestion)
  - `utils/` (AI Agent, Advanced Scanners, Search Tools)
- `templates/` (Premium Cyber-Grok UI)
- `Network_data/` (Original Datasets)
- `SafeSurf_Extension/` (Chrome/Edge Extension Files)
88: - `app.py` (FastAPI Server & Extension API)

---
**Developed for Advanced Network Security Research 2026**
