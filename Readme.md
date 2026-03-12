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

### 2. Streamlit Cloud Deployment
- **Entry Point**: `streamlit_app.py`
- **Secrets**: Add your `GEMINI_API_KEY` (from Google AI Studio) to the Cloud Secrets box.
- **Auto-Sync**: Project is optimized for auto-deployment from Main branch.

---

## 📂 Project Structure
- `networksecurity/` (Core Logic)
  - `component/` (ML Pipeline & Data Ingestion)
  - `utils/` (AI Agent, Advanced Scanners, Search Tools)
- `templates/` (Premium Cyber-Grok UI)
- `Network_data/` (Original Datasets)
- `app.py` (FastAPI Server)

---
**Developed for Advanced Network Security Research 2026**
