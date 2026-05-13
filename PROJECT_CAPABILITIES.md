# Safe-Surf v3.2.7 | Technical Capabilities & Constraints

## 🛡️ DETECTABLE THREATS (The Strengths)
- **Known Malicious Entities**: Instant identification via MongoDB/Registry matches.
- **Typosquatting & Brand Spoofing**: Detects look-alike domains (e.g., `faceb00k.com`).
- **Homograph (Punycode) Attacks**: Flags spoofed characters (e.g., `xn--`).
- **Zero-Day Gibberish (Entropy Shield)**: Identifies computer-generated DGA domains (e.g., `aabbajaabadaaba.org`).
- **Heuristic Indicators**: Flags newly registered domains, suspicious TLDs, and path keywords.
- **Infrastructure Vulnerabilities**: Detects Open Redirects, Subdomain Takeovers, and missing `X-Frame-Options`.
- **Compromised Trusted Domains**: Analyzes reputable sites (e.g., `medium.com`, `docs.google.com`) for unexpected password fields or high-risk "session verification" keywords.
- **Visual-Only Payloads**: Detects QR code/image scams by analyzing volume-to-content ratios (flagging `<img/>` heavy domains with <100 readable characters).
- **Ephemeral & Evasive Routing**: Follows and flags multi-hop HTTP redirect chains used to conceal final destinations.

### 💠 v3.5 ADVANCED CAPABILITIES (New Additions)
- **🤖 ReAct Reasoning Agent**: Live forensic loop that performs Action/Observation steps for deep zero-day analysis.
- **🇮🇳 Hindi/Hinglish Phishing Guard**: Specialized logic for detecting Indian brand impersonation using Devanagari and localized keyword telemetry.
- **🚀 Dynamic Playwright Sandbox**: Automated headless browser execution to identify **Cloaking** and **Redirection Loops** in real-time.
- **⚖️ 70/30 Optimized Ensemble**: A mathematically validated weighted voting architecture that integrates ML confidence with ground-truth heuristics.

### 🛡️ ADVERSARIAL RESILIENCE (Hardened Defense)
The v3.5 core has been specifically stress-tested and hardened against the following evasion vectors:
- **Character Substitution (Unicode Spoofing)**: Detects domains using visually identical characters from different alphabets (e.g., 'а' instead of 'a').
- **Subdomain Abuse (Cloud Hijacking)**: Identifies malicious forms hosted on reputable infrastructure (AWS, Azure, Google Cloud) by analyzing the "Depth of Impersonation."
- **TLD Swapping & Ephemeral Domains**: Real-time identification of high-risk top-level domains used in short-burst phishing campaigns.
- **Hyphen & Syntax Obfuscation**: Flags complex hyphenated strings and multi-layered subdomains designed to bypass simple regex filters.

### 🔍 LIVE FORENSIC TELEMETRY
- **Real-Time WHOIS Audit**: Direct connection to global registrars to verify domain age (detecting "Just-In-Time" phishing infrastructure).
- **SSL Trust Scoring**: Deep inspection of certificate authority (CA) reputation and transparency logs.
- **Dynamic Behavioral Analysis**: Headless execution tracking to monitor script behavior before a user even clicks.

## ❌ NON-DETECTABLE THREATS (The Hard Gaps)
- **Closed Ecosystem Phishing (WebViews)**: Attacks injected natively inside private messaging apps (e.g., WhatsApp, Telegram) cannot be intercepted without an installed mobile proxy or OS-level MITM certificate.
- **Dynamic Captcha Walls**: Sites shielded by CAPTCHAs (like Cloudflare Turnstile or reCAPTCHA) block the web scraper before it can analyze the underlying phishing code. 
- **Deep Code Obfuscation (Stateless Limits)**: Heavily obfuscated dynamic JavaScript payloads (like delayed malware execution) cannot be detected without a full dynamic execution sandbox (VM emulation).

## 🚀 CORE FEATURES (The Pros)
- **Neural Security Intelligence**: Reasoning-based reports powered by Gemini 2.0/2.5.
- **Self-Healing Model Discovery**: Dynamic API handshake to ensure maximum AI uptime.
- **Deep Heuristic Page Scraper**: Parses DOM structures in real-time for zero-day threat analysis.
- **High-Performance Dashboard**: Dual-layer architecture (FastAPI + Streamlit).

## ⚠️ SYSTEM LIMITATIONS (The Cons)
- **Analysis Latency**: Deep neural analysis and dynamic DOM fetching introduces a heavier 5-10 second overhead on searches.
- **Entropy False Positives**: May flag unusually named but legitimate startups.
- **Dependency on LLM API**: Requires an active Gemini key to provide natural language Context Reports.

---
*Updated for v3.2.7 Strategic Review.* 🛡️✨
