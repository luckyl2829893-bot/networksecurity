# Advanced Research: Detecting Phishing on Compromised Legitimate Websites

This document explores the sophisticated "In-Site Phishing" attacks where legitimate, trusted domains are used to host malicious content. This is a critical research area because these attacks bypass basic "URL Blacklisting" and "Domain Reputation" systems.

---

## 1. Types of In-Site Phishing Attacks

### A. Iframe Injection & Overlays
- **How it works**: An attacker finds a vulnerability (like XSS) in a legitimate site and injects an `<iframe>`. This iframe loads a pixel-perfect login form from an external malicious server, but it appears to be part of the trusted site.
- **The Popup Variant**: A "Session Expired" or "Security Alert" popup is triggered via JavaScript, asking the user to re-enter their credentials.

### B. Subdomain Takeover
- **How it works**: Large companies often have subdomains (e.g., `dev.google.com`) pointing to cloud services (like AWS/Azure). If the cloud service is deleted but the DNS record remains, an attacker can "claim" that service and host a phishing page on the legitimate company's subdomain.

### C. Open Redirects
- **How it works**: A legitimate site has a redirector like `trusted.com/redirect?url=external.com`. Attackers use this to send users to a phishing page, knowing the user will only see `trusted.com` in their email preview or mobile browser bar.

### D. Clickjacking (UI Redressing)
- **How it works**: The attacker loads a legitimate site in a transparent iframe and overlays their own invisible buttons. When the user thinks they are clicking "Download" on a safe site, they are actually clicking "Authorize Transaction" on the hidden malicious layer.

---

## 2. Homograph (Punycode) Attacks: The "Twin Character" Danger

You mentioned that a character 'a' in another language looks identical to an English 'a'. This is called a **Homograph Attack**.

### What is it?
Attackers use characters from different alphabets (like Cyrillic, Greek, or Latin) that look identical to "naked eyes."
- **English 'a'** (Latin): `a`
- **Cyrillic 'а'**: `а`
- Resulting URL: `аррӏе.com` (using Cyrillic 'a' and 'i') looks exactly like `apple.com`.

### How to Catch it? (The "ML vs. DL" Approach)

1. **Punycode Conversion (Rule-Based)**:
   - Browsers convert these URLs into "Punycode" (starting with `xn--`).
   - *Example*: `аррӏе.com` → `xn--80ak6aa92e.com`.
   - **How to catch**: Any URL that contains `xn--` is instantly suspicious and should be flagged for manual review or higher risk.

2. **Visual Feature Extraction (Deep Learning)**:
   - This is where you need **DL**.
   - **Method**: Render the suspect domain (e.g., `apple.com`) and a "Known Safe" domain (the real `apple.com`) into images.
   - **Model**: Use a **Siamese Network** or a **CNN (Convolutional Neural Network)** to compare the visual features of the text.
   - **Research Value**: Even if the characters are different in code, if the DL model says the images are 99% identical, you have found a Homograph attack.

3. **OCR (Optical Character Recognition)**:
   - Convert the rendered image of the URL back into text. If the OCR text is "apple.com" but the actual encoded URL is `xn--80ak6aa92e.com`, the mismatch confirms an attack.

---

## 3. How to Catch "In-Site" Phishing (Research Variables)

Since the **Domain is correct**, your tool needs to look *inside* the page content:

1. **DOM Structure Inconsistency**:
   - Compare the current DOM (Document Object Model) with a "Baseline" version of the legitimate site. If a new `<form>` or `<iframe>` appears that doesn't belong to the site's original structure, it's a red flag.
   
2. **Third-Party Script Analysis**:
   - Monitor where data is being sent. If a form on `bank.com` submits data to `evil-server.xyz`, it is a 100% confirmed phishing attack.
   
3. **Behavioral Heuristics (Dynamic Analysis)**:
   - Use a **Headless Browser** to detect if a popup appears immediately upon loading or if specific mouse movements trigger hidden elements.

4. **Visual Similarity (CV-based)**:
   - Use Computer Vision (SIFT/ORB algorithms) to check if a specific "Login Box" on a page looks identical to a known brand's login box, but is hosted on a different (even if legitimate) site.

---

## 4. How to Simulate for Research (Experimental Setup)

To demonstrate this in your paper, you can create a "Controlled Compromised Site":

### Requirements & Tech Stack:
- **Environment**: A local web server (using Flask or Node.js) hosting a fake "Safe Website".
- **Attack Script**: A JavaScript snippet that injects a phishing modal (popup) into the page.
- **Analysis Tool (Your Project)**:
    - **Playwright/Puppeteer**: To "render" the site and see the hidden popups.
    - **BeautifulSoup/LXML**: To parse the HTML and find injected iframes.
    - **Network Interceptor**: To catch where the data is being sent.

---

## 5. Master Requirements & Tech Stack

To build a professional, research-grade version of this project, you need the following:

### A. Skill Pillars:
| Skill / Tech | Role in Project | Why it's needed? |
| :--- | :--- | :--- |
| **SQL (Relational DB)** | Transaction Logging & Auditing | For immutable history. MongoDB is for speed; SQL is for "Gold Standard" reporting. |
| **NLP (Natural Language)** | Social Engineering Detection | To analyze the *intent* of email/SMS content (Scam vs. Ham). |
| **Deep Learning (DL)** | Visual & Behavioral Analysis | For detecting Homograph attacks and Graph-based fraud detection. |
| **LLMs (GenAI)** | Explainable AI (XAI) | To translate raw technical scores into human-readable "briefings." |
| **Web Scraping** | Real-time Data Collection | To "visit" a site and scan its content (popups, forms). |

### B. Project Evolution Modules:
1.  **Dynamic Scanning Layer**: Instead of just checking URLs, the system must "visit" the site using a headless browser.
2.  **Cross-Origin Request Monitor**: A module that checks if forms on a page are sending data to a different domain than the page itself.
3.  **UI Comparison Engine**: A database of "Official Login Box" images to compare against any input boxes found on scanned pages.
4.  **Transaction Context**: A "Behavioral Profile" that flags if a "Safe" site suddenly starts asking for sensitive data it never asked for before.

---

## 6. Security Research Topics for your Paper
- *"A Deep Learning approach to Visual Spoofing: Detecting Homograph Punycode Attacks in Financial Portals."*
- *"Beyond Domain Reputation: Detection of Injection-based Phishing on Compromised High-Trust Domains."*
- *"A Behavioral Approach to Detecting Clickjacking in Real-time Web Traffic."*
- *"Automated DOM Auditing: Identifying Malicious Iframe Injections in Financial Portals."*
