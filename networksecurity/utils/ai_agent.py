import os
import requests
import json
import whois
import ssl
import socket
from datetime import datetime
from networksecurity.utils.dynamic_scanner import run_dynamic_scan

class PhishingAIAgent:
    """
    A resilient 4-tier AI Security Agent for Safe-Surf v4.0.
    Fallback Chain: Tier 1 (Gemini) -> Tier 2 (Llama 3.1) -> Tier 3 (Phi-3) -> Tier 4 (Rules)
    """
    
    def __init__(self, personality="CyberAnalyst"):
        self.personality = personality
        self.gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.ollama_url = "http://localhost:11434/api/generate"

    def _check_domain_age(self, domain):
        """Live WHOIS tool."""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                days_old = (datetime.now() - creation_date).days
                return f"Domain is {days_old} days old (Created: {creation_date})."
            return "Domain age unknown (WHOIS privacy enabled or no record)."
        except:
            return "WHOIS lookup failed."

    def _check_ssl_certificate(self, domain):
        """Live SSL tool."""
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                return f"SSL Verified. Issued to: {subject.get('commonName')} by {issuer.get('commonName')}."
        except Exception as e:
            return f"SSL Verification Failed: {str(e)}"

    def _scan_page_content(self, url):
        """Live Dynamic Content tool."""
        res = run_dynamic_scan(url)
        if res["status"] == "success":
            return f"Final URL: {res['final_url']} | Title: {res['page_title']} | Content Snippet: {res['page_content'][:500]}..."
        return f"Scan failed: {res['error']}"

    def generate_detailed_analysis(self, query, input_type, risk_score, heuristic_reasons, db_results):
        """
        Executes the 4-tier fallback chain with ReAct tools.
        """
        domain = query.split("//")[-1].split("/")[0]
        
        # Priority 7: Real-time Tool Execution
        live_intel = {
            "domain_age": self._check_domain_age(domain),
            "ssl_info": self._check_ssl_certificate(domain),
            "dynamic_intel": self._scan_page_content(query) if risk_score > 20 else "Skipped for low risk."
        }
        
        prompt = self._build_prompt(query, input_type, risk_score, heuristic_reasons, db_results, live_intel)
        
        # Tier 1: Gemini
        if self.gemini_key:
            analysis = self._call_gemini_tier(prompt)
            if analysis:
                return {"analysis": analysis, "model_used": "Gemini 1.5 Flash", "tier": 1}

        # Tier 2: Llama 3.1 8B (Local Ollama)
        analysis = self._call_ollama_tier("llama3.1:8b", prompt)
        if analysis:
            return {"analysis": analysis, "model_used": "Llama 3.1 (8B)", "tier": 2}

        # Tier 3: Phi-3 Mini (Local Ollama)
        analysis = self._call_ollama_tier("phi3:mini", prompt)
        if analysis:
            return {"analysis": analysis, "model_used": "Phi-3 Mini", "tier": 3}

        # Tier 4: Rule-based Fallback
        analysis = self._call_rule_based_tier(query, input_type, risk_score, heuristic_reasons, db_results)
        return {"analysis": analysis, "model_used": "Rule-based Engine", "tier": 4}

    def _build_prompt(self, query, input_type, risk_score, heuristic_reasons, db_results, live_intel):
        return f"""
        Act as a senior Cyber Security Intelligence Agent (Agent Safe-Surf). 
        Target: '{query}' ({input_type}).
        
        STATIC SCORING DATA:
        - ML Risk Score: {risk_score}/100
        - Heuristic Alarms: {', '.join(heuristic_reasons) if heuristic_reasons else 'None'}
        - Database Matches: {list(db_results.keys()) if db_results else 'None'}
        
        LIVE RE-ACT INTEL (Real-time checks):
        - WHOIS Data: {live_intel['domain_age']}
        - SSL Certificate: {live_intel['ssl_info']}
        - Dynamic Browser Scan: {live_intel['dynamic_intel']}
        
        TASK:
        Provide a sharp, reasoning-based security briefing using BOTH static and live data.
        1. Break down the attack vector (e.g. Brand Spoofing, Data Exfiltration).
        2. 2-3 technical bullets on danger.
        3. Final Verdict and Action.
        
        Tone: Brilliant, cybersecurity expert. Use Markdown.
        """

    def _call_gemini_tier(self, prompt):
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_key}"
            data = {"contents": [{"parts": [{"text": prompt}]}]}
            res = requests.post(url, json=data, timeout=10)
            if res.status_code == 200:
                return res.json()['candidates'][0]['content']['parts'][0]['text']
        except:
            pass
        return None

    def _call_ollama_tier(self, model_name, prompt):
        try:
            data = {
                "model": model_name,
                "prompt": prompt,
                "stream": False
            }
            res = requests.post(self.ollama_url, json=data, timeout=30)
            if res.status_code == 200:
                return res.json().get("response")
        except:
            pass
        return None

    def _call_rule_based_tier(self, query, input_type, risk_score, heuristic_reasons, db_results):
        analysis = f"### 🤖 Safe-Surf Intelligence Report (Rule-based)\n\n"
        analysis += f"Risk Level: **{risk_score}/100**\n\n"
        analysis += "#### 🔍 Automated Findings:\n"
        
        if heuristic_reasons:
            analysis += f"Our scanners identified several red flags: {', '.join(heuristic_reasons)}.\n"
        else:
            analysis += "No critical heuristic alarms triggered, but base ML risk remains present.\n"
            
        if db_results:
            analysis += f"CRITICAL: The target matches known malicious signatures in our database.\n"
            
        analysis += "\n#### 🆘 Recommended Action:\n"
        if risk_score > 60:
            analysis += "🛑 **IMMEDIATE ACTION**: Do not interact. This target shows high-confidence phishing patterns."
        else:
            analysis += "⚠️ **CAUTION**: Exercise standard security protocols."
            
        return analysis

def get_ai_agent_response(query, input_type, risk_score, heuristic_reasons, db_results):
    agent = PhishingAIAgent()
    return agent.generate_detailed_analysis(query, input_type, risk_score, heuristic_reasons, db_results)
