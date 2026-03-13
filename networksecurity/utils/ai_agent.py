import random
import os
import requests
import json

class PhishingAIAgent:
    """
    A sophisticated AI Security Agent that provides deep, reasoning-based analysis 
    of phishing threats. Supports Gemini, Grok, and OpenAI.
    """
    
    def __init__(self, personality="CyberAnalyst"):
        self.personality = personality
        # Check for XAI (Grok) or OpenAI/Gemini keys
        self.api_key = (os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY") or os.getenv("GEMINI_API_KEY") or "").strip()
        
        if self.api_key and self.api_key.startswith("AIza"):
            self.provider = "gemini"
            print(f"--- [Safe-Surf Node] Localhost: INITIALIZED Gemini v3.2.3 (Key: {len(self.api_key)} chars) ---")
        else:
            self.api_url = "https://api.x.ai/v1/chat/completions"
            self.provider = "openai"
            self.model = "grok-2"
            print(f"--- [Safe-Surf Node] Localhost: INITIALIZED Grok/OpenAI (Key: {len(self.api_key)} chars) ---")

    def _get_intro(self, risk_score):
        if risk_score > 80:
            return random.choice([
                "SYSTEM ALERT: High-level malicious activity detected. Let me break down this attack for you.",
                "Analyzing threat vectors... This looks like a multi-stage phishing attempt. Here's my intelligence report.",
                "CRITICAL: Found strong evidence of brand impersonation and identity theft. Initiating deep dive..."
            ])
        elif risk_score > 40:
            return random.choice([
                "Scanning patterns... I've identified several suspicious markers. Exercise caution.",
                "Preliminary analysis complete. The indicators point to a potential phishing setup.",
                "Heuristic evaluation suggests this URL is atypical. Here are the red flags I've found."
            ])
        else:
            return "Scan complete. No significant malicious patterns detected in my current baseline."

    def generate_detailed_analysis(self, query, input_type, risk_score, heuristic_reasons, db_results):
        """
        Main entry point. Calls REAL API if key exists, else falling back to simulation.
        """
        if self.api_key:
            return self._fetch_real_llm_analysis(query, input_type, risk_score, heuristic_reasons, db_results)
        
        return self._generate_simulated_analysis(query, input_type, risk_score, heuristic_reasons, db_results)

    def _fetch_real_llm_analysis(self, query, input_type, risk_score, heuristic_reasons, db_results):
        """
        Calls the REAL X.ai (Grok) or OpenAI API with the security research data.
        """
        prompt = f"""
        Act as a senior Cyber Security Intelligence Agent (Agent Safe-Surf). 
        I have found a suspicious {input_type} target: '{query}'.
        
        TECHNICAL DATA FOUND BY OUR SCANNERS:
        - Risk Score: {risk_score}/100
        - Heuristic Alarms: {', '.join(heuristic_reasons) if heuristic_reasons else 'None'}
        - Database Matches: {list(db_results.keys()) if db_results else 'None'}
        
        TASK:
        Write a detailed, sharp, and reasoning-based security briefing (Safe-Surf-style).
        1. Break down the specific attack vector (e.g., Homograph, Brand Spoofing, Data Exfiltration).
        2. Explain WHY it is dangerous in 2-3 technical bullets.
        3. Give a final 'Verdict' and immediate 'Action' for the user.
        
        Tone: Brilliant, slightly edgy, cybersecurity expert. Use Markdown (bold, headers) for structure.
        """

        try:
            if self.provider == "gemini":
                # --- HYPER-DISCOVERY LOOP (v3.2.4 Sync) ---
                models_to_try = [
                    "gemini-2.0-flash",
                    "gemini-1.5-flash",
                    "gemini-2.0-flash-lite-001",
                    "gemini-1.5-pro",
                    "gemini-2.5-flash",
                    "gemini-flash-latest"
                ]
                
                gemini_data = {"contents": [{"parts": [{"text": prompt}]}]}
                last_err = ""
                
                # We try v1beta first as it supports the newest models (2.0/2.5)
                for version in ["v1beta", "v1"]:
                    for model in models_to_try:
                        url = f"https://generativelanguage.googleapis.com/{version}/models/{model}:generateContent?key={self.api_key}"
                        try:
                            # Short timeout for fast skipping
                            res = requests.post(url, json=gemini_data, timeout=8)
                            if res.status_code == 200:
                                print(f"--- [Safe-Surf Node] Gemini Success: {version}/{model} ---")
                                return res.json()['candidates'][0]['content']['parts'][0]['text']
                            last_err = f"{version}/{model} ({res.status_code})"
                        except Exception as e:
                            last_err = f"NetErr ({str(e)[:20]})"
                            continue
                
                # If we get here, log the total failure
                print(f"--- [Safe-Surf Node] FATAL: All Gemini models 404'd. Last: {last_err} ---")
                return f"⚠️ [Safe-Surf Node: 404] Local Gemini connection failed. Last: {last_err}\n\n" + \
                       self._generate_simulated_analysis(query, input_type, risk_score, heuristic_reasons, db_results)

            else:
                # Standard OpenAI/Grok Format
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}"
                }
                data = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a world-class cybersecurity AI agent named Safe-Surf."},
                        {"role": "user", "content": prompt}
                    ],
                    "stream": False
                }
                
                response = requests.post(self.api_url, headers=headers, json=data, timeout=12)
                if response.status_code == 200:
                    result = response.json()
                    return result['choices'][0]['message']['content']
                else:
                    err_msg = response.text[:150]
                    return f"⚠️ [Safe-Surf Node: {response.status_code}] {err_msg}...\n\n" + \
                           self._generate_simulated_analysis(query, input_type, risk_score, heuristic_reasons, db_results)
                
        except Exception as e:
            return f"⚠️ [Local Failover: {str(e)[:50]}]\n\n" + \
                   self._generate_simulated_analysis(query, input_type, risk_score, heuristic_reasons, db_results)

    def _generate_simulated_analysis(self, query, input_type, risk_score, heuristic_reasons, db_results):
        """
        High-quality simulation fallback.
        """
        if risk_score < 20:
            return self._get_intro(risk_score)

        # Build the 'Reasoning' sections
        analysis = f"### 🤖 Safe-Surf Intelligence Report\n\n"
        analysis += f"{self._get_intro(risk_score)}\n\n"
        
        analysis += "#### 🔍 Investigation Log:\n"
        
        # 1. Structural Analysis
        analysis += f"1. **Infrastructure**: Analyzing the `{input_type}` target. "
        if db_results:
            analysis += "Historical data confirms this entity is already flagged in global malicious blacklists. "
        else:
            analysis += "No prior history in static blacklists, suggesting a zero-day or recycled attack vector. "
            
        # 2. Heuristic Deep Dive
        analysis += "\n2. **Threat Markers**: "
        reasons_text = []
        for reason in heuristic_reasons:
            if "Homograph" in reason:
                reasons_text.append("detected a **Homograph (Punycode)** attack using invisible character spoofing")
            elif "Brand" in reason:
                reasons_text.append("identified **Brand Impersonation** (using unofficial domains)")
            elif "EXTERNAL domain" in reason:
                reasons_text.append("found hidden **Data Exfiltration** code")
            elif "VERY NEW" in reason:
                reasons_text.append("flagged a **Newly Registered Domain** (<30 days)")
            elif "Open Redirect" in reason:
                reasons_text.append("detected an **Open Redirect tunnel**")
            else:
                reasons_text.append(f"identified {reason.lower()}")
        
        if reasons_text:
            analysis += "Our scanners " + ", and I have ".join(reasons_text) + ". "
        
        # 3. Risk Assessment
        analysis += f"\n3. **Final Verdict**: With a risk score of **{risk_score}/100**, this is a "
        if risk_score > 80:
            analysis += "Highly Dangerous threat. This site is specifically designed for credential harvesting."
        else:
            analysis += "Suspicious entity. It displays patterns commonly associated with social engineering."
            
        analysis += "\n\n#### 🆘 Recommended Action:\n"
        if risk_score > 60:
            analysis += "🛑 **IMMEDIATE ACTION**: Close the tab. Do not input credentials. Report this to security."
        else:
            analysis += "⚠️ **CAUTION**: Site shows unconventional patterns. Verify the source manually."
            
        return analysis

# Placeholder for real LLM integration
def get_ai_agent_response(query, input_type, risk_score, heuristic_reasons, db_results):
    agent = PhishingAIAgent()
    return agent.generate_detailed_analysis(query, input_type, risk_score, heuristic_reasons, db_results)
