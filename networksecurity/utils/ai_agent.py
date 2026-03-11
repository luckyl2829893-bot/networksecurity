import random
import os
import requests
import json

class PhishingAIAgent:
    """
    A sophisticated AI Security Agent that provides deep, reasoning-based analysis 
    of phishing threats. It supports REAL Grok (X.AI) or OpenAI-compatible APIs.
    """
    
    def __init__(self, personality="CyberAnalyst"):
        self.personality = personality
        # Check for XAI (Grok) or OpenAI keys
        self.api_key = os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY")
        self.api_url = "https://api.x.ai/v1/chat/completions"

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
        if self.api_key and risk_score > 10:
            return self._fetch_real_llm_analysis(query, input_type, risk_score, heuristic_reasons, db_results)
        
        return self._generate_simulated_analysis(query, input_type, risk_score, heuristic_reasons, db_results)

    def _fetch_real_llm_analysis(self, query, input_type, risk_score, heuristic_reasons, db_results):
        """
        Calls the REAL X.ai (Grok) or OpenAI API with the security research data.
        """
        prompt = f"""
        Act as a senior Cyber Security Intelligence Agent (Agent NS-Grok). 
        I have found a suspicious {input_type} target: '{query}'.
        
        TECHNICAL DATA FOUND BY OUR SCANNERS:
        - Risk Score: {risk_score}/100
        - Heuristic Alarms: {', '.join(heuristic_reasons) if heuristic_reasons else 'None'}
        - Database Matches: {list(db_results.keys()) if db_results else 'None'}
        
        TASK:
        Write a detailed, sharp, and reasoning-based security briefing (Grok-style).
        1. Break down the specific attack vector (e.g., Homograph, Brand Spoofing, Data Exfiltration).
        2. Explain WHY it is dangerous in 2-3 technical bullets.
        3. Give a final 'Verdict' and immediate 'Action' for the user.
        
        Tone: Brilliant, slightly edgy, cybersecurity expert. Use Markdown (bold, headers) for structure.
        """

        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
            data = {
                "model": "grok-2", 
                "messages": [
                    {"role": "system", "content": "You are a world-class cybersecurity AI agent named NS-Grok."},
                    {"role": "user", "content": prompt}
                ],
                "stream": False
            }
            
            response = requests.post(self.api_url, headers=headers, json=data, timeout=12)
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return f"⚠️ [Agent Connection: Code {response.status_code}] Falling back to local neural analysis...\n\n" + \
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
        analysis = f"### 🤖 NS-Grok Intelligence Report\n\n"
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
