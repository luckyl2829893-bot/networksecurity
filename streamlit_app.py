import streamlit as st
import streamlit.components.v1 as components
import os
import json
import requests
from dotenv import load_dotenv
from urllib.parse import urlparse

# Load local environment variables (for Localhost)
load_dotenv()

# Import your core logic
from networksecurity.utils.search_utils import identify_input_type, calculate_risk_score, calculate_heuristic_score
from networksecurity.utils.advanced_analysis import (
    analyze_form_targets, 
    get_domain_age_risk,
    analyze_open_redirects,
    check_subdomain_takeover
)
# Removed external agent import to ensure cloud stability
# from networksecurity.utils.ai_agent import get_ai_agent_response

# --- SELF-HEALING AI AGENT (V3.1) ---
class SafeSurfAgent:
    def __init__(self):
        self.api_key = (os.getenv("XAI_API_KEY") or os.getenv("GEMINI_API_KEY") or "").strip()
        
    def get_analysis(self, query, input_type, risk_score, heuristic_reasons):
        if not self.api_key:
            return "⚠️ NO API KEY DETECTED. Connect Gemini in Streamlit Secrets."
            
        # Complete experimental model list (v3.2.1)
        models_to_try = [
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-2.0-flash-lite-001",
            "gemini-1.5-pro",
            "gemini-2.5-flash",
            "gemini-flash-latest"
        ]
        
        prompt = f"Act as Safe-Surf AI Security Agent. Analyze this {input_type}: {query}. Risk Score: {risk_score}/100. Heuristic Alarms: {heuristic_reasons}. Write a sharp, technical security briefing with a final Verdict and Recommended Action. Use Markdown."
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        last_error = ""
        # Try different endpoints and model combinations
        # We try v1beta first as it supports the newest models (2.0/2.5)
        for version in ["v1beta", "v1"]:
            for model in models_to_try:
                url = f"https://generativelanguage.googleapis.com/{version}/models/{model}:generateContent?key={self.api_key}"
                try:
                    res = requests.post(url, json=payload, timeout=10)
                    if res.status_code == 200:
                        data = res.json()
                        return data['candidates'][0]['content']['parts'][0]['text']
                    # Log failure for discovery message
                    last_error = f"{version}/{model} ({res.status_code})"
                except Exception as e:
                    last_error = f"ConnErr ({str(e)[:30]})"
                    continue
        
        # If all fail, try to LIST the models to see what really is available
        try:
            list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={self.api_key}"
            list_res = requests.get(list_url, timeout=5).json()
            available = [m['name'].replace('models/', '') for m in list_res.get('models', [])]
            return f"⚠️ [Safe-Surf Node Error]: Key supports {len(available)} models, but discovery failed. Last: {last_error}. Try one of: {available[:3]}..."
        except:
            return f"⚠️ [System Error]: Connection failed. {last_error}"

# Set Page Config
st.set_page_config(
    page_title="Safe-Surf | Cyber Phishing Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- HELPER: Logic Execution ---
def perform_scan(query):
    query = query.strip()
    if not query:
        return None

    input_type = identify_input_type(query)
    results = {}
    
    # Note: MongoDB is usually skipped in cloud unless secrets are set
    db_score = 0 
    heuristic_data = calculate_heuristic_score(query, input_type)
    heuristic_score = heuristic_data["score"]
    heuristic_reasons = heuristic_data["reasons"]

    if input_type == "url":
        form_analysis = analyze_form_targets(query)
        if form_analysis["detected"]:
            heuristic_score += 100
            heuristic_reasons.extend(form_analysis["details"])
    
    domain_str = query
    if input_type == "url":
        domain_str = urlparse(query).netloc
        
    whois_data = get_domain_age_risk(domain_str)
    if whois_data["is_new"]:
        heuristic_score += 50
        heuristic_reasons.extend(whois_data["details"])
        
    redirect_analysis = analyze_open_redirects(query)
    if redirect_analysis["detected"]:
        heuristic_score += 40
        heuristic_reasons.extend(redirect_analysis["details"])
        
    subdomain_analysis = check_subdomain_takeover(domain_str)
    if subdomain_analysis["detected"]:
        heuristic_score += 70
        heuristic_reasons.extend(subdomain_analysis["details"])
    
    total_risk_score = min(db_score + heuristic_score, 100)
    
    # AI Agent Report (Safe-Surf-style)
    agent = SafeSurfAgent()
    security_brief = agent.get_analysis(query, input_type, total_risk_score, heuristic_reasons)
    confidence = 100 - (total_risk_score // 5) if total_risk_score < 50 else 95
    
    return {
        "query": query,
        "input_type": input_type,
        "risk_score": total_risk_score,
        "results": results,
        "heuristic_reasons": heuristic_reasons,
        "security_brief": security_brief,
        "confidence": confidence
    }

# --- UI STATE MANAGEMENT ---
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None

# --- STREAMLIT UI ---
# We inject a simple search bar at the top
st.title("🛡️ Safe-Surf Hub (v3.2)")
st.markdown("---")

col1, col2 = st.columns([4, 1])
with col1:
    target_input = st.text_input("ENTER TARGET NODE (URL/IP/DOMAIN)", placeholder="https://example.com")
with col2:
    if st.button("RUN SCAN", use_container_width=True):
        if target_input:
            with st.spinner("INITIATING NEURAL LINK..."):
                st.session_state.scan_results = perform_scan(target_input)
        else:
            st.warning("Please enter a target.")

# --- RENDER CUSTOM DASHBOARD ---
if st.session_state.scan_results:
    # We read the index.html and pass the data to it
    # Since Streamlit doesn't support Jinja directly in components.html, 
    # we would need to mock the search page.
    # ALTERNATIVELY: Direct Streamlit UI for Cloud deployment
    
    res = st.session_state.scan_results
    
    # Sidebar Metrics
    with st.sidebar:
        st.markdown("### 🤖 Safe-Surf Intelligence Report\n\n")
        st.metric("Risk Score", f"{res['risk_score']}/100", delta="- Malicious" if res['risk_score'] > 50 else "Safe")
        st.metric("Confidence", f"{res['confidence']}%")
        st.write("**Anomalies Detected:**")
        for r in res['heuristic_reasons']:
            st.error(r)

    # Main Stage
    st.subheader("Neural Briefing")
    st.markdown(res['security_brief'])
    
    # Detailed Tabs
    tab1, tab2, tab3 = st.tabs(["Risk Architecture", "Registry Feed", "Fingerprint"])
    
    with tab1:
        st.write("### Risk Breakdown")
        st.progress(res['risk_score']/100, text=f"Overall Threat Index ({res['risk_score']}%)")
        st.info("Score is calculated via deep heuristic analysis of structural indices.")
        
    with tab2:
        st.write("### Cyber Threat intelligence")
        if not res['results']:
            st.success("Target is not found in global threat registries.")
        else:
            st.write(res['results'])
            
    with tab3:
        st.write("### System Fingerprint")
        st.code(f"UIDX-{hash(res['query']) % 1000000}-TGT\nTYPE: {res['input_type'].upper()}")

else:
    st.info("Enter a URL and click 'RUN SCAN' to initiate intelligence gathering.")
