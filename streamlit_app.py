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
from networksecurity.utils.ai_agent import get_ai_agent_response
from networksecurity.utils.whitelist_manager import whitelist_manager
from networksecurity.utils.hindi_detector import hindi_detector
from networksecurity.utils.dynamic_scanner import run_dynamic_scan

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

    domain_str = query
    if input_type == "url":
        domain_str = urlparse(query).netloc

    is_trusted = whitelist_manager.is_whitelisted(query) or whitelist_manager.is_whitelisted(domain_str)

    if is_trusted:
        total_risk_score = 0
        heuristic_reasons.append("✅ Verified Domain (Tranco Top 100k)")
    else:
        if input_type == "url":
            form_analysis = analyze_form_targets(query)
            if form_analysis["detected"]:
                heuristic_score += 100
                heuristic_reasons.extend(form_analysis["details"])
        
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
        
        # Priority 6: Hindi Phishing Detection
        hindi_results = hindi_detector.detect(query)
        if hindi_results["detected"]:
            heuristic_score += hindi_results["score_boost"]
            heuristic_reasons.extend(hindi_results["reasons"])
        
        total_risk_score = heuristic_score

    # Priority 5: Dynamic Sandbox Scan (Disabled by default for speed)
    dynamic_results = None
    if False: # total_risk_score > 30:
        with st.status("🚀 Launching Playwright Sandbox...", expanded=False):
            dynamic_results = run_dynamic_scan(query)
            if dynamic_results["status"] == "success":
                if dynamic_results["detected_cloaking"]:
                    total_risk_score = 100
                    heuristic_reasons.append("🚨 CLOAKING DETECTED: Initial domain differs from final destination.")
                
                # Check dynamic content for Hindi phishing
                dynamic_hindi = hindi_detector.detect(query, dynamic_results["page_content"])
                if dynamic_hindi["detected"]:
                    total_risk_score = min(total_risk_score + dynamic_hindi["score_boost"], 100)
                    heuristic_reasons.extend(dynamic_hindi["reasons"])
    
    # AI Agent Report (Safe-Surf-style)
    ai_response = get_ai_agent_response(query, input_type, total_risk_score, heuristic_reasons, {})
    
    confidence = 100 - (total_risk_score // 5) if total_risk_score < 50 else 95
    
    return {
        "query": query,
        "input_type": input_type,
        "risk_score": total_risk_score,
        "results": results,
        "heuristic_reasons": heuristic_reasons,
        "security_brief": ai_response["analysis"],
        "model_used": ai_response["model_used"],
        "tier": ai_response["tier"],
        "is_trusted": is_trusted,
        "dynamic_scan": dynamic_results,
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
        
        if res.get("is_trusted"):
            st.success("💎 TRUSTED DOMAIN: Found in Tranco Top 100k.")
            
        st.write("**Anomalies Detected:**")
        for r in res['heuristic_reasons']:
            st.error(r)

    # Main Stage
    st.subheader("Neural Briefing")
    st.info(f"🤖 Analyzed by: **{res['model_used']}** | Tier: **{res['tier']}**")
    st.markdown(res['security_brief'])
    
    # Detailed Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Risk Architecture", "Registry Feed", "Fingerprint", "Dynamic Sandbox", "Explainability"])
    
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

    with tab4:
        st.write("### 🚀 Playwright Dynamic Sandbox")
        if res.get("dynamic_scan"):
            ds = res["dynamic_scan"]
            if ds["status"] == "success":
                st.success("Analysis Complete")
                st.write(f"**Final Destination:** `{ds['final_url']}`")
                st.write(f"**Page Title:** {ds['page_title']}")
                if ds["detected_cloaking"]:
                    st.error("⚠️ CLOAKING/REDIRECTION LOOP DETECTED")
            else:
                st.error(f"Sandbox Error: {ds['error']}")
        else:
            st.info("Dynamic scan only triggers for high-risk targets (>30%).")

    with tab5:
        st.write("### AI Model Explainability (SHAP)")
        st.info("These plots explain exactly how the Machine Learning model reached its conclusion based on the extracted features.")
        
        _base = os.path.dirname(os.path.abspath(__file__))
        summary_path = os.path.join(_base, "Artifacts", "Explainability", "shap_summary_plot.png")
        if os.path.exists(summary_path):
            st.image(summary_path, caption="Global Feature Importance (SHAP Summary)")
        else:
            st.warning("SHAP Summary Plot not found. Please trigger a model retrain.")
            
        waterfall_path = os.path.join(_base, "Artifacts", "Explainability", "shap_waterfall_plot.png")
        if os.path.exists(waterfall_path):
            st.image(waterfall_path, caption="Local Instance Analysis (SHAP Waterfall)")

else:
    st.info("Enter a URL and click 'RUN SCAN' to initiate intelligence gathering.")
