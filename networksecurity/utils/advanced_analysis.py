import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import whois
import dns.resolver
from datetime import datetime
import os
import sys

def analyze_form_targets(url: str) -> dict:
    """
    Scrapes the URL and checks if forms send data to a different domain (Cross-Origin Data Leak).
    """
    results = {"detected": False, "details": []}
    
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            
        # 1. Fetch the page (with a timeout to avoid hanging)
        response = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        if response.status_code != 200:
            return results
            
        soup = BeautifulSoup(response.text, 'html.parser')
        base_domain = urlparse(url).netloc
        
        # 2. Find all forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            if not action:
                continue
                
            # Resolve relative URLs
            full_action_url = urljoin(url, action)
            action_domain = urlparse(full_action_url).netloc
            
            # 3. Check for Cross-Origin matching
            if action_domain and action_domain != base_domain:
                results["detected"] = True
                results["details"].append(f"Form data targeted at EXTERNAL domain: {action_domain}")
        
        # 4. Check for Suspicious Iframes (In-Site Phishing)
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if not src: continue
            
            iframe_domain = urlparse(urljoin(url, src)).netloc
            if iframe_domain and iframe_domain != base_domain:
                results["detected"] = True
                results["details"].append(f"Suspicious EXTERNAL Iframe found: {iframe_domain}")

        # 5. Check for Clickjacking Protection (X-Frame-Options / CSP)
        # Section 1.D of Research
        headers = response.headers
        if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
            results["detected"] = True
            results["details"].append("Vulnerable to Clickjacking: Missing 'X-Frame-Options' header.")
            
        # 6. Suspicious Script (JS) Scanner
        # Section 3.2 of Research - Monitoring third-party scripts
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if not src: continue
            
            script_domain = urlparse(urljoin(url, src)).netloc
            high_risk_tlds = [".xyz", ".top", ".online", ".site", ".ru", ".cn"]
            if script_domain and any(script_domain.endswith(tld) for tld in high_risk_tlds):
                results["detected"] = True
                results["details"].append(f"Suspicious Script detected from high-risk domain: {script_domain}")

        return results
        
    except Exception as e:
        # Silently fail for web scraping as it might be blocked or offline
        return {"detected": False, "details": [f"Web analysis error: {str(e)}"]}

def get_domain_age_risk(domain_str: str) -> dict:
    """
    Checks the WHOIS record for the domain to identify if it's unusually new.
    """
    results = {"is_new": False, "age_days": None, "details": []}
    
    try:
        # Clean domain
        domain = domain_str.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
        
        # 1. Perform WHOIS lookup
        w = whois.whois(domain)
        
        # 2. Extract creation date (can be a list or a single datetime object)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            now = datetime.now()
            age_delta = now - creation_date
            results["age_days"] = age_delta.days
            
            # 3. If domain is < 30 days old, it's high risk
            if age_delta.days < 30:
                results["is_new"] = True
                results["details"].append(f"Domain is VERY NEW (Created {age_delta.days} days ago)")
            elif age_delta.days < 180:
                results["details"].append(f"Domain is relatively new ({age_delta.days} days old)")
                
        return results
        
    except Exception:
        # WHOIS often fails for newer/obscure TLDs or when rate-limited
        return results

def analyze_open_redirects(url: str) -> dict:
    """
    Checks for Open Redirect vulnerabilities (Section 1.C of Research).
    Example: site.com/login?url=http://evil.com
    """
    results = {"detected": False, "details": []}
    parsed_url = urlparse(url)
    
    # Critical redirect parameters used by attackers
    REDIRECT_PARAMS = ["url", "redirect", "next", "goto", "target", "r", "u", "link"]
    
    query_params = parsed_url.query.split("&")
    for param in query_params:
        if "=" not in param: continue
        key, value = param.split("=", 1)
        
        if key.lower() in REDIRECT_PARAMS:
            # Check if the value is an absolute URL (starts with http/https) 
            # and is NOT for the same domain.
            if value.startswith(("http", "//")):
                val_domain = urlparse(value).netloc if value.startswith("http") else value.split("/")[2]
                if val_domain and val_domain != parsed_url.netloc:
                    results["detected"] = True
                    results["details"].append(f"Open Redirect detected in parameter '{key}' pointing to: {val_domain}")
                    
    return results

def check_subdomain_takeover(domain_str: str) -> dict:
    """
    Checks if a subdomain's CNAME points to common dead cloud resources (Section 1.B).
    """
    results = {"detected": False, "details": []}
    DEAD_SERVICES = [
        "s3.amazonaws.com", "azurewebsites.net", "herokuapp.com", "github.io",
        "shopify.com", "bitbucket.io", "wordpress.com", "cloudfront.net"
    ]
    
    try:
        domain = domain_str.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
        # Only check subdomains (more than 1 dot before TLD)
        if domain.count('.') < 2:
            return results
            
        # Resolve CNAME
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).lower()
            if any(service in target for service in DEAD_SERVICES):
                # This suggests the subdomain points to a cloud service. 
                # To confirm takeover, we would check if the service returns 404 (not implemented here).
                results["detected"] = True
                results["details"].append(f"Subdomain Takeover potential (CNAME points to: {target})")
                
    except Exception:
        pass # DNS resolution failed, skip.
        
    return results

def generate_security_brief(heuristic_reasons: list, db_results: dict, risk_score: int) -> str:
    """
    Explainable AI (XAI): Converts raw security data into a human-readable briefing.
    """
    if risk_score < 30:
        return "This input appears relatively safe. No common phishing patterns or malicious database matches were found."
        
    brief = f"🚨 SEVERE THREAT DETECTED (Risk Score: {risk_score}/100).\n\n"
    
    # 1. Database Matches
    if db_results:
        brief += "Analysis: Found in malicious blacklists.\n"
        
    # 2. Pattern Explanations
    brief += "\nKey Findings:\n"
    for reason in heuristic_reasons:
        if "Homograph" in reason:
            brief += "- ⚠️ IDENTITY THEFT: This URL uses invisible character spoofing to mimic a real brand.\n"
        elif "Brand" in reason:
            brief += "- ⚠️ BRAND SPOOFING: A trusted brand name is used on a non-official website.\n"
        elif "EXTERNAL domain" in reason:
            brief += "- ⚠️ DATA EXFILTRATION: This site is programmed to send your credentials to a third-party server.\n"
        elif "VERY NEW" in reason:
            brief += "- ⚠️ RECENTLY REGISTERED: Malicious sites are often created and deleted within days to avoid detection.\n"
        else:
            brief += f"- {reason}\n"
            
    brief += "\nRecommended Action: DO NOT visit this link or enter any credentials."
    return brief
