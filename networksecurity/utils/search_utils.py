import re
from urllib.parse import urlparse

def identify_input_type(input_str: str) -> str:
    """
    Identifies if the input is an IP address, Domain, or URL.
    """
    input_str = input_str.strip()
    
    # Regex for IP address (IPv4)
    ip_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if ip_pattern.match(input_str):
        return "ip"
    
    # Check if it's a URL (has scheme or looks like a path)
    if input_str.startswith("http://") or input_str.startswith("https://") or "/" in input_str:
        return "url"
    
    # Default to domain (e.g., google.com)
    return "domain"

def calculate_risk_score(results: dict) -> int:
    """
    Calculates a risk score (0-100) based on search results.
    """
    score = 0
    
    # Weights
    WEIGHTS = {
        "phishing_link": 50,
        "combined_urls": 50,
        "domains": 30,
        "ips": 20
    }
    
    if results.get("phishing_link"):
        score += WEIGHTS["phishing_link"]
        
    if results.get("combined_urls"):
        score += WEIGHTS["combined_urls"]
        
    if results.get("domains"):
        score += WEIGHTS["domains"]
        
    if results.get("ips"):
        score += WEIGHTS["ips"]
        
    # Cap score at 100
    return min(score, 100)

def calculate_heuristic_score(input_str: str, input_type: str) -> dict:
    """
    Analyzes the input for suspicious patterns (Heuristics) 
    to assess risk even if not found in the database.
    """
    heuristic_score = 0
    details = []
    
    input_lower = input_str.lower()
    
    # 1. Suspicious Keywords
    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "verify", "update", "secure", "account", 
        "banking", "paypal", "amazon", "apple", "google", "microsoft",
        "confirm", "wallet", "crypto", "free", "bonus"
    ]
    
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in input_lower]
    if found_keywords:
        score_increase = len(found_keywords) * 10
        heuristic_score += score_increase
        details.append(f"Suspicious keywords found: {', '.join(found_keywords)} (+{score_increase})")

    # 2. Suspicious TLDs (Top Level Domains)
    # These are often abused, though not inherently malicious.
    SUSPICIOUS_TLDS = [".xyz", ".top", ".club", ".info", ".cn", ".ru", ".work", ".gq", ".ml"]
    if any(input_lower.endswith(tld) for tld in SUSPICIOUS_TLDS):
        heuristic_score += 20
        details.append("Uses high-risk TLD (+20)")

    # 3. Length / Complexity
    if len(input_str) > 75:
        heuristic_score += 15
        details.append("Unusually long URL/Domain (+15)")
        
    # 4. IP Address as Host (for URLs)
    # e.g., http://192.168.1.1/login
    if input_type == "url":
        # Simple check if the host part looks like an IP
        try:
            from urllib.parse import urlparse
            parsed = urlparse(input_str if "://" in input_str else "http://" + input_str)
            hostname = parsed.hostname
            if hostname and re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname):
                heuristic_score += 25
                details.append("URL uses IP address instead of domain (+25)")
        except:
            pass

    # 5. Typosquatting / Brand Imitation
    TARGET_BRANDS = [
        "paypal", "google", "facebook", "amazon", "apple", "microsoft", 
        "netflix", "instagram", "whatsapp", "twitter", "linkedin"
    ]
    
    from difflib import SequenceMatcher
    
    # Clean input for comparison
    clean_input = input_lower.replace("http://", "").replace("https://", "").replace("www.", "")
    
    # Remove path if present
    if "/" in clean_input:
        clean_input = clean_input.split("/")[0]
        
    # Check for "Brand Split" (e.g., ama.zon)
    # We remove all dots and see if it equals a brand
    no_dot_input = clean_input.replace(".", "")
    for brand in TARGET_BRANDS:
        if brand in no_dot_input:
            # But we must ensure it's not the actual brand domain (e.g. amazon.com -> amazoncom contains amazon)
            # If the original input had a dot inside the brand part, it's suspicious.
            # e.g. ama.zon.com -> amazoncom. Brand is amazon. 
            # We check if the brand appears in the cleaned string BUT was separated in the original.
            
            # Simple check: if the brand is present in the "no dot" version, 
            # but the "dot" version doesn't contain the brand as a whole word.
            if brand not in clean_input:
                 heuristic_score += 50
                 details.append(f"Suspicious dot placement detected (Targeting '{brand}') (+50)")
                 break

    # Fuzzy Matching on Domain Parts
    parts = clean_input.split(".")
    
    # Check each part (subdomain/domain) against brands
    for part in parts:
        if len(part) < 3: continue # Skip short parts
        
        for brand in TARGET_BRANDS:
            if part == brand:
                continue # Exact match of a part might be okay (e.g. google.com) or handled elsewhere
                
            similarity = SequenceMatcher(None, part, brand).ratio()
            if 0.8 <= similarity < 1.0:
                heuristic_score += 40
                details.append(f"Potential typosquatting in subdomain '{part}' (Simulates '{brand}') (+40)")
                break 

    return {"score": heuristic_score, "reasons": details}

def normalize_url(url: str) -> str:
    """
    Normalizes URL for searching. 
    Removes scheme if present to match dataset format if needed, 
    or ensures consistency.
    """
    # For this specific dataset, we might need to match exact strings or partials.
    # Let's keep it simple for now.
    return url.strip()
