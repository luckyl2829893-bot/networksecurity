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
    Only adds score if the found record is actually malicious.
    """
    score = 0
    
    # Weights
    # If found in our malicious database, it is High Risk.
    WEIGHTS = {
        "phishing_link": 100,
        "combined_urls": 100,
        "domains": 100,
        "ips": 100
    }
    
    # Helper to check if a document is malicious
    def is_malicious(doc):
        if not doc: return False
        # Check 'result' (1 = bad, 0 = good)
        if "result" in doc:
            return str(doc["result"]) == "1"
        # Check 'label' (bad/good)
        if "label" in doc:
            return str(doc["label"]).lower() == "bad"
        # Default to True if it's in a specific blacklist collection without labels
        return True

    if is_malicious(results.get("phishing_link")):
        score += WEIGHTS["phishing_link"]
        
    if is_malicious(results.get("combined_urls")):
        score += WEIGHTS["combined_urls"]
        
    if is_malicious(results.get("domains")):
        score += WEIGHTS["domains"]
        
    if is_malicious(results.get("ips")):
        score += WEIGHTS["ips"]
        
    # Cap score at 100
    return min(score, 100)

def is_homograph_attack(input_str: str) -> bool:
    """
    Detects if a URL/Domain is a homograph attack by checking for Punycode encoding
    or non-ASCII characters that might be spoofing legitimate characters.
    """
    input_lower = input_str.lower()
    
    # 1. Check for Punycode prefix directly (Universal standard for homograph URLs)
    if "xn--" in input_lower:
        return True
        
    # 2. Extract domain part to check for non-ASCII
    # Homographs are most dangerous in the domain name.
    clean_domain = input_lower.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
    
    # 3. Check for non-ASCII characters in the domain.
    # If the domain contains non-ASCII characters (like Cyrillic 'а'), 
    # it is a high-risk indicator of a homograph attack.
    if any(ord(char) > 127 for char in clean_domain):
        return True
        
    return False

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
        "confirm", "wallet", "crypto", "free", "bonus", "alert", "support",
        "service", "auth", "security", "sassa", "forms", "app", "billing",
        "membership", "access", "portal", "relay", "ideas", "industriales"
    ]
    
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in input_lower]
    if found_keywords:
        score_increase = len(found_keywords) * 10
        heuristic_score += score_increase
        details.append(f"Suspicious keywords found: {', '.join(found_keywords)} (+{score_increase})")

    # 2. Suspicious TLDs (Top Level Domains)
    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".club", ".info", ".cn", ".ru", ".work", 
        ".gq", ".ml", ".ga", ".cf", ".tk", ".online", ".site", ".live",
        ".biz", ".loan", ".app"
    ]
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
            
        # Check for URL Chaining / Open Redirects (Multiple schemes)
        # e.g. http://legit.com//http://evil.com
        scheme_count = input_lower.count("http") + input_lower.count("https") + input_lower.count("www.")
        # Note: A normal URL has 1 scheme (http or https). If we see more, it's suspicious.
        # We count 'http' which is inside 'https', so 'https://' counts as 1 http and 1 https? 
        # Simpler: count "://"
        slash_slash_count = input_lower.count("://")
        if slash_slash_count > 1:
             heuristic_score += 40
             details.append("Multiple URL schemes detected (Potential Open Redirect) (+40)")

        # 4.B Deep Subdomain Count (e.g., ideasindustrialesrb.codepro47.net)
        # Professional sites rarely go more than 2-3 levels deep on external subdomains.
        try:
            subdomain_part = parsed.netloc.replace("www.", "")
            dot_count = subdomain_part.count(".")
            if dot_count >= 3:
                heuristic_score += 25
                details.append(f"Excessive subdomains found ({dot_count} levels deep) (+25)")
        except:
            pass
             
        # Check for '@' symbol (Obfuscation)
        if "@" in input_str:
            heuristic_score += 30
            details.append("URL contains '@' symbol (Potential Obfuscation) (+30)")

    # 5. Typosquatting / Brand Imitation
    TARGET_BRANDS = {
        "paypal": "paypal.com",
        "google": "google.com",
        "facebook": "facebook.com",
        "amazon": "amazon.com",
        "apple": "apple.com",
        "microsoft": "microsoft.com",
        "netflix": "netflix.com",
        "instagram": "instagram.com",
        "whatsapp": "whatsapp.com",
        "twitter": "twitter.com",
        "linkedin": "linkedin.com",
        "chase": "chase.com",
        "wellsfargo": "wellsfargo.com"
    }
    
    from difflib import SequenceMatcher
    
    # Clean input for comparison
    clean_input = input_lower.replace("http://", "").replace("https://", "").replace("www.", "")
    
    # Remove path if present
    if "/" in clean_input:
        clean_input = clean_input.split("/")[0]
        
    # Check for Brand Impersonation (Brand name in domain but NOT official domain)
    for brand, official_domain in TARGET_BRANDS.items():
        if brand in clean_input:
            # Check if it is the official domain or a subdomain of it
            if not (clean_input == official_domain or clean_input.endswith("." + official_domain)):
                heuristic_score += 60
                details.append(f"Brand '{brand}' detected in unofficial domain '{clean_input}' (+60)")
                break # Stop after finding one impersonation

    # Fuzzy Matching on Domain Parts (Typosquatting)
    parts = clean_input.split(".")
    
    # Check each part (subdomain/domain) against brands
    for part in parts:
        if len(part) < 3: continue # Skip short parts
        
        for brand in TARGET_BRANDS.keys():
            if part == brand:
                continue # Exact match handled above
                
            similarity = SequenceMatcher(None, part, brand).ratio()
            if 0.8 <= similarity < 1.0:
                heuristic_score += 40
                details.append(f"Potential typosquatting in subdomain '{part}' (Simulates '{brand}') (+40)")
                break 

    # 6. Gibberish / DGA Detection (Entropy Analysis)
    # Detects random strings like 'aabbajaabadaaba' commonly used in zero-day attacks
    domain_part = clean_input.split('.')[0]
    if len(domain_part) > 10:
        vowels = set("aeiou")
        vowel_count = sum(1 for char in domain_part if char in vowels)
        # Random gibberish often has very high or very low vowel ratios
        # or uses repeating clusters.
        vowel_ratio = vowel_count / len(domain_part)
        UNIQUE_CHARS = len(set(domain_part))
        
        # Heuristic: If vowels are < 15% or > 80%, or if unique chars are very low/high relative to length
        if vowel_ratio < 0.15 or vowel_ratio > 0.8 or (UNIQUE_CHARS < len(domain_part) * 0.3):
            heuristic_score += 30
            details.append(f"High-Entropy/Gibberish domain detected ('{domain_part}') (+30)")

    # 7. Homograph / Punycode Attack Detection
    if is_homograph_attack(input_str):
        heuristic_score += 90
        details.append("Homograph Attack detected: URL uses non-standard characters to spoof a domain (+90)")

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
