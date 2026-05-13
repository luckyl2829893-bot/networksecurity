import re

class HindiPhishingDetector:
    def __init__(self):
        # Common Hindi phishing keywords in Devnagari
        self.hindi_keywords = [
            "ईनाम", "जीतें", "खाता बंद", "केवाईसी", "बोनस", "अपडेट", 
            "लॉटरी", "बैंक", "सुरक्षित", "लिंक", "क्लिक", "ऑफर"
        ]
        
        # Specifically Indian/Hinglish markers (High Confidence)
        self.indian_markers = [
            "khata", "band-hoga", "inaam", "rupay", "upi-band", 
            "aadhaar", "paytm", "jio", "bsnl", "phonepe", "gpay", 
            "kyc-update", "aadhaar-link"
        ]
        
        # Generic markers that only trigger if Indian context is present
        self.generic_risk_keywords = [
            "secure", "update", "login", "bank", "lottery", "prize", "winner"
        ]

    def detect(self, url, content=""):
        """
        Detects if the URL or page content contains Hindi phishing indicators.
        """
        url_lower = url.lower()
        content_lower = content.lower()
        
        reasons = []
        
        # 1. Detect Devnagari Script (Strong indicator of local targeting)
        devnagari_pattern = re.compile(r'[\u0900-\u097F]+')
        has_devnagari = bool(devnagari_pattern.search(url + content))
        
        # 2. Check for High-Confidence Indian Markers
        for word in self.indian_markers:
            if word in url_lower or word in content_lower:
                reasons.append(f"Detected Indian-specific threat marker: '{word}'")

        # 3. Check for Generic Keywords ONLY if Devnagari or Indian brands are present
        if has_devnagari or any(marker in url_lower + content_lower for marker in ["paytm", "jio", "bank", "khata"]):
             for word in self.generic_risk_keywords:
                if word in url_lower or word in content_lower:
                    reasons.append(f"Generic risk word '{word}' found in Indian phishing context")

        # 4. Devnagari keyword matching (if script detected)
        if has_devnagari:
            for word in self.hindi_keywords:
                if word in url_lower or word in content_lower:
                    reasons.append(f"Detected Hindi phishing keyword: '{word}'")

        return {
            "detected": len(reasons) > 0,
            "reasons": list(set(reasons)), # Deduplicate
            "score_boost": len(reasons) * 15 # Each marker adds to the risk
        }

# Singleton instance
hindi_detector = HindiPhishingDetector()
