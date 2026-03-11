import sys
import os
import requests
from urllib.parse import urlparse

# Add current directory to path
sys.path.append(os.getcwd())

from networksecurity.utils.search_utils import calculate_heuristic_score, is_homograph_attack
from networksecurity.utils.advanced_analysis import (
    analyze_form_targets, 
    get_domain_age_risk, 
    analyze_open_redirects,
    check_subdomain_takeover
)

def run_comprehensive_tests():
    # Use a file for results because of terminal encoding/truncation issues
    with open("master_test_results.txt", "w", encoding="utf-8") as f:
        f.write("====================================================\n")
        f.write("🛡️  NETWORK SECURITY PROJECT: COMPREHENSIVE TEST SUITE\n")
        f.write("====================================================\n\n")

        test_cases = [
            {
                "name": "1. Homograph Attack (Punycode)",
                "query": "xn--80ak6aa92e.com",
                "type": "domain",
                "check": lambda q, t: is_homograph_attack(q)
            },
            {
                "name": "2. Open Redirect (Section 1.C)",
                "query": "https://example.com/login?next=http://malicious-site.xyz",
                "type": "url",
                "check": lambda q, t: analyze_open_redirects(q)["detected"]
            },
            {
                "name": "3. Brand Impersonation (Subdomain spoof)",
                "query": "secure-paypal-login.xyz",
                "type": "domain",
                "check": lambda q, t: "Brand 'paypal' detected" in str(calculate_heuristic_score(q, t)["reasons"])
            },
            {
                "name": "4. High-Risk TLD (.xyz)",
                "query": "free-crypto-bonus.xyz",
                "type": "domain",
                "check": lambda q, t: "high-risk TLD" in str(calculate_heuristic_score(q, t)["reasons"])
            },
            {
                "name": "5. Suspicious Keywords",
                "query": "update-your-banking-account-secure.com",
                "type": "domain",
                "check": lambda q, t: "Suspicious keywords found" in str(calculate_heuristic_score(q, t)["reasons"])
            }
        ]

        for test in test_cases:
            f.write(f"Testing {test['name']}...\n")
            f.write(f"  > Input: {test['query']}\n")
            
            try:
                passed = test["check"](test["query"], test["type"])
                status = "✅ PASSED (Detected)" if passed else "❌ FAILED (Not Detected)"
                f.write(f"  > Result: {status}\n")
            except Exception as e:
                f.write(f"  > Result: ⚠️ ERROR ({str(e)})\n")
            f.write("-" * 50 + "\n")

        f.write("\n--- Live Web Analysis Tests (Requires Internet) ---\n")
        live_tests = [
            ("http://www.google.com", "Legitimate Site (Should be low risk)"),
            ("http://testing-ground.scrapethissite.com/", "Scraping Test Site")
        ]

        for url, desc in live_tests:
            f.write(f"Testing Live URL: {url} ({desc})\n")
            try:
                analysis = analyze_form_targets(url)
                f.write(f"  > Form/Iframe Analysis Detected: {analysis['detected']}\n")
                if analysis['details']:
                    for detail in analysis['details']:
                        f.write(f"    - {detail}\n")
            except Exception as e:
                f.write(f"  > Live test error: {str(e)}\n")
            f.write("-" * 50 + "\n")

    print("[SUCCESS] Comprehensive test results written to master_test_results.txt.")

if __name__ == "__main__":
    run_comprehensive_tests()
