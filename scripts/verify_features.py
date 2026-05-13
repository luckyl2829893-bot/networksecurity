import sys
import os
from networksecurity.utils.whitelist_manager import whitelist_manager
from networksecurity.utils.hindi_detector import hindi_detector
from networksecurity.utils.dynamic_scanner import run_dynamic_scan

def test_whitelist():
    print("\n--- [Test 1: Tranco Whitelist] ---")
    urls = ["https://www.google.com", "https://github.com", "http://suspicious-site.xyz"]
    for url in urls:
        is_trusted = whitelist_manager.is_whitelisted(url)
        print(f"URL: {url:30} | Trusted: {is_trusted}")

def test_hindi_detection():
    print("\n--- [Test 2: Hindi/Hinglish Detection] ---")
    # Real-world phishing patterns for India
    phishing_patterns = [
        "http://paytm-kyc-update-ईनाम.com",
        "http://bank-account-band-hoga.net",
        "https://secure-login.com"
    ]
    for url in phishing_patterns:
        res = hindi_detector.detect(url)
        print(f"URL: {url:40} | Detected: {res['detected']} | Reasons: {res['reasons']}")

def test_dynamic_sandbox():
    print("\n--- [Test 3: Playwright Dynamic Sandbox] ---")
    # Test with a URL that redirects
    url = "http://google.com" # Should redirect to https://www.google.com
    print(f"Scanning: {url} ... (Launching browser)")
    res = run_dynamic_scan(url)
    if res["status"] == "success":
        print(f"Final URL: {res['final_url']}")
        print(f"Page Title: {res['page_title']}")
        print(f"Cloaking Detected: {res['detected_cloaking']}")
    else:
        print(f"Sandbox Error: {res['error']}")

if __name__ == "__main__":
    print("🚀 SAFE-SURF REAL-WORLD FEATURE VERIFICATION")
    print("="*50)
    test_whitelist()
    test_hindi_detection()
    test_dynamic_sandbox()
    print("\n" + "="*50)
    print("✅ VERIFICATION COMPLETE")
