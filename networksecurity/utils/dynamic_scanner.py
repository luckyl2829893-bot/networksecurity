import asyncio
from playwright.async_api import async_playwright

class DynamicScanner:
    def __init__(self, timeout=15000):
        self.timeout = timeout

    async def scan_url(self, url):
        """
        Visits the URL using a headless browser and extracts dynamic features.
        """
        results = {
            "final_url": url,
            "redirect_count": 0,
            "page_content": "",
            "page_title": "",
            "detected_cloaking": False,
            "status": "success",
            "error": None
        }

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                
                # Intercept redirects
                response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                
                results["final_url"] = page.url
                results["page_title"] = await page.title()
                results["page_content"] = await page.content()
                
                # Check for cloaking (Major domain shift)
                def get_base_domain(url):
                    domain = url.split("//")[-1].split("/")[0].lower()
                    if domain.startswith("www."):
                        domain = domain[4:]
                    return domain

                initial_domain = get_base_domain(url)
                final_domain = get_base_domain(results["final_url"])
                
                # Priority 5 Fix: Never flag Tranco Whitelisted domains for cloaking
                from networksecurity.utils.whitelist_manager import whitelist_manager
                is_trusted = whitelist_manager.is_whitelisted(url)

                if not is_trusted and initial_domain != final_domain and len(final_domain) > 0:
                    results["detected_cloaking"] = True
                
                await browser.close()
        except Exception as e:
            results["status"] = "failed"
            results["error"] = str(e)

        return results

def run_dynamic_scan(url):
    """Sync wrapper for the async scanner."""
    scanner = DynamicScanner()
    return asyncio.run(scanner.scan_url(url))
