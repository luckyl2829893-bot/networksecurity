import pandas as pd
import os
from urllib.parse import urlparse

class WhitelistManager:
    def __init__(self, whitelist_path="Network_data/top-1m.csv", top_n=100000):
        # Resolve path relative to project root (assuming this file is in networksecurity/utils/)
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.whitelist_path = os.path.join(base_dir, whitelist_path)
        self.top_n = top_n
        self.whitelist = set()
        self._load_whitelist()

    def _load_whitelist(self):
        """Loads the top N domains from the Tranco CSV."""
        if not os.path.exists(self.whitelist_path):
            print(f"--- [Whitelist Warning] {self.whitelist_path} not found. Skipping whitelist. ---")
            return

        try:
            # The CSV has format: rank,domain
            df = pd.read_csv(self.whitelist_path, header=None, nrows=self.top_n)
            self.whitelist = set(df[1].astype(str).str.lower().tolist())
            print(f"--- [Whitelist] Loaded {len(self.whitelist)} trusted domains. ---")
        except Exception as e:
            print(f"--- [Whitelist Error] Failed to load whitelist: {e} ---")

    def is_whitelisted(self, url):
        """Checks if the domain of the given URL is in the whitelist."""
        try:
            domain = urlparse(url).netloc.lower()
            if not domain:
                domain = url.split('/')[0].lower() # Fallback for raw domains
            
            # Remove 'www.' prefix for consistency
            if domain.startswith("www."):
                domain = domain[4:]
                
            return domain in self.whitelist
        except:
            return False

# Singleton instance for easy access
whitelist_manager = WhitelistManager()
