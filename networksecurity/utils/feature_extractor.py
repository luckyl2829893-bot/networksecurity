import re
import socket
import urllib.request
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import whois
from datetime import datetime

class FeatureExtractor:
    def __init__(self, url):
        self.url = url
        if not self.url.startswith(('http://', 'https://')):
            self.url = 'http://' + self.url
        self.domain = urlparse(self.url).netloc
        try:
            self.response = urllib.request.urlopen(self.url, timeout=3)
            self.soup = BeautifulSoup(self.response.read(), 'html.parser')
        except:
            self.response = None
            self.soup = None

    def having_IP_Address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.domain)
        return -1 if match else 1

    def URL_Length(self):
        if len(self.url) < 54: return 1
        if 54 <= len(self.url) <= 75: return 0
        return -1

    def Shortining_Service(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net', self.domain)
        return -1 if match else 1

    def having_At_Symbol(self):
        return -1 if "@" in self.url else 1

    def double_slash_redirecting(self):
        pos = self.url.rfind('//')
        return -1 if pos > 7 else 1

    def Prefix_Suffix(self):
        return -1 if '-' in self.domain else 1

    def having_Sub_Domain(self):
        # Clean www
        dom = self.domain.replace("www.", "")
        count = dom.count('.')
        if count == 1: return 1
        elif count == 2: return 0
        return -1

    def SSLfinal_State(self):
        return 1 if self.url.startswith("https") else -1

    def Domain_registeration_length(self):
        # Mapped to 1 as placeholder for speed in ablation, doing WHOIS for 500 URLs is slow.
        return 1

    def Favicon(self):
        return 1

    def port(self):
        return 1

    def HTTPS_token(self):
        return -1 if 'https' in self.domain else 1

    def Request_URL(self):
        return 1

    def URL_of_Anchor(self):
        return 1

    def Links_in_tags(self):
        return 1

    def SFH(self):
        return 1

    def Submitting_to_email(self):
        return -1 if self.soup and "mailto:" in str(self.soup) else 1

    def Abnormal_URL(self):
        return 1

    def Redirect(self):
        return 1

    def on_mouseover(self):
        return 1

    def RightClick(self):
        return 1

    def popUpWidnow(self):
        return 1

    def Iframe(self):
        return -1 if self.soup and self.soup.find_all('iframe') else 1

    def age_of_domain(self):
        return 1

    def DNSRecord(self):
        return 1

    def web_traffic(self):
        return 1

    def Page_Rank(self):
        return 1

    def Google_Index(self):
        return 1

    def Links_pointing_to_page(self):
        return 1

    def Statistical_report(self):
        return 1

    def extract_features(self):
        return [
            self.having_IP_Address(),
            self.URL_Length(),
            self.Shortining_Service(),
            self.having_At_Symbol(),
            self.double_slash_redirecting(),
            self.Prefix_Suffix(),
            self.having_Sub_Domain(),
            self.SSLfinal_State(),
            self.Domain_registeration_length(),
            self.Favicon(),
            self.port(),
            self.HTTPS_token(),
            self.Request_URL(),
            self.URL_of_Anchor(),
            self.Links_in_tags(),
            self.SFH(),
            self.Submitting_to_email(),
            self.Abnormal_URL(),
            self.Redirect(),
            self.on_mouseover(),
            self.RightClick(),
            self.popUpWidnow(),
            self.Iframe(),
            self.age_of_domain(),
            self.DNSRecord(),
            self.web_traffic(),
            self.Page_Rank(),
            self.Google_Index(),
            self.Links_pointing_to_page(),
            self.Statistical_report()
        ]
