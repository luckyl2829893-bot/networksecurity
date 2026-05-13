import os
import sys
import pandas as pd
import numpy as np
import concurrent.futures
from tqdm import tqdm

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from networksecurity.utils.feature_extractor import FeatureExtractor

def extract_for_url(args):
    url, label = args
    ext = FeatureExtractor(url)
    features = ext.extract_features()
    features.append(label)
    return features

def build_dataset():
    print("Building Real-World Dataset (2,000 URLs) using Multithreading...")
    
    df_phish = pd.read_csv("Network_data/verified_online.csv").head(1000)
    urls_phish = df_phish['url'].tolist()
    
    df_safe = pd.read_csv("Network_data/top-1m.csv", header=None).head(1000)
    urls_safe = ["http://" + str(d) for d in df_safe[1].tolist()]
    
    # Create tuples of (url, label)
    # -1 for Phishing, 1 for Safe
    tasks = [(u, -1) for u in urls_phish] + [(u, 1) for u in urls_safe]
    
    dataset = []
    print(f"Extracting features for {len(tasks)} URLs with 50 parallel workers...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Use list to force execution and keep order doesn't matter for dataset
        results = list(tqdm(executor.map(extract_for_url, tasks), total=len(tasks)))
        
    dataset = [r for r in results if r is not None]
        
    columns = [
        "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol","double_slash_redirecting",
        "Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registeration_length","Favicon",
        "port","HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email",
        "Abnormal_URL","Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report","Result"
    ]
    
    df_real = pd.DataFrame(dataset, columns=columns)
    
    out_path = "Network_data/real_phishing_data.csv"
    df_real.to_csv(out_path, index=False)
    print(f"\nDataset built and saved to {out_path} with {len(df_real)} rows.")

if __name__ == "__main__":
    build_dataset()
