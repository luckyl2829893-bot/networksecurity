import os
import sys
import pandas as pd
import pymongo
from dotenv import load_dotenv
import certifi
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

# Load environment variables
load_dotenv()
MONGO_DB_URL = os.getenv("MONGO_DB_URL")
ca = certifi.where()

# Define file paths and target collections
DATA_FILES = {
    "ips": "Network_data/balanced_ips.csv",
    "domains": "Network_data/domaindata.csv",
    "phishing_links": "Network_data/phishing_link.csv",
    "combined_urls": "Network_data/combined_phishing_data_urls.csv"
}

DATABASE_NAME = "PhishingDetectionDB"

def ingest_data():
    """
    Reads CSV files and ingests them into MongoDB collections.
    Creates indexes on search fields for performance.
    """
    try:
        print(f"Connecting to MongoDB: {DATABASE_NAME}...")
        client = pymongo.MongoClient(MONGO_DB_URL, tlsCAFile=ca)
        db = client[DATABASE_NAME]
        
        for collection_name, file_path in DATA_FILES.items():
            if not os.path.exists(file_path):
                print(f"Warning: File not found: {file_path}")
                continue
                
            print(f"Processing {file_path} -> Collection: {collection_name}...")
            logging.info(f"Ingesting {file_path} into {collection_name}...")
            
            # Read CSV
            try:
                df = pd.read_csv(file_path)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")
                continue

            # Convert to dictionary records
            records = df.to_dict(orient='records')
            
            collection = db[collection_name]
            
            # Clear existing data to ensure clean state
            collection.drop()
            
            if records:
                # Insert data
                collection.insert_many(records)
                print(f"Successfully inserted {len(records)} records into '{collection_name}'.")
                
                # Create Index based on collection type
                if collection_name == "ips":
                    collection.create_index("ip")
                    print("Created index on 'ip'")
                elif collection_name == "domains":
                    collection.create_index("domain")
                    print("Created index on 'domain'")
                elif collection_name in ["phishing_links", "combined_urls"]:
                    collection.create_index("url")
                    print("Created index on 'url'")
            else:
                print(f"No records found in {file_path}")
                
        print("\nData Ingestion Completed Successfully!")

    except Exception as e:
        logging.error(f"Data Ingestion Failed: {str(e)}")
        raise NetworkSecurityException(e, sys)

if __name__ == "__main__":
    ingest_data()
