import sys
import os

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGO_DB_URL")
print(mongo_db_url)
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile,Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.search_utils import identify_input_type, calculate_risk_score, calculate_heuristic_score


client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from networksecurity.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

# Search Database Connection
SEARCH_DB_NAME = "PhishingDetectionDB"
search_db = client[SEARCH_DB_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)

@app.get("/search")
async def search_route(request: Request, query: str):
    try:
        if not query:
            return templates.TemplateResponse("index.html", {"request": request, "error": "Please enter a query"})

        input_type = identify_input_type(query)
        results = {}
        
        # Query Collections based on input type or check all relevant ones
        # For simplicity and "Universal Search", we check relevant collections
        
        if input_type == "ip":
            # Check IPs
            ip_doc = search_db["ips"].find_one({"ip": query})
            if ip_doc:
                results["ips"] = ip_doc
                
        elif input_type == "domain":
            # Check Domains
            domain_doc = search_db["domains"].find_one({"domain": query})
            if domain_doc:
                results["domains"] = domain_doc
                
        elif input_type == "url":
            # Check URLs
            # Exact match for now
            phishing_doc = search_db["phishing_links"].find_one({"url": query})
            if phishing_doc:
                results["phishing_link"] = phishing_doc
                
            combined_doc = search_db["combined_urls"].find_one({"url": query})
            if combined_doc:
                results["combined_urls"] = combined_doc

        # Calculate Database Risk Score
        db_score = calculate_risk_score(results)
        
        # Calculate Heuristic Score (Pattern Matching)
        heuristic_data = calculate_heuristic_score(query, input_type)
        heuristic_score = heuristic_data["score"]
        heuristic_reasons = heuristic_data["reasons"]
        
        # Total Risk Score
        total_risk_score = min(db_score + heuristic_score, 100)
        
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "query": query, 
            "input_type": input_type,
            "risk_score": total_risk_score,
            "results": results,
            "heuristic_reasons": heuristic_reasons
        })

    except Exception as e:
        # Log error but return page with error message
        logging.error(f"Search Error: {e}")
        return templates.TemplateResponse("index.html", {"request": request, "error": "An error occurred during search"})
    
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        #print(df)
        preprocesor=load_object("final_model/preprocessor.pkl")
        final_model=load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df['predicted_column'] = y_pred
        print(df['predicted_column'])
        #df['predicted_column'].replace(-1, 0)
        #return df.to_json()
        os.makedirs("prediction_output", exist_ok=True)
        df.to_csv("prediction_output/output.csv", index=False)
        table_html = df.to_html(classes='table table-striped')
        #print(table_html)
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        
    except Exception as e:
            raise NetworkSecurityException(e,sys)

    
if __name__=="__main__":
    app_run(app,host="0.0.0.0",port=8000)
