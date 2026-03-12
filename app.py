import os
import sys
import pandas as pd

from fastapi import FastAPI, File, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import uvicorn
from dotenv import load_dotenv

# Load environment variables (Localhost support)
load_dotenv()

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.templating import Jinja2Templates
from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.search_utils import identify_input_type, calculate_risk_score, calculate_heuristic_score
from networksecurity.utils.advanced_analysis import (
    analyze_form_targets, 
    get_domain_age_risk,
    analyze_open_redirects,
    check_subdomain_takeover
)
from networksecurity.utils.ai_agent import get_ai_agent_response


try:
    from pymongo import MongoClient
    mongo_db_url = os.getenv("MONGO_DB_URL")
    if mongo_db_url:
        client = MongoClient(mongo_db_url)
        search_db = client["PhishingDetectionDB"]
    else:
        search_db = None
except Exception as e:
    search_db = None
    logging.error(f"MongoDB connection failed: {e}")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["authentication"])
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/train")
async def train_route():
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)

@app.get("/search")
async def search_route(request: Request, query: str):
    try:
        query = query.strip()
        if not query:
            return templates.TemplateResponse("index.html", {"request": request, "error": "Please enter a query"})

        input_type = identify_input_type(query)
        results = {}
        
        if search_db:
            if input_type == "ip":
                ip_doc = search_db["ips"].find_one({"ip": query})
                if ip_doc:
                    results["ips"] = ip_doc
            elif input_type == "domain":
                domain_doc = search_db["domains"].find_one({"domain": query})
                if domain_doc:
                    results["domains"] = domain_doc
            elif input_type == "url":
                phishing_doc = search_db["phishing_links"].find_one({"url": query})
                if phishing_doc:
                    results["phishing_link"] = phishing_doc
                combined_doc = search_db["combined_urls"].find_one({"url": query})
                if combined_doc:
                    results["combined_urls"] = combined_doc
        else:
             logging.warning("Skipping database search as database client is not initialized.")

        db_score = calculate_risk_score(results)
        heuristic_data = calculate_heuristic_score(query, input_type)
        heuristic_score = heuristic_data["score"]
        heuristic_reasons = heuristic_data["reasons"]

        if input_type == "url":
            form_analysis = analyze_form_targets(query)
            if form_analysis["detected"]:
                heuristic_score += 100
                heuristic_reasons.extend(form_analysis["details"])
        
        domain_str = query
        if input_type == "url":
            from urllib.parse import urlparse
            domain_str = urlparse(query).netloc
            
        whois_data = get_domain_age_risk(domain_str)
        if whois_data["is_new"]:
            heuristic_score += 50
            heuristic_reasons.extend(whois_data["details"])
            
        redirect_analysis = analyze_open_redirects(query)
        if redirect_analysis["detected"]:
            heuristic_score += 40
            heuristic_reasons.extend(redirect_analysis["details"])
            
        subdomain_analysis = check_subdomain_takeover(domain_str)
        if subdomain_analysis["detected"]:
            heuristic_score += 70
            heuristic_reasons.extend(subdomain_analysis["details"])
        
        total_risk_score = min(db_score + heuristic_score, 100)
        
        # AI Agent Report (Grok-style)
        security_brief = get_ai_agent_response(query, input_type, total_risk_score, heuristic_reasons, results)
        
        # UI Confidence Level
        confidence = 100 - (total_risk_score // 5) if total_risk_score < 50 else 95
        
        # Check if real LLM is active
        llm_mode = bool(os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY"))
        
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "query": query, 
            "input_type": input_type,
            "risk_score": total_risk_score,
            "results": results,
            "heuristic_reasons": heuristic_reasons,
            "security_brief": security_brief,
            "confidence": confidence,
            "llm_mode": llm_mode
        })

    except Exception as e:
        logging.error(f"Search Error: {e}")
        return templates.TemplateResponse("index.html", {"request": request, "error": "An error occurred during search"})
    
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        final_model_dir='final_model'
        network_model = NetworkModel(model_dir=final_model_dir)
        y_pred = network_model.predict(df)
        df['predicted_column'] = y_pred
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        return Response(table_html)
    except Exception as e:
        raise NetworkSecurityException(e,sys)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
