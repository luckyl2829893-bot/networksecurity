import os
import sys
import pandas as pd
import numpy as np
import concurrent.futures
from tqdm import tqdm
from sklearn.metrics import accuracy_score, f1_score
from scripts.ablation_study import evaluate_url, load_object, FeatureExtractor, calculate_heuristic_score, whitelist_manager

def run_optimization_experiment():
    print("="*70)
    print("   EXPERIMENT: SYSTEMATIC ENSEMBLE WEIGHT OPTIMIZATION")
    print("="*70)
    
    # 1. Load Model
    model = load_object("final_model/model.pkl")
    
    # 2. Sample a DEDICATED Validation Set (2000 URLs)
    print("Step 1: Sampling 2000 URLs for Weight Tuning...")
    df_phish = pd.read_csv("Network_data/verified_online.csv").sample(1000)
    df_safe = pd.read_csv("Network_data/top-1m.csv", header=None).sample(1000)
    tasks = [(u, 1) for u in df_phish['url']] + [(u, 0) for u in df_safe[1]]
    np.random.shuffle(tasks)

    # 3. Extract Raw Scores (ML Prob & Heuristic Score)
    print("Step 2: Extracting base probabilities for all URLs...")
    
    raw_results = []
    
    def get_raw_scores(task):
        url, label = task
        # ML Prob
        try:
            extractor = FeatureExtractor(url)
            features = np.array(extractor.extract_features()).reshape(1, -1)
            prob_safe = model.predict_proba(features)[0][1] 
            p_ml = 1.0 - prob_safe 
        except:
            p_ml = 0.5
            
        # Heuristic Prob
        s_data = calculate_heuristic_score(url, "url")
        p_heur = min(s_data["score"] / 50.0, 1.0)
        
        # Whitelist
        is_whitelisted = whitelist_manager.is_whitelisted(url)
        
        return p_ml, p_heur, is_whitelisted, label

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        raw_results = list(tqdm(ex.map(get_raw_scores, tasks), total=len(tasks)))

    # 4. Test Combinations
    combinations = [
        (0.5, 0.5), (0.6, 0.4), (0.7, 0.3), (0.8, 0.2), (0.9, 0.1)
    ]
    
    report = []
    
    for w_ml, w_heur in combinations:
        preds = []
        labels = []
        for p_ml, p_heur, white, label in raw_results:
            prob = (w_ml * p_ml) + (w_heur * p_heur)
            if white: prob *= 0.2
            
            preds.append(1 if prob >= 0.5 else 0)
            labels.append(label)
        
        acc = accuracy_score(labels, preds)
        f1 = f1_score(labels, preds)
        report.append({
            "Weights (ML/Heur)": f"{int(w_ml*100)}/{int(w_heur*100)}",
            "Accuracy": acc,
            "F1-Score": f1
        })

    # 5. Output Table
    df_report = pd.DataFrame(report)
    print("\n" + "="*50)
    print("         OPTIMIZATION RESULTS TABLE")
    print("="*50)
    print(df_report.to_string(index=False))
    print("="*50)
    
    best_row = df_report.loc[df_report['Accuracy'].idxmax()]
    print(f"\nOPTIMAL CONFIGURATION: {best_row['Weights (ML/Heur)']} Split")
    print(f"Max Validation Accuracy: {best_row['Accuracy']:.4f}")

if __name__ == "__main__":
    run_optimization_experiment()
