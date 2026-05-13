import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, KFold
from sklearn.metrics import accuracy_score, f1_score, precision_score
from scripts.ablation_study import evaluate_url, load_object
import concurrent.futures
from tqdm import tqdm

def verify():
    print("="*85)
    print("   SAFE-SURF: COMPREHENSIVE ABLATION & VALIDATION MATRIX (IEEE READY)")
    print("="*85)
    
    # 1. Load Model
    try:
        model_obj = load_object("final_model/model.pkl")
        from scripts import ablation_study
        ablation_study.model = model_obj
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    # 2. Randomized Sampling
    print("Step 1: Sampling 2000 fresh URLs from master datasets...")
    df_phish = pd.read_csv("Network_data/verified_online.csv").sample(1000)
    df_safe = pd.read_csv("Network_data/top-1m.csv", header=None).sample(1000)
    tasks = [(u, 1) for u in df_phish['url']] + [(u, 0) for u in df_safe[1]]
    np.random.shuffle(tasks)

    # 3. Process URLs (Full Pipeline)
    print(f"Step 2: Running {len(tasks)} URLs through all 4 layers...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(tqdm(executor.map(evaluate_url, tasks), total=len(tasks)))
    
    df = pd.DataFrame(results)

    # --- COMPARATIVE ANALYSIS ---
    layers = ["ml", "heur", "combined", "agent"]
    layer_names = ["Layer 1: ML Only", "Layer 2: Heuristics", "Layer 3: Combined", "Layer 4: AI Agent"]
    
    # 1. Standard Split (80/20)
    test_size = int(0.2 * len(df))
    df_test = df.tail(test_size)
    
    # 2. 5-Fold CV
    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    
    print("\n" + "="*85)
    print(f"{'ABLATION LAYER':<25} | {'STANDARD SPLIT (ACC)':<25} | {'K-FOLD (MEAN +/- SD)':<25}")
    print("-" * 85)
    
    for i, l in enumerate(layers):
        # Standard Accuracy
        std_acc = accuracy_score(df_test['label'], df_test[l])
        
        # K-Fold Accuracy
        kf_accs = []
        for _, test_idx in kf.split(df):
            fold = df.iloc[test_idx]
            kf_accs.append(accuracy_score(fold['label'], fold[l]))
        
        kf_mean = np.mean(kf_accs)
        kf_std = np.std(kf_accs)
        
        kf_str = f"{kf_mean:.4f} (+/- {kf_std:.4f})"
        print(f"{layer_names[i]:<25} | {std_acc:.4f}                    | {kf_str:<25}")

    print("="*85)
    
    # Audit Log
    audit_path = "prediction_output/verification_audit.csv"
    df['url'] = [t[0] for t in tasks]
    df[['url', 'label', 'ml', 'heur', 'combined', 'agent']].to_csv(audit_path, index=False)
    
    print(f"\nAUDIT SUCCESS: Raw prediction data saved to: {audit_path}")
    print("Open this file to see why each layer made its decision.")

if __name__ == "__main__":
    verify()
