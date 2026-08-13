"""
Full Evaluation Script - Runs all 4 tests and prints clean results for the methodology section.
Run from the project root directory.
Command:  python run_full_eval.py
"""

import os, sys, pickle, warnings
import numpy as np
warnings.filterwarnings("ignore")

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

# ─────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────
MODEL_PATH       = os.path.join(PROJECT_DIR, "final_model", "model.pkl")
TRAIN_ARR_PATH   = os.path.join(PROJECT_DIR, "Artifacts", "05_19_2026_14_32_30", "data_transformation", "transformed", "train.npy")
TEST_ARR_PATH    = os.path.join(PROJECT_DIR, "Artifacts", "05_19_2026_14_32_30", "data_transformation", "transformed", "test.npy")

SEPARATOR = "=" * 65

def header(title):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)

# ─────────────────────────────────────────────
# TEST 1 & 2: Model metrics + CV info
# ─────────────────────────────────────────────
header("TEST 1 & 2 — Model Metrics + CV Info")

try:
    from sklearn.metrics import (
        f1_score, accuracy_score, precision_score, recall_score,
        confusion_matrix, classification_report
    )
    from sklearn.model_selection import cross_val_score

    # Load model
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)

    print(f"\n✅ Model loaded: {type(model).__name__}")

    # Load arrays
    train_arr = np.load(TRAIN_ARR_PATH)
    test_arr  = np.load(TEST_ARR_PATH)

    X_train, y_train = train_arr[:, :-1], train_arr[:, -1]
    X_test,  y_test  = test_arr[:, :-1],  test_arr[:, -1]

    print(f"   Train samples: {X_train.shape[0]}  |  Test samples: {X_test.shape[0]}")
    print(f"   Features: {X_train.shape[1]}")

    # Predictions
    y_train_pred = model.predict(X_train)
    y_test_pred  = model.predict(X_test)

    # Metrics
    train_f1   = f1_score(y_train, y_train_pred)
    test_f1    = f1_score(y_test,  y_test_pred)
    train_acc  = accuracy_score(y_train, y_train_pred)
    test_acc   = accuracy_score(y_test,  y_test_pred)
    test_prec  = precision_score(y_test, y_test_pred)
    test_rec   = recall_score(y_test,  y_test_pred)

    print(f"\n{'─'*40}")
    print(f"  WINNING MODEL : {type(model).__name__}")
    print(f"{'─'*40}")
    print(f"  Train F1       : {train_f1:.4f}  ({train_f1*100:.2f}%)")
    print(f"  Test  F1       : {test_f1:.4f}  ({test_f1*100:.2f}%)")
    print(f"  Train Accuracy : {train_acc:.4f}  ({train_acc*100:.2f}%)")
    print(f"  Test  Accuracy : {test_acc:.4f}  ({test_acc*100:.2f}%)")
    print(f"  Test Precision : {test_prec:.4f}  ({test_prec*100:.2f}%)")
    print(f"  Test Recall    : {test_rec:.4f}  ({test_rec*100:.2f}%)")
    print(f"  Overfit gap F1 : {(train_f1 - test_f1)*100:.2f}%  (Train - Test)")

    # TEST 2: 5-Fold CV
    print(f"\n{'─'*40}")
    print(f"  5-FOLD CROSS-VALIDATION")
    print(f"{'─'*40}")
    print("  Running 5-fold CV on test set (may take 10-20s)...")
    cv_scores = cross_val_score(model, X_test, y_test, cv=5, scoring="f1")
    print(f"  CV F1 Scores   : {[round(s,4) for s in cv_scores]}")
    print(f"  Mean CV F1     : {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    
    # TEST 4: Confusion Matrix
    header("TEST 4 — Confusion Matrix")
    cm = confusion_matrix(y_test, y_test_pred)
    # Labels: -1 = phishing (negative class), 1 = legitimate (positive class)
    # confusion_matrix orders by sorted unique labels
    labels = sorted(np.unique(y_test))
    print(f"\n  Labels in data: {labels}")
    print(f"\n  Raw Confusion Matrix:")
    print(f"  {cm}")

    if len(labels) == 2:
        # Determine which label is "positive" (phishing = -1 or 1?)
        # In this dataset convention: -1 = phishing, 1 = legitimate
        # sklearn treats the HIGHER label as positive by default
        # So label 1 (legitimate) is "positive" in sklearn's view
        # We want: Phishing detected = TP for phishing class
        # Reframe: treat -1 (phishing) as the "positive" class for security reporting
        tn, fp, fn, tp = cm.ravel()  # sklearn order with labels sorted [-1, 1]
        # With sorted labels [-1, 1]:
        # cm[0,0] = true -1 predicted -1  = phishing correctly caught (TP for phishing)
        # cm[0,1] = true -1 predicted  1  = phishing missed (FN for phishing)  
        # cm[1,0] = true  1 predicted -1  = legit flagged as phishing (FP)
        # cm[1,1] = true  1 predicted  1  = legit correctly passed (TN)
        print(f"\n  ─── Security-oriented view (Phishing = Positive class) ───")
        print(f"  TP (Phishing correctly detected) : {cm[0,0]}")
        print(f"  FN (Phishing missed / false safe) : {cm[0,1]}")
        print(f"  FP (Legit flagged as phishing)   : {cm[1,0]}")
        print(f"  TN (Legit correctly passed)       : {cm[1,1]}")
        print(f"\n  ─── sklearn standard view ───")
        print(f"  TN={tn}  FP={fp}  FN={fn}  TP={tp}")
        
        total = cm.sum()
        print(f"\n  Total test samples : {total}")
        print(f"  Phishing samples   : {cm[0].sum()}")
        print(f"  Legitimate samples : {cm[1].sum()}")

    print(f"\n  Full Classification Report:")
    print(classification_report(y_test, y_test_pred, target_names=["Phishing(-1)", "Legitimate(1)"]))

except Exception as e:
    print(f"\n❌ Error in Test 1/2/4: {e}")
    import traceback; traceback.print_exc()


# ─────────────────────────────────────────────
# TEST 3: URL Risk Scores via Heuristic Engine
# ─────────────────────────────────────────────
header("TEST 3 — URL Risk Scores (Heuristic Engine)")

try:
    from networksecurity.utils.search_utils import (
        identify_input_type, calculate_heuristic_score, calculate_risk_score
    )

    test_urls = [
        ("google.com",               "Expect: 0–5%"),
        ("paypal.com",               "Expect: 0–10%"),
        ("paypa1.com",               "Expect: 70%+  (typosquat)"),
        ("bit.ly/test",              "Expect: 50%+  (shortener)"),
        ("apple.com",                "Expect: 0–5%"),
        ("secure-login.xyz",         "Expect: 40%+  (.xyz + keywords)"),
        ("verify-account-paypal.tk", "Expect: HIGH  (brand + .tk + keywords)"),
        ("192.168.1.1/login",        "Expect: HIGH  (IP + login keyword)"),
        ("http://faceb00k-verify.ru/signin", "Expect: VERY HIGH (brand spoof + .ru)"),
    ]

    print(f"\n  {'URL':<42} {'Type':<8} {'Score':>6}  {'Heuristic Reasons'}")
    print(f"  {'─'*42} {'─'*8} {'─'*6}  {'─'*35}")

    for url, expectation in test_urls:
        input_type     = identify_input_type(url)
        heuristic_data = calculate_heuristic_score(url, input_type)
        score          = min(heuristic_data["score"], 100)
        reasons        = heuristic_data["reasons"]
        short_reasons  = " | ".join(r.split("(")[0].strip() for r in reasons[:2])
        print(f"  {url:<42} {input_type:<8} {score:>5}%  {short_reasons}")

    print(f"\n  ── Detailed breakdown for key URLs ──")
    for url, expectation in test_urls[:6]:
        input_type     = identify_input_type(url)
        heuristic_data = calculate_heuristic_score(url, input_type)
        score          = min(heuristic_data["score"], 100)
        print(f"\n  URL: {url}  →  Score: {score}%  [{expectation}]")
        for r in heuristic_data["reasons"]:
            print(f"       • {r}")

except Exception as e:
    print(f"\n❌ Error in Test 3: {e}")
    import traceback; traceback.print_exc()


# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
header("SUMMARY — Copy these numbers for Methodology")
try:
    print(f"""
  Model         : {type(model).__name__}
  Train F1      : {train_f1*100:.2f}%
  Test  F1      : {test_f1*100:.2f}%
  Train Acc     : {train_acc*100:.2f}%
  Test  Acc     : {test_acc*100:.2f}%
  Precision     : {test_prec*100:.2f}%
  Recall        : {test_rec*100:.2f}%
  CV Mean F1    : {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%
  Overfit gap   : {(train_f1 - test_f1)*100:.2f}% (Train F1 - Test F1)
""")
except:
    print("  (Run the script fully to see summary)")

print(SEPARATOR + "\n")
