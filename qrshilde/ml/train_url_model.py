import os, json, datetime
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from xgboost import XGBClassifier

from qrshilde.src.ml.url_features import extract_url_features
from qrshilde.src.ml.url_model import MODEL_PATH


DATA_PATH = os.path.join("data", "malicious_phish_Dataset.csv")
META_PATH = os.path.join(os.path.dirname(MODEL_PATH), "url_model_meta.json")


def _metrics_from_threshold(y_true, y_prob, thr: float):
    y_pred = (y_prob >= thr).astype(int)
    return {
        "threshold": float(thr),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def _tune_threshold_f1(y_true, y_prob):
    # scan thresholds for best F1 (simple + effective)
    best_thr = 0.5
    best_f1 = -1.0
    for thr in np.linspace(0.05, 0.95, 19):
        m = _metrics_from_threshold(y_true, y_prob, thr)
        if m["f1"] > best_f1:
            best_f1 = m["f1"]
            best_thr = thr
    return float(best_thr), float(best_f1)


def main():
    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    df = df[["url", "type"]].dropna()
    df["url"] = df["url"].astype(str)
    df["type"] = df["type"].astype(str).str.lower()

    # benign=0, anything else=1
    y = df["type"].map(lambda v: 0 if v == "benign" else 1).astype(int).to_numpy()

    X_list = []
    for u in df["url"].tolist():
        feats, _ = extract_url_features(u)
        X_list.append(feats)
    X = np.array(X_list, dtype=np.float32)

    # Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Handle imbalance: scale_pos_weight = negative / positive
    pos = max(int((y_train == 1).sum()), 1)
    neg = max(int((y_train == 0).sum()), 1)
    scale_pos_weight = neg / pos

    model = XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        min_child_weight=1.0,
        gamma=0.0,
        eval_metric="logloss",
        n_jobs=-1,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
    )

    model.fit(X_train, y_train)

    # probabilities
    y_prob = model.predict_proba(X_test)[:, 1]

    # default thr=0.5 metrics
    default_metrics = _metrics_from_threshold(y_test, y_prob, 0.5)

    # tune threshold for best F1
    best_thr, best_f1 = _tune_threshold_f1(y_test, y_prob)
    tuned_metrics = _metrics_from_threshold(y_test, y_prob, best_thr)

    joblib.dump(model, MODEL_PATH)

    meta = {
        "trained_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": os.path.abspath(DATA_PATH),
        "rows": int(len(df)),
        "label_mapping": {"benign": 0, "other": 1},
        "imbalance": {"pos": pos, "neg": neg, "scale_pos_weight": float(scale_pos_weight)},
        "metrics_default_thr_0_5": default_metrics,
        "metrics_tuned_best_f1": tuned_metrics,
        "suggested_threshold": float(best_thr),
        "notes": "Set URL_MAL_THRESHOLD env var to suggested_threshold for best F1 (or tune for recall if you prefer).",
    }

    with open(META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Trained and saved model: {MODEL_PATH}")
    print(f"[+] Saved meta: {META_PATH}")
    print("[+] Default thr=0.5:", default_metrics)
    print("[+] Tuned best F1:", tuned_metrics)
    print(f"[+] Suggested threshold: {best_thr:.2f}")


if __name__ == "__main__":
    main()