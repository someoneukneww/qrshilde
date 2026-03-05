import os
import joblib
from qrshilde.src.ml.url_features import extract_url_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "url_model.pkl")


def model_exists() -> bool:
    return os.path.exists(MODEL_PATH)


def _load_model():
    return joblib.load(MODEL_PATH)


def get_threshold() -> float:
    try:
        return float(os.getenv("URL_MAL_THRESHOLD", "0.31"))
    except Exception:
        return 0.31


def predict_url(url: str) -> dict:
    model = _load_model()
    feats, names = extract_url_features(url)

    # predict probability (class 1 = malicious/phishing)
    proba = model.predict_proba([feats])[0][1]
    p = float(proba)

    threshold = get_threshold()
    label = "phishing" if p >= threshold else "benign"

    # Explainability:
    reasons = []
    try:
        if hasattr(model, "coef_"):
            coefs = model.coef_[0]
            impacts = []
            for i, fname in enumerate(names):
                impacts.append((fname, float(coefs[i] * feats[i])))
            impacts.sort(key=lambda x: abs(x[1]), reverse=True)
            reasons = [{"feature": f, "impact": v} for f, v in impacts[:5]]
        elif hasattr(model, "feature_importances_"):
            imps = list(getattr(model, "feature_importances_", []))
            pairs = [(names[i], float(imps[i])) for i in range(min(len(names), len(imps)))]
            pairs.sort(key=lambda x: x[1], reverse=True)
            reasons = [{"feature": f, "impact": v} for f, v in pairs[:5]]
    except Exception:
        reasons = []

    return {
        "phishing_probability": p,
        "threshold": threshold,
        "label": label,
        "reasons": reasons,
    }