import os
import datetime

from qrshilde.src.ml.url_model import MODEL_PATH, model_exists


def get_ml_status() -> dict:
    status = {
        "url_model": {
            "exists": model_exists(),
            "path": MODEL_PATH,
            "last_modified": None,
        },
        "versions": {}
    }

    if status["url_model"]["exists"]:
        ts = os.path.getmtime(MODEL_PATH)
        status["url_model"]["last_modified"] = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    # Try to fetch versions safely
    try:
        import sklearn
        status["versions"]["scikit-learn"] = getattr(sklearn, "__version__", None)
    except Exception:
        status["versions"]["scikit-learn"] = None

    try:
        import pandas as pd
        status["versions"]["pandas"] = getattr(pd, "__version__", None)
    except Exception:
        status["versions"]["pandas"] = None

    try:
        import joblib
        status["versions"]["joblib"] = getattr(joblib, "__version__", None)
    except Exception:
        status["versions"]["joblib"] = None

    try:
        import google.genai  # noqa: F401
        # google.genai doesn't always expose __version__ reliably
        status["versions"]["google-genai"] = "installed"
    except Exception:
        status["versions"]["google-genai"] = None

    return status