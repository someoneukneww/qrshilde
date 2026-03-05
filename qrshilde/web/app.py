from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from qrshilde.src.ai.analyzer import analyze_qr_payload

# Load .env from project root
ROOT_DIR = Path(__file__).resolve().parents[3]
ENV_PATH = ROOT_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH, override=False)

app = FastAPI(title="QrShilde - QR Secure (Rules + ML)", version="1.0.0")

# Optional dashboard (you already have templates/dashboard.html)
TEMPLATES_DIR = ROOT_DIR / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Serve static (you already have /static)
STATIC_DIR = ROOT_DIR / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class AnalyzeRequest(BaseModel):
    payload: str
    report_id: str | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    # If template missing, return simple HTML
    if not (TEMPLATES_DIR / "dashboard.html").exists():
        return HTMLResponse(
            "<h2>QrShilde</h2><p>POST /api/analyze with JSON {payload}</p>"
        )
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.post("/api/analyze")
async def api_analyze(req: AnalyzeRequest):
    payload = (req.payload or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="payload is required")

    result = await analyze_qr_payload(payload=payload, report_id=req.report_id or "")
    return result


@app.get("/debug")
def debug():
    ml_path = Path(__file__).resolve().parents[1] / "ml" / "url_model.pkl"
    return {
        "cwd": str(Path.cwd()),
        "env_path": str(ENV_PATH),
        "env_exists": ENV_PATH.exists(),
        "ml_model_exists": ml_path.exists(),
    }