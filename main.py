from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests
import re

app = FastAPI(title="Sentinel AI Engine")

# Security: Allow the frontend to talk to the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    body: str
    url: str

@app.post("/api/scan")
async def perform_scan(data: ScanRequest, x_vt_key: str = Header(None)):
    if not x_vt_key or x_vt_key == "null":
        return {"verdict": "ERROR", "alerts": ["API Key Missing. Check Settings."]}

    score = 0
    logs = []

    # Layer 1: Heuristics (Urgency/Threats)
    triggers = ["verify", "urgent", "suspended", "security alert", "password reset"]
    if any(word in data.body.lower() for word in triggers):
        score += 30
        logs.append("Detected psychological pressure tactics.")

    # Layer 2: VirusTotal Real-Time Intel
    if data.url:
        try:
            url_id = requests.utils.quote(data.url, safe='')
            vt_resp = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": x_vt_key}
            )
            if vt_resp.status_code == 200:
                stats = vt_resp.json()['data']['attributes']['last_analysis_stats']
                malicious_count = stats.get('malicious', 0)
                if malicious_count > 0:
                    score += 60
                    logs.append(f"Blacklist: URL flagged by {malicious_count} security engines.")
        except Exception:
            logs.append("Global intel scan timed out.")

    verdict = "CRITICAL" if score >= 70 else "WARNING" if score >= 30 else "SECURE"
    return {"verdict": verdict, "score": min(score, 100), "alerts": logs}

# Mount the frontend folder
app.mount("/", StaticFiles(directory="static", html=True), name="static")
