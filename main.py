from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from transformers import pipeline

app = FastAPI()

# 1. Initialize the AI Model (Zero-Shot Classifier)
# This model can classify text into ANY category without extra training
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

class EmailPayload(BaseModel):
    text: str

@app.post("/analyze")
async def analyze_email(payload: EmailPayload):
    # We ask the AI to check the text against these specific "Security Labels"
    candidate_labels = ["phishing attempt", "urgent financial request", "safe professional email", "spam"]
    
    result = classifier(payload.text, candidate_labels)
    
    # Extract the top result
    top_label = result['labels'][0]
    confidence = result['scores'][0] * 100

    # Logic for Verdict
    if top_label in ["phishing attempt", "urgent financial request"] and confidence > 60:
        verdict = "MALICIOUS"
    elif confidence < 50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "verdict": verdict,
        "ai_label": top_label,
        "confidence": f"{confidence:.2f}%",
        "analysis": "AI detected signs of " + top_label
    }

app.mount("/", StaticFiles(directory="static", html=True), name="static")
