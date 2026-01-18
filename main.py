from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from transformers import pipeline

app = FastAPI()

# 1. LOAD THE LLM (Neural Engine)
# We use a 'Zero-Shot' model that knows security concepts out of the box.
# 'cross-encoder/ms-marco-TinyBERT-L-2-v2' is fast and lightweight.
print("Loading Neural Engine... Please wait.")
classifier = pipeline("zero-shot-classification", model="cross-encoder/ms-marco-TinyBERT-L-2-v2")

class EmailInput(BaseModel):
    content: str

@app.post("/analyze")
async def analyze_email(data: EmailInput):
    # The AI will weigh the text against these security-focused labels
    labels = ["safe professional email", "phishing scam", "urgent account threat", "spam"]
    
    # AI Analysis Phase
    output = classifier(data.content, labels)
    
    top_label = output['labels'][0]
    confidence = output['scores'][0] * 100
    
    # Determine the Verdict based on AI Reasoning
    if top_label in ["phishing scam", "urgent account threat"] and confidence > 55:
        verdict = "MALICIOUS"
        color = "#ef4444" # Red
    elif confidence < 50:
        verdict = "SUSPICIOUS"
        color = "#f59e0b" # Amber
    else:
        verdict = "SAFE"
        color = "#10b981" # Green

    return {
        "verdict": verdict,
        "score": round(confidence, 1),
        "ai_logic": f"AI classified this as a '{top_label}' with {confidence:.1f}% confidence.",
        "color": color
    }

# Mount the frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
