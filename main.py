import re
from typing import Optional, List, Dict, Any, Union
from fastapi import FastAPI, Header, HTTPException, status, Depends, Request
from pydantic import BaseModel
from json import JSONDecodeError

app = FastAPI(title="Agentic Honeypot API")

# --- Configuration ---
API_KEY_VALUE = "AIIHB-2026-SECRET"
API_KEY_NAME = "x-api-key"

# --- Models ---

class ExtractedData(BaseModel):
    upi_ids: List[str]
    bank_accounts: List[str]
    phishing_links: List[str]

class HoneypotResponse(BaseModel):
    is_scam: bool
    conversation_id: Optional[str]
    engagement_active: bool
    turns: int
    extracted_data: ExtractedData
    confidence: float
    status: str

# --- Logic ---

def validate_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """Validates the x-api-key header."""
    if x_api_key != API_KEY_VALUE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key"
        )
    return x_api_key

def extract_intelligence(text: str) -> Dict[str, list]:
    """Extracts UPIs, bank accounts, and URLs from the text using Regex."""
    
    # UPI ID Regex
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
    upi_ids = list(set(re.findall(upi_pattern, text)))

    # Bank Account Regex: 9 to 18 digits. 
    bank_account_pattern = r'\b\d{9,18}\b'
    bank_accounts = list(set(re.findall(bank_account_pattern, text)))

    # Phishing URL Regex
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&\'()*+,;=]*)?'
    phishing_links = list(set(re.findall(url_pattern, text)))

    return {
        "upi_ids": upi_ids,
        "bank_accounts": bank_accounts,
        "phishing_links": phishing_links
    }

def analyze_scam_intent(text: str, extracted_data: Dict[str, list]) -> tuple[bool, float]:
    """
    Detects scam intent based on keywords and presence of suspicious data.
    Returns (is_scam, confidence).
    """
    text_lower = text.lower()
    
    # Keywords often found in scam messages
    scam_keywords = [
        "urgent", "winner", "lottery", "congratulations", "won", "prize",
        "verify", "kyc", "blocked", "account", "expire", "otp", "password",
        "credential", "refund", "deposit", "investment", "scheme", "double",
        "click here", "limited time", "act now", "action required"
    ]
    
    keyword_hits = sum(1 for word in scam_keywords if word in text_lower)
    
    # Simple heuristics for confidence
    score = 0.0
    
    if keyword_hits > 0:
        score += 0.3 + (min(keyword_hits, 5) * 0.1)
    
    if extracted_data["phishing_links"]:
        score += 0.4
    if extracted_data["upi_ids"] or extracted_data["bank_accounts"]:
        score += 0.3
        
    confidence = min(score, 1.0)
    is_scam = confidence > 0.4
    
    if not text.strip():
        confidence = 0.0
        is_scam = False
        
    return is_scam, round(confidence, 2)

async def _process_request(request: Request) -> HoneypotResponse:
    """Shared logic for processing requests from any endpoint."""
    # Parse body manually to handle missing/empty body without 422
    try:
        body = await request.json()
    except (JSONDecodeError, Exception):
        # If parsing fails (e.g. empty body, invalid JSON), treat as empty input
        body = {}
    
    # Safely extract fields with defaults
    message = body.get("message", "")
    if not isinstance(message, str):
        message = str(message) if message is not None else ""
        
    conversation_id = body.get("conversation_id")
    if conversation_id is not None and not isinstance(conversation_id, str):
        conversation_id = str(conversation_id)

    # Core logic
    extracted = extract_intelligence(message)
    is_scam, confidence = analyze_scam_intent(message, extracted)
    
    return HoneypotResponse(
        is_scam=is_scam,
        conversation_id=conversation_id,
        engagement_active=True,
        turns=1,
        extracted_data=ExtractedData(
            upi_ids=extracted["upi_ids"],
            bank_accounts=extracted["bank_accounts"],
            phishing_links=extracted["phishing_links"]
        ),
        confidence=confidence,
        status="analysis_complete"
    )

# --- Endpoints ---

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: Request,
    api_key: str = Depends(validate_api_key)
):
    return await _process_request(request)

@app.post("/", response_model=HoneypotResponse)
async def root_endpoint(
    request: Request,
    api_key: str = Depends(validate_api_key)
):
    """Fallback endpoint for testers that hit root instead of /honeypot"""
    return await _process_request(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
