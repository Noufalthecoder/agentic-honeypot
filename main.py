import re
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Header, HTTPException, status, Depends
from pydantic import BaseModel, Field

app = FastAPI(title="Agentic Honeypot API")

# --- Configuration ---
API_KEY_VALUE = "AIIHB-2026-SECRET"
API_KEY_NAME = "x-api-key"

# --- Models ---

class HoneypotRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None

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
    
    # UPI ID Regex: Matches standard UPI patterns (e.g., user@bank, phone@upi)
    # Basic loose pattern to catch most handles
    upi_pattern = r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}'
    upi_ids = list(set(re.findall(upi_pattern, text)))

    # Bank Account Regex: 9 to 18 digits. 
    # Using \b to ensure we don't cut numbers from larger strings, but simplistic enough.
    # We filter out items that might look like phone numbers if they are strictly 10 digits starting with 6-9 usually,
    # but requirement just says 9-18 digits, so we stick to that strictly.
    bank_account_pattern = r'\b\d{9,18}\b'
    bank_accounts = list(set(re.findall(bank_account_pattern, text)))

    # Phishing URL Regex: Standard http/https URL extraction
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w._~:/?#[\]@!$&\'()*+,;=]*)?'
    # Also simple www matches if needed, but sticking to http/s for safer "phishing" assumption
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
    
    # 1. Keyword presence
    if keyword_hits > 0:
        score += 0.3 + (min(keyword_hits, 5) * 0.1) # Up to 0.8 from keywords
    
    # 2. Presence of extracted entities (scams often ask to pay or click)
    if extracted_data["phishing_links"]:
        score += 0.4
    if extracted_data["upi_ids"] or extracted_data["bank_accounts"]:
        score += 0.3
        
    confidence = min(score, 1.0)
    is_scam = confidence > 0.4 # Threshold
    
    # Edge case: minimal text with no keywords or entities might just be low confidence
    if not text.strip():
        confidence = 0.0
        is_scam = False
        
    return is_scam, round(confidence, 2)

# --- Endpoints ---

@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest, 
    api_key: str = Depends(validate_api_key)
):
    extracted = extract_intelligence(request.message)
    is_scam, confidence = analyze_scam_intent(request.message, extracted)
    
    return HoneypotResponse(
        is_scam=is_scam,
        conversation_id=request.conversation_id,
        engagement_active=True, # Assuming honeypot is active and listening
        turns=1, # Hardcoded as requested to start with 1
        extracted_data=ExtractedData(
            upi_ids=extracted["upi_ids"],
            bank_accounts=extracted["bank_accounts"],
            phishing_links=extracted["phishing_links"]
        ),
        confidence=confidence,
        status="analysis_complete"
    )

if __name__ == "__main__":
    import uvicorn
    # Local development run
    uvicorn.run(app, host="127.0.0.1", port=8000)
