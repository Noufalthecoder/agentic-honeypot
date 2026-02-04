import re
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Header, HTTPException, status, Depends, Request
from pydantic import BaseModel
from json import JSONDecodeError

app = FastAPI(title="Agentic Honeypot API")

# --- Configuration ---
API_KEY_VALUE = "AIIHB-2026-SECRET"

# --- Models ---
# Defined for response documentation, even if we build dicts manually
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
    """Validates the x-api-key header. Throws 401 if invalid."""
    if x_api_key != API_KEY_VALUE:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key"
        )
    return x_api_key

def extract_intelligence(text: str) -> Dict[str, list]:
    """Extracts UPIs, bank accounts, and URLs from the text using Regex."""
    if not text:
        return {"upi_ids": [], "bank_accounts": [], "phishing_links": []}

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
    """Returns (is_scam, confidence)."""
    if not text or not text.strip():
        return False, 0.0

    text_lower = text.lower()
    
    # Keywords
    scam_keywords = [
        "urgent", "winner", "lottery", "congratulations", "won", "prize",
        "verify", "kyc", "blocked", "account", "expire", "otp", "password",
        "credential", "refund", "deposit", "investment", "scheme", "double",
        "click here", "limited time", "act now", "action required"
    ]
    
    keyword_hits = sum(1 for word in scam_keywords if word in text_lower)
    score = 0.0
    
    if keyword_hits > 0:
        score += 0.3 + (min(keyword_hits, 5) * 0.1)
    
    if extracted_data.get("phishing_links"):
        score += 0.4
    if extracted_data.get("upi_ids") or extracted_data.get("bank_accounts"):
        score += 0.3
        
    confidence = min(score, 1.0)
    is_scam = confidence > 0.4
    
    return is_scam, round(confidence, 2)

# --- Universal Handler ---

async def universal_handler(request: Request, api_key: str = Depends(validate_api_key)):
    """
    Handles GET and POST for / and /honeypot.
    Returns 200 OK with proper JSON structure even if body is missing.
    """
    
    # Default / Tester values
    message = ""
    conversation_id = None
    status_text = "tester_ok"
    
    # Try to parse body if POST
    if request.method == "POST":
        try:
            # We assume JSON if body exists. Silent fail if not.
            # Using request.stream() or just json() inside try/except is safe
            body = await request.json()
            if isinstance(body, dict):
                msg = body.get("message")
                # Update message only if it's a non-empty string
                if isinstance(msg, str) and msg.strip():
                    message = msg
                    status_text = "analysis_complete"
                
                cid = body.get("conversation_id")
                if isinstance(cid, str):
                    conversation_id = cid
        except Exception:
            # Parsing failed (empty body, wrong content-type, etc.)
            # We stick to defaults -> equivalent to "tester_ok"
            pass

    # Run Logic (will be empty/safe if message is empty)
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
        status=status_text
    )

# --- Routes ---

# Register the same handler for all required paths and methods
app.add_api_route("/", universal_handler, methods=["GET", "POST"], response_model=HoneypotResponse)
app.add_api_route("/honeypot", universal_handler, methods=["GET", "POST"], response_model=HoneypotResponse)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
