from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "update", "bank", "paypal"
]

class DomainRequest(BaseModel):
    domain: str

@app.get("/")
def root():
    return {"message": "API is running"}

@app.post("/analyze-domain")
def analyze_domain(request: DomainRequest):
    domain = request.domain
    score = 0
    reasons = []

    for word in SUSPICIOUS_KEYWORDS:
        if word in domain.lower():
            score += 20
            reasons.append(f"Contains suspicious keyword: {word}")

    if len(domain) > 25:
        score += 10
        reasons.append("Domain is unusually long")

    if "-" in domain:
        score += 10
        reasons.append("Contains hyphens")

    if "xn--" in domain.lower():
        reasons.append("Threat: Homograph/Punycode pattern detected")
    
    sketchy_tlds = [".xyz", "top", ".click", ".support", ".cfd", ".live"]
    if any(domain.lower().endswith(tld) for tld in sketchy_tlds):
        reasons.append("Threat: Suspicious/High-Risk TLD detected")
    

    protected_brands = ["amazon", "microsoft", "google", "paypal", "apple", "netflix"]
    for brand in protected_brands:
        if brand in domain.lower() and not domain.lower().endswith(f"{brand}.com"):
            reasons.append(f"Threat: Unauthorized Brand Impersonation ({brand})")


    if domain.count('.') >= 3:
        reasons.append("Threat: Excessive subdomain nesting (Potential Proxy)") 
              
    return {
        "domain": domain,
        "risk_score": score,
        "reasons": reasons
    }