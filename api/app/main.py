"""
main.py

PURPOSE:
    This file is the SINGLE entry point for all frontend API requests.

FLOW OVERVIEW:
    Frontend (app.js)
        -> sends POST request to /analyze-domain
        -> main.py receives request
        -> builds analysis_context
        -> calls helper modules
        -> sends data to scoring engine
        -> returns final result to frontend

IMPORTANT:
    - This is the ONLY backend entry point used by the frontend
    - All helper modules are called from here
    - No other file should directly handle API requests
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os

# 🔽 Helper modules (these do the actual analysis work)
from .database_check import check_known_phishing_database
from .html_analyzer import analyze_html_content
from .phishing_scoring_engine import PhishingScoringEngine
from .ssl_check import inspect_ssl_certificate
from .virustotal_check import check_virustotal_url
from .whois_lookup import lookup_domain_info

# Create FastAPI app
app = FastAPI()

# 🔐 CORS setup
# Allows frontend (running in browser) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # Allow all origins (safe for dev, restrict in prod)
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 📥 Request model (what frontend sends)
class DomainRequest(BaseModel):
    domain: str


# 🧪 Basic health check endpoint
@app.get("/")
def root():
    return {"message": "API is running"}


# 🚀 MAIN ENTRY POINT USED BY FRONTEND
@app.post("/analyze-domain")
def analyze_domain(request: DomainRequest):
    """
    MAIN PIPELINE:

    1. Receive domain from frontend
    2. Normalize into usable URL
    3. Create shared analysis_context dictionary
    4. Call each helper module
    5. Merge all results into analysis_context
    6. Send context to scoring engine
    7. Return final result to frontend
    """

    # STEP 1: Clean input
    submitted_domain = request.domain.strip()

    if not submitted_domain:
        return {
            "domain": submitted_domain,
            "risk_score": 0,
            "reasons": ["No domain was provided."]
        }

    # STEP 2: Normalize into URL
    # (ensures helpers work correctly)
    test_url = submitted_domain
    if not test_url.startswith("http://") and not test_url.startswith("https://"):
        test_url = f"http://{test_url}"

    # STEP 3: Create shared analysis context
    # This dictionary is passed through ALL helpers
    analysis_context = {}

    # Pull API key (if available)
    vt_api_key = os.getenv("VT_API_KEY")

    # STEP 4: Run helper modules (ONE FLOW)

    # Check known phishing database
    analysis_context.update(
        check_known_phishing_database(
            test_url,
            url_blacklist_file="known_bad_urls.txt",
            domain_blacklist_file="known_bad_domains.txt",
            json_cache_file=".known_phishing_cache.json",
        )
    )

    # WHOIS lookup (domain registration info)
    analysis_context.update(lookup_domain_info(test_url))

    # SSL certificate inspection
    analysis_context.update(inspect_ssl_certificate(test_url))

    # VirusTotal check (external reputation service)
    analysis_context.update(check_virustotal_url(test_url, vt_api_key))

    # HTML content analysis (structure + phishing patterns)
    analysis_context.update(analyze_html_content(test_url, fetch_page=True))

    # STEP 5: Score everything
    engine = PhishingScoringEngine()

    result = engine.score_url(
        url=test_url,
        displayed_url=None,
        analysis_context=analysis_context,
    )

    # Convert result object to dictionary
    result_dict = result.to_dict()

    # STEP 6: Return ONLY what frontend expects
    return {
    "domain": submitted_domain,
    "risk_score": result_dict.get("final_score", 0),
    "risk_level": result_dict.get("risk_level", "Unknown"),
    "reasons": [
        indicator.get("explanation", indicator.get("name", "Unknown indicator"))
        for indicator in result_dict.get("triggered_indicators", [])
    ],
    "notes": result_dict.get("notes", []),
}