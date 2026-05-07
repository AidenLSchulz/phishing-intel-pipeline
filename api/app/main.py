"""
main.py

Main API file.

This version:
- Does NOT use phishing_scoring_engine.py
- Does NOT calculate helper-specific scores inside main.py
- Calls each helper module
- Pulls the "score" returned by each helper
- Adds the helper scores together
- Assigns the final risk level based on the total score
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime

import sqlite3
import os
import json

# Helper modules
from .result_repository import save_result, domain_exists, normalize_domain, initialize_database
from .database_check import check_known_phishing_database
from .html_analyzer import analyze_html_content
from .ssl_check import inspect_ssl_certificate
from .whois_lookup import lookup_domain_info


app = FastAPI()
initialize_database()

# Allows the frontend to communicate with this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Expected frontend request format:
# {
#   "domain": "example.com"
# }
class DomainRequest(BaseModel):
    domain: str

@app.get("/")
def root():
    return {"message": "API is running"}


@app.get("/results-summary")
def results_summary():
    db_file = os.path.join(os.path.dirname(__file__), "analysis_results.db")

    if not os.path.exists(db_file):
        return {
            "total_scans": 0,
            "risk_breakdown": [],
            "latest_scans": [],
            "message": "Database not found yet."
        }

    # UPDATED: use context manager for safe connection handling
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM analysis_results")
        total_scans = cursor.fetchone()[0]

        cursor.execute("""
            SELECT risk_level, COUNT(*)
            FROM analysis_results
            GROUP BY risk_level
            ORDER BY COUNT(*) DESC
        """)
        risk_breakdown = [
            {"risk_level": row[0], "count": row[1]}
            for row in cursor.fetchall()
        ]

        cursor.execute("""
            SELECT domain, final_score, risk_level, timestamp
            FROM analysis_results
            ORDER BY id DESC
            LIMIT 10
        """)
        latest_scans = [
            {
                "domain": row[0],
                "final_score": row[1],
                "risk_level": row[2],
                "timestamp": row[3]
            }
            for row in cursor.fetchall()
        ]

    return {
        "total_scans": total_scans,
        "risk_breakdown": risk_breakdown,
        "latest_scans": latest_scans
    }

@app.get("/reports/indicators")
def get_indicator_report():
    db_file = os.path.join(os.path.dirname(__file__), "analysis_results.db")

    if not os.path.exists(db_file):
        return []

    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT domain, final_score, risk_level, timestamp, raw_results
            FROM analysis_results
            ORDER BY id DESC
            LIMIT 10000
        """)

        rows = cursor.fetchall()

    indicator_report = {}

    for row in rows:
        domain = row[0]
        risk_score = row[1]
        risk_level = row[2]
        scanned_at = row[3]
        saved_raw_results = row[4]

        if not saved_raw_results:
            continue

        try:
            raw_results = json.loads(saved_raw_results)
        except Exception:
            continue

        database_result = raw_results.get("database_check", {})
        ssl_result = raw_results.get("ssl_check", {})
        whois_result = raw_results.get("whois_check", {})
        html_result = raw_results.get("html_analyzer", {})

        indicators = collect_hit_indicators(
            domain,
            database_result,
            ssl_result,
            whois_result,
            html_result
        )

        for indicator in indicators:
            indicator_name = indicator.get("name", "Unknown Indicator")
            indicator_details = indicator.get("details", "No details provided")

            if indicator_name not in indicator_report:
                indicator_report[indicator_name] = {
                    "indicator_name": indicator_name,
                    "hit_count": 0,
                    "top_domains": []
                }

            indicator_report[indicator_name]["hit_count"] += 1

            indicator_report[indicator_name]["top_domains"].append({
                "domain": domain,
                "details": indicator_details,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "scanned_at": scanned_at
            })

    for indicator in indicator_report.values():
        indicator["top_domains"] = sorted(
            indicator["top_domains"],
            key=lambda item: item["risk_score"],
            reverse=True
        )[:15]

    return sorted(
        indicator_report.values(),
        key=lambda item: item["hit_count"],
        reverse=True
    )


def detect_indicators_from_domain(domain):
    indicators = []

    suspicious_keywords = [
        "login", "secure", "update", "verify", "account",
        "bank", "signin", "auth", "portal", "support",
        "billing", "alert", "confirm"
    ]

    for keyword in suspicious_keywords:
        if keyword in domain.lower():
            indicators.append({
                "name": "Suspicious Keyword",
                "details": keyword
            })

    if len(domain) > 25:
        indicators.append({
            "name": "Long Domain",
            "details": "Domain length is greater than 25 characters"
        })

    if domain.count("-") >= 2:
        indicators.append({
            "name": "Multiple Hyphens",
            "details": "Domain contains multiple hyphens"
        })

    if any(char.isdigit() for char in domain):
        indicators.append({
            "name": "Contains Numbers",
            "details": "Domain contains numeric characters"
        })

    if domain.endswith(".info") or domain.endswith(".biz"):
        indicators.append({
            "name": "Suspicious TLD",
            "details": "Domain uses a higher-risk TLD"
        })

    return indicators


# Final scoring model:
# 0–249     Safe
# 250–499   Suspicious
# 500–749   Likely Phishing
# 750–1000  High Risk
def get_risk_level(total_score: int) -> str:
    if total_score <= 249:
        return "Safe"
    elif total_score <= 499:
        return "Suspicious"
    elif total_score <= 749:
        return "Likely Phishing"
    return "High Risk"


# Safely pull the score returned by a helper.
# If a helper fails or does not return a valid score, use 0.
def get_helper_score(helper_result: dict) -> int:
    try:
        return int(helper_result.get("score", 0))
    except Exception:
        return 0
    

def collect_hit_indicators(domain, database_result, ssl_result, whois_result, html_result):
    indicators = []

    # Domain pattern indicators
    indicators.extend(detect_indicators_from_domain(domain))

    # Known phishing database
    if database_result.get("score", 0) > 0:
        indicators.append({
            "name": "Known Phishing Database",
            "details": "; ".join(database_result.get("details", ["Known phishing database returned a score"]))
        })

    # SSL/TLS check
    if ssl_result.get("score", 0) > 0:
        ssl_details = ssl_result.get("reason") or ssl_result.get("details") or ["SSL/TLS check returned a score"]

        indicators.append({
            "name": "SSL/TLS Check",
            "details": "; ".join(ssl_details) if isinstance(ssl_details, list) else str(ssl_details)
        })

    # WHOIS check
    if whois_result.get("score", 0) > 0:
        whois_details = []

        if whois_result.get("domain_age_days") is not None:
            whois_details.append(f"Domain age: {whois_result.get('domain_age_days')} days")

        if whois_result.get("domain_age_risk"):
            whois_details.append(f"Domain age risk: {whois_result.get('domain_age_risk')}")

        if whois_result.get("registrar_name"):
            whois_details.append(f"Registrar: {whois_result.get('registrar_name')}")

        if whois_result.get("whois_privacy_enabled") is True:
            whois_details.append("WHOIS privacy is enabled")

        if whois_result.get("whois_error"):
            whois_details.append(f"WHOIS error: {whois_result.get('whois_error')}")

        indicators.append({
            "name": "WHOIS Check",
            "details": "; ".join(whois_details) if whois_details else "WHOIS check returned a score"
        })

    # HTML analyzer
    if html_result.get("score", 0) > 0:
        html_reasons = html_result.get("reasons", [])

        indicators.append({
            "name": "HTML Analyzer",
            "details": "; ".join(html_reasons) if html_reasons else "HTML analyzer returned a score"
        })

        scoring_details = html_result.get("scoring_details", {})

        for detail_name, detail_value in scoring_details.items():
            if isinstance(detail_value, dict) and detail_value.get("triggered") is True:
                indicators.append({
                    "name": f"HTML Indicator: {detail_name}",
                    "details": detail_value.get("reason", "HTML scoring detail was triggered")
                })

    return indicators


@app.post("/analyze-domain")
def analyze_domain(request: DomainRequest):

    # Clean the submitted domain
    submitted_domain = request.domain.strip()

    # Handle empty input
    if not submitted_domain:
        return {
            "domain": "",
            "risk_score": 0,
            "risk_level": "Safe",
            "score_breakdown": {
                "known_phishing_feed": 0,
                "ssl_tls_check": 0,
                "domain_whois_check": 0,
                "html_content_check": 0,
                "total": 0
            },
            "helper_results": {},
            "notes": ["No domain was provided."]
        }

    # Add http:// if user only entered example.com
    test_url = submitted_domain

    if not test_url.startswith("http://") and not test_url.startswith("https://"):
        test_url = "https://" + test_url

    notes = []

    # ----------------------------------------------------
    # Run helper modules
    # Main.py does not score these checks.
    # It only collects the score each helper returns.
    # ----------------------------------------------------

    try:
        database_result = check_known_phishing_database(test_url)
    except Exception as e:
        database_result = {"score": 0, "error": str(e)}
        notes.append(f"Known phishing feed check failed: {e}")

    try:
        ssl_result = inspect_ssl_certificate(test_url)
    except Exception as e:
        ssl_result = {"score": 0, "error": str(e)}
        notes.append(f"SSL/TLS check failed: {e}")

    try:
        whois_result = lookup_domain_info(test_url)
    except Exception as e:
        whois_result = {"score": 0, "error": str(e)}
        notes.append(f"WHOIS/domain check failed: {e}")

    try:
        html_result = analyze_html_content(test_url, fetch_page=True)
    except Exception as e:
        html_result = {"score": 0, "error": str(e)}
        notes.append(f"HTML/content check failed: {e}")

    # ----------------------------------------------------
    # Pull scores directly from helper return values
    # ----------------------------------------------------

    database_score = get_helper_score(database_result)
    ssl_score = get_helper_score(ssl_result)
    whois_score = get_helper_score(whois_result)
    html_score = get_helper_score(html_result)

    # ----------------------------------------------------
    # Add helper scores together
    # ----------------------------------------------------

    total_score = (
        database_score +
        ssl_score +
        whois_score +
        html_score
    )

    # Keep total score inside 0–1000
    total_score = max(0, min(total_score, 1000))

    # Convert score to final risk label
    risk_level = get_risk_level(total_score)

    # ----------------------------------------------------
    # Save result + prevent duplicates
    # ----------------------------------------------------

    domain = normalize_domain(submitted_domain)

    if domain_exists(domain):
        notes.append("Domain already analyzed previously. Skipping save.")
    else:
        result = {
            "domain": domain,
            "final_score": total_score,
            "risk_level": risk_level,
            "indicators": collect_hit_indicators(
                domain,
                database_result,
                ssl_result,
                whois_result,
                html_result
            ),
            "raw_results": {
                "database_check": database_result,
                "ssl_check": ssl_result,
                "whois_check": whois_result,
                "html_analyzer": html_result
            },
            "timestamp": datetime.utcnow().isoformat()
        }

        save_result(result)

    # ----------------------------------------------------
    # Return final result to frontend
    # ----------------------------------------------------

    return {
        "domain": submitted_domain,
        "risk_score": total_score,
        "risk_level": risk_level,

        "score_breakdown": {
            "known_phishing_feed": database_score,
            "ssl_tls_check": ssl_score,
            "domain_whois_check": whois_score,
            "html_content_check": html_score,
            "total": total_score
        },

        "helper_results": {
            "database_check": database_result,
            "ssl_check": ssl_result,
            "whois_check": whois_result,
            "html_analyzer": html_result
        },

        "notes": notes
    }