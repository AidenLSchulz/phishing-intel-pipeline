from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Dict, Optional, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# --- CONFIGURATION ---

# List of highly trusted domains that should bypass phishing scoring[cite: 2]
WHITELISTED_DOMAINS: Set[str] = {
    "google.com", "microsoft.com", "apple.com", "amazon.com", 
    "facebook.com", "github.com", "linkedin.com", "okta.com",
    "live.com", "outlook.com", "gmail.com"
}

# Keywords specifically associated with credential theft[cite: 1]
CREDENTIAL_KEYWORDS = {
    "verify your account",
    "confirm your password",
    "reset your password",
    "confirm identity",
    "validate account",
}

# Known brands frequently targeted by impersonation attacks[cite: 1]
KNOWN_BRANDS = {
    "paypal", "microsoft", "google", "apple", "amazon", 
    "bank of america", "chase", "outlook", "office365", 
    "facebook", "instagram", "youtube", "netflix", "linkedin", "gmail"
}

# Defines the impact of each indicator on the final risk score[cite: 1]
HTML_SIGNAL_WEIGHTS = {
    "external_form_submission": 60,
    "credential_harvesting_language": 90,
    "javascript_obfuscation": 80,
    "hidden_iframe": 10,
    "urgent_threatening_language": 60,
    "brand_impersonation": 70,
    "lookalike_domain": 85,
    "login_form_present": 2, # Low weight: logins are common on safe sites[cite: 1]
}

# Documentation of reasoning for each indicator as required by Acceptance Criteria[cite: 1]
HTML_SIGNAL_REASONING = {
    "external_form_submission": "Form submits data to a different domain, which may indicate credential theft.",
    "credential_harvesting_language": "Page uses account/password verification language commonly seen in phishing.",
    "javascript_obfuscation": "Page contains suspicious JavaScript functions often used to hide malicious behavior.",
    "hidden_iframe": "Hidden iframe may be used to load deceptive or malicious content.",
    "urgent_threatening_language": "Urgent wording may pressure users into acting quickly.",
    "brand_impersonation": "Page references a known brand that does not match the domain owner.",
    "lookalike_domain": "Domain appears to imitate a known brand using character substitution or close spelling similarity.",
    "login_form_present": "A login form was detected on the page.",
}

# --- UTILITY FUNCTIONS ---

def _extract_domain(url: str) -> str:
    """Gets the fully qualified domain name (FQDN) from a URL[cite: 1]."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc.lower().split(":")[0]

def _get_base_domain(url: str) -> str:
    """Extracts the registered domain (e.g., 'google.com') to ignore subdomains[cite: 2]."""
    domain = _extract_domain(url)
    parts = domain.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return domain

def _is_whitelisted(url: str) -> bool:
    """Checks if the base domain is part of the trusted whitelist[cite: 2]."""
    return _get_base_domain(url) in WHITELISTED_DOMAINS

def _normalize_lookalike_domain(domain: str) -> str:
    """
    Converts common phishing character substitutions into normal letters.
    Example: g00gle -> google
    """
    return (
        domain.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("7", "t")
        .replace("@", "a")
        .replace("$", "s")
    )

def _detect_lookalike_domain(url: str) -> bool:
    """
    Detects domains that imitate known brands using:
    - character substitution (g00gle)
    - fuzzy similarity (grnail vs gmail)
    """
    domain = _extract_domain(url)
    base_domain = _get_base_domain(url)

    if base_domain in WHITELISTED_DOMAINS:
        return False

    domain_name = base_domain.split(".")[0]
    normalized_domain_name = _normalize_lookalike_domain(domain_name)

    for brand in KNOWN_BRANDS:
        clean_brand = brand.replace(" ", "").lower()

        if clean_brand == domain_name:
            return False

        if clean_brand in normalized_domain_name and clean_brand not in domain_name:
            return True

        similarity = SequenceMatcher(None, clean_brand, normalized_domain_name).ratio()

        if similarity > 0.70 and clean_brand not in domain_name:
            return True

    return False

def _empty_indicator_result() -> Dict[str, bool]:
    """Initializes all indicators to False[cite: 1]."""
    return {
        "login_form_present": False,
        "external_form_submission": False,
        "credential_harvesting_language": False,
        "brand_impersonation": False,
        "lookalike_domain": False,
        "urgent_threatening_language": False,
        "javascript_obfuscation": False,
        "hidden_iframe": False,
    }

def _calculate_html_score(indicators: Dict[str, bool]) -> tuple[int, list[str], dict]:
    """Sums weights of triggered indicators to produce a final risk score[cite: 1]."""
    score = 0
    reasons = []
    scoring_details = {}

    for signal, triggered in indicators.items():
        if triggered and signal in HTML_SIGNAL_WEIGHTS:
            weight = HTML_SIGNAL_WEIGHTS[signal]
            reason = HTML_SIGNAL_REASONING.get(signal, "Suspicious indicator detected.")
            score += weight
            reasons.append(f"{signal}: +{weight}")
            scoring_details[signal] = {"triggered": True, "weight": weight, "reason": reason}

    return min(score, 250), reasons, scoring_details

def _fallback_score_from_domain(url: str) -> tuple[int, list[str], dict]:
    """Provides high-level risk assessment if HTML cannot be fetched[cite: 1]."""
    domain_raw = _extract_domain(url)
    score = 0
    reasons = ["Unable to fetch HTML. Analyzing domain structure."]
    details = {"suspicious_domain": True}

    if _detect_lookalike_domain(url):
        score += HTML_SIGNAL_WEIGHTS["lookalike_domain"]
        reasons.append("lookalike_domain: +85")
        details["lookalike_domain"] = {
            "triggered": True,
            "weight": HTML_SIGNAL_WEIGHTS["lookalike_domain"],
            "reason": HTML_SIGNAL_REASONING["lookalike_domain"]
        }
    
    if "-" in domain_raw:
        score += 50
        reasons.append("suspicious_domain_hyphen: +50")

    if any(domain_raw.endswith(tld) for tld in [".xyz", ".top", ".click"]):
        score += 100
        reasons.append("suspicious_tld: +100")
    
    return min(score, 250), reasons, details

def _get_page_html(url: str, timeout: int = 10) -> Optional[str]:
    """Fetches HTML content while mimicking a standard web browser[cite: 1]."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, timeout=timeout, allow_redirects=True, headers=headers)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"[ERROR] Fetch failed: {e}")
        return None

# --- MAIN ANALYSIS ENGINE ---

def analyze_html_content(url: str, html: Optional[str] = None, fetch_page: bool = False) -> Dict[str, object]:
    """Main entry point for auditing HTML for phishing indicators[cite: 1, 2]."""
    
    # 1. Early exit if the domain is whitelisted to prevent false positives[cite: 2]
    if _is_whitelisted(url):
        return {
            "score": 0,
            "reasons": ["Site is on the trusted whitelist."],
            "html_analysis_success": True,
            "whitelisted": True
        }

    if html is None and fetch_page:
        html = _get_page_html(url)

    if not html:
        score, reasons, details = _fallback_score_from_domain(url)
        return {"score": score, "reasons": reasons, "scoring_details": details, "html_analysis_success": False}

    soup = BeautifulSoup(html, "html.parser")
    page_text = soup.get_text(" ", strip=True).lower()
    page_domain = _extract_domain(url)
    base_page_domain = _get_base_domain(url)

    indicators = _empty_indicator_result()

    # 2. Domain Audit: Detects lookalike/ripoff domains such as g00gle.com or grnail.com
    indicators["lookalike_domain"] = _detect_lookalike_domain(url)

    # 3. Form Audit: Checks for password inputs and external data submission[cite: 1, 2]
    forms = soup.find_all("form")
    for form in forms:
        form_html = str(form).lower()
        if "password" in form_html:
            indicators["login_form_present"] = True

        action = form.get("action")
        if action:
            target_url = urljoin(url, action)
            target_base = _get_base_domain(target_url)
            # Only flag as 'external' if the base domain doesn't match and isn't whitelisted[cite: 2]
            if target_base != base_page_domain and target_base not in WHITELISTED_DOMAINS:
                indicators["external_form_submission"] = True

    # 4. Brand Audit: Detects brand names mentioned on mismatching domains[cite: 2]
    found_brand = any(brand in page_text for brand in KNOWN_BRANDS)
    brand_in_url = any(brand in page_domain for brand in KNOWN_BRANDS)
    if found_brand and not brand_in_url:
        indicators["brand_impersonation"] = True

    # 5. Language Audit: Scans for urgency or credential-harvesting terms[cite: 1]
    indicators["credential_harvesting_language"] = any(kw in page_text for kw in CREDENTIAL_KEYWORDS)
    indicators["urgent_threatening_language"] = "account will be locked" in page_text or "act now" in page_text

    # 6. Script Audit: Detects obfuscation patterns like 'eval' or 'unescape'[cite: 1]
    for script in soup.find_all("script"):
        if re.search(r"(eval\(|fromcharcode|unescape\()", script.get_text(), re.I):
            indicators["javascript_obfuscation"] = True

    # Finalize scoring and reasoning[cite: 1]
    score, reasons, details = _calculate_html_score(indicators)

    return {
        "score": score,
        "reasons": reasons,
        "scoring_details": details,
        **indicators,
        "html_analysis_success": True
    }