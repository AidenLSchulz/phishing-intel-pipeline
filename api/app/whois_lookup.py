"""
whois_lookup.py

FLOW OVERVIEW:
    1. Receive URL from main.py
    2. Extract domain from URL
    3. Run WHOIS lookup (if available)
    4. Normalize returned WHOIS data
    5. Derive useful fields (age, privacy, registrar)
    6. Return structured data for scoring engine

This file does NOT perform scoring.
It only prepares clean, structured data for downstream use.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# OPTIONAL DEPENDENCY IMPORT
# ---------------------------------------------------------------------------
# Determines if WHOIS functionality is available in this environment
try:
    import whois  # type: ignore
    WHOIS_AVAILABLE = True
except Exception:
    whois = None
    WHOIS_AVAILABLE = False


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """
    STEP 1:
    Normalize input and extract the domain portion.

    Example:
        https://example.com/login → example.com
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lower().split(":")[0]


def _normalize_creation_date(value: object) -> Optional[datetime]:
    """
    STEP 3 (part 1):
    Normalize raw WHOIS creation date into a usable datetime.

    Handles multiple possible formats returned by WHOIS:
        - single datetime
        - list of datetimes
        - None

    Output:
        A single datetime or None
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    if isinstance(value, list):
        valid_dates = [item for item in value if isinstance(item, datetime)]

        if not valid_dates:
            return None

        return min(valid_dates)

    return None


def _calculate_domain_age_days(creation_date: Optional[datetime]) -> Optional[int]:
    """
    STEP 4:
    Convert creation date into domain age (in days).

    Output:
        Integer days OR None if no date is available
    """
    if creation_date is None:
        return None

    if creation_date.tzinfo is None:
        creation_date = creation_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    return (now - creation_date).days


def _get_domain_age_risk(domain_age_days: Optional[int]) -> Optional[str]:
    """
    STEP 5:
    Convert raw age into a standardized risk category.

    Output:
        "high" / "moderate" / "low" / None
    """
    if domain_age_days is None:
        return None

    if domain_age_days <= 30:
        return "high"

    if domain_age_days <= 90:
        return "moderate"

    return "low"


def _detect_whois_privacy(record: object) -> Optional[bool]:
    """
    STEP 5 (part 2):
    Inspect WHOIS fields to determine if privacy protection is likely enabled.

    Output:
        True / False / None (if insufficient data)
    """
    privacy_keywords = ("privacy", "redacted", "protect", "proxy", "whoisguard")

    fields_to_check = [
        getattr(record, "registrar", None),
        getattr(record, "org", None),
        getattr(record, "name", None),
        getattr(record, "emails", None),
    ]

    available_fields = [str(value) for value in fields_to_check if value]

    if not available_fields:
        return None

    whois_blob = " ".join(available_fields).lower()

    return any(keyword in whois_blob for keyword in privacy_keywords)


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def lookup_domain_info(url: str) -> Dict[str, object]:
    """
    MAIN FLOW ENTRY

    INPUT:
        URL from main.py

    PROCESS:
        1. Extract domain
        2. Run WHOIS lookup
        3. Normalize raw WHOIS data
        4. Derive structured fields
        5. Return dictionary for scoring engine

    OUTPUT:
        Dictionary added to analysis_context in main.py
    """

    # STEP 1: Extract clean domain
    domain = _extract_domain(url)

    # STEP 2: If WHOIS not available → return safe defaults
    if not WHOIS_AVAILABLE:
        return {
            "domain": domain,
            "domain_age_days": None,
            "domain_age_risk": None,
            "registrar_name": None,
            "whois_privacy_enabled": None,
            "whois_lookup_success": False,
            "whois_error": (
                "python-whois is not installed. "
                "Install it with: pip install python-whois"
            ),
        }

    try:
        # STEP 3: Perform WHOIS lookup
        record = whois.whois(domain)

        # STEP 4: Normalize creation date
        creation_date = _normalize_creation_date(
            getattr(record, "creation_date", None)
        )

        # STEP 5: Derive structured values
        domain_age_days = _calculate_domain_age_days(creation_date)
        domain_age_risk = _get_domain_age_risk(domain_age_days)

        registrar_name = getattr(record, "registrar", None)
        whois_privacy_enabled = _detect_whois_privacy(record)

        # STEP 6: Return structured WHOIS data
        return {
            "domain": domain,
            "domain_age_days": domain_age_days,
            "domain_age_risk": domain_age_risk,
            "registrar_name": registrar_name,
            "whois_privacy_enabled": whois_privacy_enabled,
            "whois_lookup_success": True,
            "whois_error": None,
        }

    except Exception as exc:
        # STEP 6 (fallback): Return safe failure response
        return {
            "domain": domain,
            "domain_age_days": None,
            "domain_age_risk": None,
            "registrar_name": None,
            "whois_privacy_enabled": None,
            "whois_lookup_success": False,
            "whois_error": str(exc),
        }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = lookup_domain_info("https://example.com")
    print(result)