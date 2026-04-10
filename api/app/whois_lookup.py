"""
whois_lookup.py

Purpose:
    Provide domain-age / WHOIS-style enrichment that main.py can call.

Important:
    This file is written to work safely even when python-whois is NOT installed.
    If the dependency is missing, the function returns a usable dictionary with
    an error message instead of crashing the whole program.

Install for full WHOIS support:
    pip install python-whois

Main callable function:
    lookup_domain_info(url)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# OPTIONAL DEPENDENCY IMPORT
# ---------------------------------------------------------------------------
# We intentionally guard this import so the module still imports cleanly in
# environments where python-whois has not been installed yet.
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
    """Extract the domain from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lower().split(":")[0]


def _normalize_creation_date(value: object) -> Optional[datetime]:
    """
    Normalize creation_date values returned by python-whois.

    python-whois may return:
        - a single datetime
        - a list of datetimes
        - None
    """
    if value is None:
        return None
    if isinstance(value, list) and value:
        candidate = value[0]
        return candidate if isinstance(candidate, datetime) else None
    return value if isinstance(value, datetime) else None


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def lookup_domain_info(url: str) -> Dict[str, object]:
    """
    Run a WHOIS lookup and return fields that the scoring engine understands.

    Returns keys such as:
        - domain_age_days
        - whois_privacy_enabled
        - whois_lookup_success
        - whois_error

    If python-whois is not installed yet, this function returns defaults plus an
    informative error message. That way the rest of the pipeline still runs.
    """
    domain = _extract_domain(url)

    # If the optional dependency is unavailable, fail gracefully.
    if not WHOIS_AVAILABLE:
        return {
            "domain_age_days": None,
            "whois_privacy_enabled": False,
            "whois_lookup_success": False,
            "whois_error": (
                "python-whois is not installed. "
                "Install it with: pip install python-whois"
            ),
        }

    try:
        record = whois.whois(domain)
        creation_date = _normalize_creation_date(getattr(record, "creation_date", None))

        # Calculate domain age in days when we have a usable creation date.
        domain_age_days = None
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            domain_age_days = (now - creation_date).days

        # WHOIS privacy is heuristic-based. Different registrars return different
        # field names and values, so we combine several known text fields.
        privacy_keywords = ("privacy", "redacted", "protect", "proxy")
        registrar_blob = " ".join(
            str(v)
            for v in [
                getattr(record, "registrar", None),
                getattr(record, "org", None),
                getattr(record, "name", None),
                getattr(record, "emails", None),
            ]
            if v
        ).lower()

        whois_privacy_enabled = any(keyword in registrar_blob for keyword in privacy_keywords)

        return {
            "domain_age_days": domain_age_days,
            "whois_privacy_enabled": whois_privacy_enabled,
            "whois_lookup_success": True,
            "whois_error": None,
        }

    except Exception as exc:
        return {
            "domain_age_days": None,
            "whois_privacy_enabled": False,
            "whois_lookup_success": False,
            "whois_error": str(exc),
        }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    result = lookup_domain_info("https://example.com")
    print(result)
