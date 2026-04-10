"""
ssl_check.py

Purpose:
    Provide SSL/TLS certificate enrichment that main.py can call.

Main callable function:
    inspect_ssl_certificate(url, port=443, timeout=5)

Notes:
    - This function attempts a live network connection.
    - If the host does not support TLS, is offline, or the certificate fails
      verification, we return a safe error structure instead of crashing.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract the host/domain from a URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc.lower().split(":")[0]


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def inspect_ssl_certificate(url: str, port: int = 443, timeout: int = 5) -> Dict[str, object]:
    """
    Retrieve SSL/TLS certificate details and translate them into fields used by
    the scoring engine.

    Returned keys:
        - ssl_certificate_valid
        - ssl_certificate_mismatch
        - recently_issued_ssl_certificate
        - ssl_lookup_success
        - ssl_error
        - ssl_issue_age_days
    """
    domain = _extract_domain(url)

    try:
        # Use the default CA trust store so normal validation occurs.
        context = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        # If we reached this point, hostname verification and certificate trust
        # both succeeded under the current SSL context.
        ssl_certificate_valid = True
        ssl_certificate_mismatch = False

        # Determine how recently the certificate was issued.
        not_before_str = cert.get("notBefore")
        issue_days = None
        recently_issued_ssl_certificate = False

        if not_before_str:
            issued_dt = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            issue_days = (datetime.now(timezone.utc) - issued_dt).days
            recently_issued_ssl_certificate = issue_days < 30

        return {
            "ssl_certificate_valid": ssl_certificate_valid,
            "ssl_certificate_mismatch": ssl_certificate_mismatch,
            "recently_issued_ssl_certificate": recently_issued_ssl_certificate,
            "ssl_lookup_success": True,
            "ssl_error": None,
            "ssl_issue_age_days": issue_days,
        }

    except ssl.SSLCertVerificationError as exc:
        # This often means the certificate is invalid, untrusted, or the host
        # name does not match the certificate.
        return {
            "ssl_certificate_valid": False,
            "ssl_certificate_mismatch": True,
            "recently_issued_ssl_certificate": False,
            "ssl_lookup_success": False,
            "ssl_error": str(exc),
            "ssl_issue_age_days": None,
        }
    except Exception as exc:
        return {
            "ssl_certificate_valid": False,
            "ssl_certificate_mismatch": True,
            "recently_issued_ssl_certificate": False,
            "ssl_lookup_success": False,
            "ssl_error": str(exc),
            "ssl_issue_age_days": None,
        }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    result = inspect_ssl_certificate("https://example.com")
    print(result)
