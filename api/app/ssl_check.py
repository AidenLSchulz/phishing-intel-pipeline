from __future__ import annotations

# Built-in networking library used to open TCP connections
import socket

# Python SSL/TLS support library
import ssl

# Used for certificate date calculations
from datetime import datetime, timezone

# Type hinting for cleaner code readability
from typing import Dict

# Used to safely extract domains from URLs
from urllib.parse import urlparse


def _extract_domain(url: str) -> str:
    """
    Extract the domain name from a URL.

    Examples:
        https://google.com/login -> google.com
        example.com -> example.com
    """

    # Add https:// if the user only entered a domain
    parsed = urlparse(url if "://" in url else f"https://{url}")

    # Remove ports if present
    return parsed.netloc.lower().split(":")[0]


def inspect_ssl_certificate(
    url: str,
    port: int = 443,
    timeout: int = 5
) -> Dict[str, object]:
    """
    Inspect an SSL/TLS certificate and return phishing risk data.

    Returns:
        {
            "score": int,
            "status": str,
            "reason": list[str]
        }

    Score Range:
        0–250
    """

    # Extract clean domain name from user input
    domain = _extract_domain(url)

    # Final phishing score for this helper
    score = 0

    # Stores human-readable explanations for scoring
    details = []

    try:

        # -------------------------------------------------
        # CREATE SSL CONTEXT
        # -------------------------------------------------
        # Creates a secure default SSL configuration
        context = ssl.create_default_context()

        # -------------------------------------------------
        # OPEN SECURE CONNECTION
        # -------------------------------------------------
        # Connect to the target domain on port 443
        with socket.create_connection(
            (domain, port),
            timeout=timeout
        ) as sock:

            # Wrap the socket using SSL/TLS
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_sock:

                # Retrieve certificate data
                cert = secure_sock.getpeercert()

        # Current UTC time used for date comparisons
        now = datetime.now(timezone.utc)

        # -------------------------------------------------
        # EXTRACT CERTIFICATE DATA
        # -------------------------------------------------

        # Pull issuer information from certificate
        issuer = (
            dict(x[0] for x in cert.get("issuer", []))
            if cert.get("issuer")
            else {}
        )

        # Extract issuer common name
        issuer_common_name = issuer.get("commonName")

        # Certificate issue date
        not_before_str = cert.get("notBefore")

        # Certificate expiration date
        not_after_str = cert.get("notAfter")

        # -------------------------------------------------
        # EXPIRATION CHECK
        # -------------------------------------------------
        # Detect expired or nearly expired certificates

        if not_after_str:

            # Convert expiration string into datetime object
            expiry_dt = datetime.strptime(
                not_after_str,
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            # Calculate remaining days before expiration
            days_until_expiration = (
                expiry_dt - now
            ).days

            # Certificate already expired
            if days_until_expiration < 0:

                score += 200

                details.append(
                    "SSL certificate is expired."
                )

            # Certificate expires very soon
            elif days_until_expiration < 7:

                score += 75

                details.append(
                    "SSL certificate expires very soon."
                )

        # Missing expiration information
        else:

            score += 75

            details.append(
                "SSL certificate missing expiration date."
            )

        # -------------------------------------------------
        # ISSUE DATE CHECK
        # -------------------------------------------------
        # Newly issued certificates can sometimes
        # indicate recently created phishing domains

        if not_before_str:

            # Convert issue date string into datetime object
            issued_dt = datetime.strptime(
                not_before_str,
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            # Calculate certificate age
            issue_days = (
                now - issued_dt
            ).days

            # Very new certificates may be suspicious
            if issue_days < 30:

                score += 50

                details.append(
                    "SSL certificate recently issued."
                )

        # Missing issue date
        else:

            score += 50

            details.append(
                "SSL certificate missing issue date."
            )

        # -------------------------------------------------
        # ISSUER CHECK
        # -------------------------------------------------
        # Verify issuer information exists

        if issuer_common_name is None:

            score += 50

            details.append(
                "SSL certificate issuer missing."
            )

        # -------------------------------------------------
        # LIMIT MAXIMUM SSL SCORE
        # -------------------------------------------------
        # SSL helper should never exceed 250 points

        score = min(score, 250)

        # -------------------------------------------------
        # SUCCESS RETURN
        # -------------------------------------------------

        return {
            "score": score,
            "status": "completed",
            "reason": details
        }

    # -----------------------------------------------------
    # SSL CERTIFICATE VALIDATION FAILURE
    # -----------------------------------------------------
    # Triggered when certificate validation fails

    except ssl.SSLCertVerificationError:

        return {
            "score": 250,
            "status": "failed",
            "reason": [
                "SSL certificate verification failed."
            ]
        }

    # -----------------------------------------------------
    # GENERAL ERROR HANDLER
    # -----------------------------------------------------
    # Prevents backend crashes from SSL/network failures

    except Exception as exc:

        # Ignore errors for domains that do not exist
        if isinstance(exc, socket.gaierror):

            return {
                "score": 0,
                "status": "skipped",
                "reason": [
                    "Domain could not be resolved."
                ]
            }

        return {
            "score": 200,
            "status": "error",
            "reason": [
                f"SSL check failed: {str(exc)}"
            ]
        }