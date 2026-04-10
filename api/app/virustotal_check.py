"""
virustotal_check.py

Purpose:
    Provide VirusTotal URL reputation enrichment that main.py can call.

Main callable function:
    check_virustotal_url(url, api_key, ...)

Important:
    This module is safe to import and safe to call even when an API key has not
    been provided. In that case it returns a usable dictionary with a helpful
    error message instead of raising an exception.

Dependency:
    pip install requests
"""

from __future__ import annotations

import base64
import time
from typing import Dict, Optional

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure VirusTotal gets a well-formed URL string."""
    url = url.strip()
    if "://" not in url:
        url = f"http://{url}"
    return url


def _vt_url_id(url: str) -> str:
    """
    VirusTotal URL lookup IDs are URL-safe base64 values without trailing '='.
    """
    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.strip("=")


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def check_virustotal_url(
    url: str,
    api_key: Optional[str],
    poll_for_completion: bool = True,
    poll_attempts: int = 3,
    poll_delay_seconds: int = 3,
    timeout: int = 15,
) -> Dict[str, object]:
    """
    Submit a URL to VirusTotal and retrieve its latest reputation / analysis.

    Returns:
        A dictionary designed for direct merging into analysis_context.

    Notes:
        - If no API key is supplied, the function returns a safe default result.
        - If the request fails, the function returns a safe default result plus
          the error string.
    """
    normalized_url = _normalize_url(url)

    if not api_key:
        return {
            "domain_reputation_malicious": False,
            "virustotal_checked": False,
            "virustotal_error": "VirusTotal API key not provided.",
            "virustotal_malicious": 0,
            "virustotal_suspicious": 0,
            "virustotal_harmless": 0,
        }

    headers = {"x-apikey": api_key}

    try:
        # Step 1: Submit the URL so VT can analyze or refresh it.
        submit_resp = requests.post(
            f"{VT_BASE_URL}/urls",
            headers=headers,
            data={"url": normalized_url},
            timeout=timeout,
        )
        submit_resp.raise_for_status()
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")

        # Step 2: Optionally poll the analysis endpoint a few times.
        if poll_for_completion and analysis_id:
            for _ in range(poll_attempts):
                analysis_resp = requests.get(
                    f"{VT_BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=timeout,
                )
                analysis_resp.raise_for_status()
                analysis_data = analysis_resp.json()
                status = analysis_data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    break
                time.sleep(poll_delay_seconds)

        # Step 3: Pull the latest URL report.
        url_id = _vt_url_id(normalized_url)
        final_resp = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=timeout,
        )
        final_resp.raise_for_status()
        final_data = final_resp.json()

        stats = final_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))

        # We intentionally map both malicious and suspicious signals to the
        # engine's domain_reputation_malicious flag, since either one indicates
        # risk worth scoring.
        return {
            "domain_reputation_malicious": malicious > 0 or suspicious > 0,
            "virustotal_checked": True,
            "virustotal_error": None,
            "virustotal_malicious": malicious,
            "virustotal_suspicious": suspicious,
            "virustotal_harmless": harmless,
        }

    except requests.RequestException as exc:
        return {
            "domain_reputation_malicious": False,
            "virustotal_checked": False,
            "virustotal_error": str(exc),
            "virustotal_malicious": 0,
            "virustotal_suspicious": 0,
            "virustotal_harmless": 0,
        }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Replace api_key=None with a real key when ready.
    result = check_virustotal_url("http://example.com", api_key=None)
    print(result)
