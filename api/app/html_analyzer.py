"""
html_analyzer.py

Purpose:
    Analyze HTML/content-based phishing indicators.
"""

from __future__ import annotations

import re
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


CREDENTIAL_KEYWORDS = {
    "verify your account",
    "confirm your password",
    "reset your password",
    "sign in",
    "login",
    "log in",
    "confirm identity",
    "validate account",
}

URGENT_KEYWORDS = {
    "urgent",
    "immediately",
    "act now",
    "suspended",
    "locked",
    "expire",
    "warning",
}

FINANCIAL_KEYWORDS = {
    "payment",
    "credit card",
    "bank account",
    "billing",
    "invoice",
    "financial",
}

KNOWN_BRANDS = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "bank of america",
    "chase",
    "outlook",
    "office365",
    "facebook",
    "instagram",
}


HTML_SIGNAL_WEIGHTS = {
    "external_form_submission": 120,
    "credential_harvesting_language": 90,
    "javascript_obfuscation": 80,
    "hidden_iframe": 70,
    "urgent_threatening_language": 60,
    "financial_request_language": 50,
    "brand_impersonation": 40,
    "unexpected_login_prompt": 40,
    "login_form_present": 20,
    "favicon_loaded_from_external_domain": 15,
    "excessive_permission_requests": 15,
    "no_contact_or_privacy_policy": 10,
    "external_resource_loading": 5,
}


HTML_SIGNAL_REASONING = {
    "external_form_submission": "Form submits data to a different domain, which may indicate credential theft.",
    "credential_harvesting_language": "Page uses account/password verification language commonly seen in phishing.",
    "javascript_obfuscation": "Page contains suspicious JavaScript functions often used to hide malicious behavior.",
    "hidden_iframe": "Hidden iframe may be used to load deceptive or malicious content.",
    "urgent_threatening_language": "Urgent wording may pressure users into acting quickly.",
    "financial_request_language": "Financial wording may indicate attempts to steal payment or banking data.",
    "brand_impersonation": "Page references a known brand, which may indicate impersonation.",
    "unexpected_login_prompt": "Login prompt appears with other suspicious login-related language.",
    "login_form_present": "Login forms are common, so this is a weak signal by itself.",
    "favicon_loaded_from_external_domain": "External favicon may be suspicious, but can also be normal.",
    "excessive_permission_requests": "Multiple permission-related terms may indicate suspicious user prompting.",
    "no_contact_or_privacy_policy": "Missing contact/privacy language may reduce trust, but is weak alone.",
    "external_resource_loading": "External resources are common on legitimate websites, so this has very low weight.",
}


def _extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.netloc.lower().split(":")[0]


def _get_page_html(url: str, timeout: int = 10) -> Optional[str]:
    """
    Fetch page HTML.

    Browser-like headers help reduce false 0 scores caused by sites blocking
    simple Python requests.
    """
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        }

        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers=headers,
        )

        resp.raise_for_status()
        return resp.text

    except Exception as e:
        print(f"[HTML ERROR] Could not fetch HTML for {url}: {e}")
        return None


def _calculate_html_score(indicators: Dict[str, bool]) -> tuple[int, list[str], dict]:
    score = 0
    reasons = []
    scoring_details = {}

    for signal, triggered in indicators.items():
        if triggered and signal in HTML_SIGNAL_WEIGHTS:
            weight = HTML_SIGNAL_WEIGHTS[signal]
            reason = HTML_SIGNAL_REASONING[signal]

            score += weight
            reasons.append(f"{signal}: +{weight} - {reason}")

            scoring_details[signal] = {
                "triggered": True,
                "weight": weight,
                "reason": reason,
            }

    score = min(score, 250)

    return score, reasons, scoring_details


def _empty_indicator_result() -> Dict[str, bool]:
    return {
        "login_form_present": False,
        "external_form_submission": False,
        "credential_harvesting_language": False,
        "brand_impersonation": False,
        "urgent_threatening_language": False,
        "financial_request_language": False,
        "unexpected_login_prompt": False,
        "javascript_obfuscation": False,
        "hidden_iframe": False,
        "external_resource_loading": False,
        "excessive_permission_requests": False,
        "favicon_loaded_from_external_domain": False,
        "no_contact_or_privacy_policy": False,
    }


def analyze_html_content(
    url: str,
    html: Optional[str] = None,
    fetch_page: bool = False,
) -> Dict[str, object]:

    if html is None and fetch_page:
        html = _get_page_html(url)

    if not html:
        indicators = _empty_indicator_result()

        return {
            "score": 50,
            "reasons": [
                "Unable to fetch HTML. The site may be blocking automated analysis or unavailable."
            ],
            "scoring_details": {
                "html_fetch_failed": {
                    "triggered": True,
                    "weight": 50,
                    "reason": "HTML could not be fetched, so a small suspicious baseline score was applied.",
                }
            },
            **indicators,
            "inconsistent_branding_or_design": False,
            "html_analysis_success": False,
            "html_error": "No HTML provided or fetched.",
        }

    soup = BeautifulSoup(html, "html.parser")
    page_text = soup.get_text(" ", strip=True).lower()
    page_domain = _extract_domain(url)

    forms = soup.find_all("form")
    scripts = soup.find_all("script")
    iframes = soup.find_all("iframe")
    links = soup.find_all("link")
    imgs = soup.find_all("img")

    login_form_present = False
    external_form_submission = False
    hidden_iframe = False
    javascript_obfuscation = False
    external_resource_loading = False
    favicon_loaded_from_external_domain = False

    for form in forms:
        form_html = str(form).lower()

        if "password" in form_html or "login" in form_html or "signin" in form_html:
            login_form_present = True

        action = form.get("action")
        if action:
            target = urljoin(url, action)

            if _extract_domain(target) != page_domain:
                external_form_submission = True

    for iframe in iframes:
        style = (iframe.get("style") or "").lower().replace(" ", "")
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()

        if "display:none" in style or width == "0" or height == "0":
            hidden_iframe = True

        src = iframe.get("src")
        if src:
            target = urljoin(url, src)

            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    for script in scripts:
        script_text = script.get_text(" ", strip=True)

        if len(script_text) > 300 and re.search(
            r"(eval\(|fromcharcode|atob\(|unescape\()",
            script_text,
            re.IGNORECASE,
        ):
            javascript_obfuscation = True

        src = script.get("src")
        if src:
            target = urljoin(url, src)

            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    for link in links:
        href = link.get("href")
        rel = " ".join(link.get("rel", [])).lower()

        if href:
            target = urljoin(url, href)

            if _extract_domain(target) != page_domain:
                external_resource_loading = True

                if "icon" in rel:
                    favicon_loaded_from_external_domain = True

    for img in imgs:
        src = img.get("src")

        if src:
            target = urljoin(url, src)

            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    credential_harvesting_language = any(
        keyword in page_text for keyword in CREDENTIAL_KEYWORDS
    )

    urgent_threatening_language = any(
        keyword in page_text for keyword in URGENT_KEYWORDS
    )

    financial_request_language = any(
        keyword in page_text for keyword in FINANCIAL_KEYWORDS
    )

    brand_impersonation = any(
        brand in page_text for brand in KNOWN_BRANDS
    )

    unexpected_login_prompt = login_form_present and (
        "login" in page_text or "sign in" in page_text
    )

    permission_keywords = [
        "notifications",
        "clipboard",
        "location",
        "camera",
        "microphone",
    ]

    excessive_permission_requests = sum(
        1 for keyword in permission_keywords if keyword in page_text
    ) >= 2

    no_contact_or_privacy_policy = (
        "privacy policy" not in page_text
        and "contact us" not in page_text
    )

    indicators = {
        "login_form_present": login_form_present,
        "external_form_submission": external_form_submission,
        "credential_harvesting_language": credential_harvesting_language,
        "brand_impersonation": brand_impersonation,
        "urgent_threatening_language": urgent_threatening_language,
        "financial_request_language": financial_request_language,
        "unexpected_login_prompt": unexpected_login_prompt,
        "javascript_obfuscation": javascript_obfuscation,
        "hidden_iframe": hidden_iframe,
        "external_resource_loading": external_resource_loading,
        "excessive_permission_requests": excessive_permission_requests,
        "favicon_loaded_from_external_domain": favicon_loaded_from_external_domain,
        "no_contact_or_privacy_policy": no_contact_or_privacy_policy,
    }

    score, reasons, scoring_details = _calculate_html_score(indicators)

    return {
        "score": score,
        "reasons": reasons,
        "scoring_details": scoring_details,
        **indicators,
        "inconsistent_branding_or_design": False,
        "html_analysis_success": True,
        "html_error": None,
    }


if __name__ == "__main__":
    sample_html = """
    <html>
      <head>
        <title>Verify Your Account</title>
        <link rel="icon" href="https://evil-login.xyz/favicon.ico">
      </head>
      <body>
        <h1>Microsoft Security Alert</h1>
        <p>Your account will be locked. Act now.</p>
        <form action="https://evil-login.xyz/post">
          <input type="text" name="email">
          <input type="password" name="password">
        </form>
        <iframe src="https://bad-site.xyz" style="display:none"></iframe>
      </body>
    </html>
    """

    result = analyze_html_content("https://example.com", html=sample_html)
    print(result)