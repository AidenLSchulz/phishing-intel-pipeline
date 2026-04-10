"""
html_analyzer.py

Purpose:
    Provide HTML/content-based phishing indicators that main.py can call.

Main callable function:
    analyze_html_content(url, html=None, fetch_page=False)

This module can work in two modes:
    1. main.py passes raw HTML directly
    2. this file fetches the page itself when fetch_page=True

Dependencies:
    pip install beautifulsoup4 requests

Important note:
    A few advanced indicators such as true visual branding consistency are hard
    to do accurately without browser rendering / screenshots / computer vision.
    Those are left as placeholders and clearly noted below.
"""

from __future__ import annotations

import re
from typing import Dict, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# SIMPLE KEYWORD TABLES
# ---------------------------------------------------------------------------
# These keyword tables are intentionally small and easy to tune.
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
    "paypal", "microsoft", "google", "apple", "amazon", "bank of america",
    "chase", "outlook", "office365", "facebook", "instagram"
}


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Extract the domain/host portion from a URL."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.netloc.lower().split(":")[0]


def _get_page_html(url: str, timeout: int = 10) -> Optional[str]:
    """
    Fetch page HTML directly.

    This is optional because some teams may prefer that main.py handle all HTTP
    requests and simply pass the HTML into this module.
    """
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp.text
    except Exception:
        return None


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def analyze_html_content(
    url: str,
    html: Optional[str] = None,
    fetch_page: bool = False,
) -> Dict[str, object]:
    """
    Analyze HTML content and map findings into scoring-engine-friendly keys.

    Parameters:
        url:
            The page URL.
        html:
            Raw HTML, if main.py already fetched it.
        fetch_page:
            If True and html is None, this module will fetch the page.

    Returns:
        A dictionary suitable for direct merging into analysis_context.
    """
    if html is None and fetch_page:
        html = _get_page_html(url)

    # If we still do not have HTML, return a safe default structure.
    if not html:
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
            # COMMENTED/PLACEHOLDER LOGIC:
            # A true design-consistency judgment usually needs rendering,
            # screenshot analysis, or manual review. For now we return False.
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

    # Initialize all detection flags.
    login_form_present = False
    external_form_submission = False
    hidden_iframe = False
    javascript_obfuscation = False
    external_resource_loading = False
    favicon_loaded_from_external_domain = False

    # Check forms.
    for form in forms:
        form_html = str(form).lower()
        if "password" in form_html or "login" in form_html or "signin" in form_html:
            login_form_present = True

        action = form.get("action")
        if action:
            target = urljoin(url, action)
            if _extract_domain(target) != page_domain:
                external_form_submission = True

    # Check iframes.
    for iframe in iframes:
        style = (iframe.get("style") or "").lower()
        width = (iframe.get("width") or "").strip()
        height = (iframe.get("height") or "").strip()

        if "display:none" in style or width == "0" or height == "0":
            hidden_iframe = True

        src = iframe.get("src")
        if src:
            target = urljoin(url, src)
            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    # Check scripts.
    for script in scripts:
        script_text = script.get_text(" ", strip=True)
        if len(script_text) > 300 and re.search(r"(eval\(|fromcharcode|atob\(|unescape\()", script_text, re.IGNORECASE):
            javascript_obfuscation = True

        src = script.get("src")
        if src:
            target = urljoin(url, src)
            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    # Check links (including favicon).
    for link in links:
        href = link.get("href")
        rel = " ".join(link.get("rel", [])).lower()
        if href:
            target = urljoin(url, href)
            if _extract_domain(target) != page_domain:
                external_resource_loading = True
                if "icon" in rel:
                    favicon_loaded_from_external_domain = True

    # Check images.
    for img in imgs:
        src = img.get("src")
        if src:
            target = urljoin(url, src)
            if _extract_domain(target) != page_domain:
                external_resource_loading = True

    # Text-based detections.
    credential_harvesting_language = any(keyword in page_text for keyword in CREDENTIAL_KEYWORDS)
    urgent_threatening_language = any(keyword in page_text for keyword in URGENT_KEYWORDS)
    financial_request_language = any(keyword in page_text for keyword in FINANCIAL_KEYWORDS)
    brand_impersonation = any(brand in page_text for brand in KNOWN_BRANDS)

    # This is a simple heuristic: if the page contains a login form and also has
    # common login text, we flag it as an unexpected login prompt signal.
    unexpected_login_prompt = login_form_present and ("login" in page_text or "sign in" in page_text)

    # Permission requests are hard to detect perfectly from static HTML alone.
    # For now we approximate based on permission-related text appearing in the page.
    permission_keywords = ["notifications", "clipboard", "location", "camera", "microphone"]
    excessive_permission_requests = sum(1 for keyword in permission_keywords if keyword in page_text) >= 2

    no_contact_or_privacy_policy = ("privacy policy" not in page_text) and ("contact us" not in page_text)

    # COMMENTED/PLACEHOLDER LOGIC:
    # A true branding/design consistency detector would need browser rendering or
    # visual comparison against brand assets. This project does not have that
    # data yet, so the indicator is left as False for now.
    inconsistent_branding_or_design = False

    return {
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
        "inconsistent_branding_or_design": inconsistent_branding_or_design,
        "html_analysis_success": True,
        "html_error": None,
    }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
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
      </body>
    </html>
    """
    result = analyze_html_content("https://example.com", html=sample_html)
    print(result)
