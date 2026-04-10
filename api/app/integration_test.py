"""
integration_test.py

Purpose:
    Simple end-to-end functional test that simulates how main.py would call the
    helper modules and scoring engine WITHOUT changing main.py itself.

Why this file exists:
    The team asked for an easy way to test the submodules independently before
    main.py is wired up to use them.

How to run:
    python integration_test.py

What this test does:
    - Uses local blacklist files if present
    - Uses sample HTML
    - Calls WHOIS / SSL / VirusTotal helpers
    - Merges all returned dictionaries into analysis_context
    - Calls the scoring engine

Notes:
    - VirusTotal will return a safe "no key" message unless you provide a key.
    - WHOIS will return a safe error unless python-whois is installed.
    - SSL requires network access.
"""

from __future__ import annotations

import json
import os

from database_check import check_known_phishing_database
from html_analyzer import analyze_html_content
from phishing_scoring_engine import PhishingScoringEngine
from ssl_check import inspect_ssl_certificate
from virustotal_check import check_virustotal_url
from whois_lookup import lookup_domain_info


def run_integration_test() -> None:
    """Run one simple pipeline test and print everything clearly."""
    test_url = "http://evil-login.xyz/secure-login"

    sample_html = """
    <html>
      <head>
        <title>Verify Your Account</title>
        <link rel="icon" href="https://evil-login.xyz/favicon.ico">
      </head>
      <body>
        <h1>PayPal Security Alert</h1>
        <p>Your account will be locked. Act now.</p>
        <form action="https://evil-login.xyz/post">
          <input type="text" name="email">
          <input type="password" name="password">
        </form>
      </body>
    </html>
    """

    # Pull API key from environment if available.
    vt_api_key = os.getenv("VT_API_KEY")

    analysis_context = {}

    # Merge each helper's output into one shared analysis_context dictionary.
    analysis_context.update(
        check_known_phishing_database(
            test_url,
            url_blacklist_file="known_bad_urls.txt",
            domain_blacklist_file="known_bad_domains.txt",
            json_cache_file=".known_phishing_cache.json",
        )
    )
    analysis_context.update(lookup_domain_info(test_url))
    analysis_context.update(inspect_ssl_certificate(test_url))
    analysis_context.update(check_virustotal_url(test_url, vt_api_key))
    analysis_context.update(analyze_html_content(test_url, html=sample_html))

    engine = PhishingScoringEngine()
    result = engine.score_url(
        url=test_url,
        displayed_url="https://paypal.com",
        analysis_context=analysis_context,
    )

    print("\n=== MERGED ANALYSIS CONTEXT ===")
    print(json.dumps(analysis_context, indent=2, default=str))

    print("\n=== FINAL PHISHING SCORE RESULT ===")
    print(json.dumps(result.to_dict(), indent=2, default=str))


if __name__ == "__main__":
    run_integration_test()
