"""
database_check.py

Purpose:
    Provide a simple, importable phishing-database lookup module that main.py
    can call without needing to know how the lookup works internally.

What this module currently supports:
    1. Local exact-match URL blacklist files
    2. Local exact-match domain blacklist files
    3. Optional JSON cache file containing known phishing URLs/domains

What this module does NOT currently do by itself:
    - Download live PhishTank / URLhaus feeds automatically
    - Query a remote threat-intel API

If your team wants live feed support later, that code can be added here without
changing the function that main.py calls.

Main callable function:
    check_known_phishing_database(url, url_blacklist_file=None,
                                  domain_blacklist_file=None,
                                  json_cache_file=None)

Returned keys are designed to merge directly into analysis_context.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional, Set
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """
    Normalize a URL for matching.

    Why this matters:
        Blacklist matching is fragile if the incoming URL changes format.
        For example, these are often intended to mean the same thing:
            evil-login.xyz
            http://evil-login.xyz
            HTTP://EVIL-LOGIN.XYZ

    This helper gives us a consistent lower-case format and adds a scheme when
    the caller did not include one.
    """
    url = url.strip().lower()
    if "://" not in url:
        url = f"http://{url}"
    return url


def _extract_domain(url: str) -> str:
    """
    Extract the network location / host portion of a URL.

    Example:
        https://evil-login.xyz/secure -> evil-login.xyz
    """
    parsed = urlparse(_normalize_url(url))
    return parsed.netloc.lower().split(":")[0]


def _load_lines(filepath: Optional[str]) -> Set[str]:
    """
    Load line-based blacklist entries from a text file.

    Supported file format:
        - one domain or URL per line
        - blank lines are ignored
        - lines starting with # are ignored

    If the file does not exist, we return an empty set instead of failing.
    This keeps main.py safe even if the blacklist files have not been created
    yet.
    """
    if not filepath:
        return set()

    path = Path(filepath)
    if not path.exists():
        return set()

    values: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip().lower()
        if not entry or entry.startswith("#"):
            continue
        values.add(entry)
    return values


def _load_json_cache(filepath: Optional[str]) -> Dict[str, Set[str]]:
    """
    Load an optional JSON cache file.

    Expected JSON shape:
        {
            "urls": ["http://bad.example/login", ...],
            "domains": ["bad.example", ...]
        }

    If the file is missing or invalid, we safely return empty sets.
    """
    if not filepath:
        return {"urls": set(), "domains": set()}

    path = Path(filepath)
    if not path.exists():
        return {"urls": set(), "domains": set()}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            "urls": {str(item).strip().lower() for item in data.get("urls", [])},
            "domains": {str(item).strip().lower() for item in data.get("domains", [])},
        }
    except Exception:
        return {"urls": set(), "domains": set()}


# ---------------------------------------------------------------------------
# MAIN CALLABLE FUNCTION
# ---------------------------------------------------------------------------

def check_known_phishing_database(
    url: str,
    url_blacklist_file: Optional[str] = None,
    domain_blacklist_file: Optional[str] = None,
    json_cache_file: Optional[str] = None,
) -> Dict[str, object]:
    """
    Check whether a URL or its domain exists in a known phishing database.

    This is intentionally simple and reliable so main.py can call it directly.

    Parameters:
        url:
            The URL to check.
        url_blacklist_file:
            Optional text file containing full URLs to block.
        domain_blacklist_file:
            Optional text file containing domains to block.
        json_cache_file:
            Optional JSON cache file with "urls" and/or "domains" arrays.

    Returns:
        A dictionary suitable for merging into analysis_context.
    """
    normalized_url = _normalize_url(url)
    domain = _extract_domain(normalized_url)

    # Load all local sources.
    url_blacklist = { _normalize_url(item) for item in _load_lines(url_blacklist_file) }
    domain_blacklist = { item.strip().lower() for item in _load_lines(domain_blacklist_file) }
    json_cache = _load_json_cache(json_cache_file)

    # Merge file-based and JSON-based sources into one lookup set.
    known_urls = set(url_blacklist) | { _normalize_url(item) for item in json_cache["urls"] }
    known_domains = set(domain_blacklist) | { item.strip().lower() for item in json_cache["domains"] }

    # 1. Exact URL match.
    if normalized_url in known_urls:
        return {
            "found_in_known_phishing_database": True,
            "database_match_type": "url",
            "database_match_value": normalized_url,
            "database_lookup_success": True,
            "database_error": None,
        }

    # 2. Exact domain match.
    if domain in known_domains:
        return {
            "found_in_known_phishing_database": True,
            "database_match_type": "domain",
            "database_match_value": domain,
            "database_lookup_success": True,
            "database_error": None,
        }

    # 3. No match.
    return {
        "found_in_known_phishing_database": False,
        "database_match_type": None,
        "database_match_value": None,
        "database_lookup_success": True,
        "database_error": None,
    }


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    """
    Easy local test:
        1. Create known_bad_domains.txt with a line like: evil-login.xyz
        2. Create known_bad_urls.txt with a line like: http://evil-login.xyz/secure
        3. Run: python database_check.py
    """
    result = check_known_phishing_database(
        url="http://evil-login.xyz/secure",
        url_blacklist_file="known_bad_urls.txt",
        domain_blacklist_file="known_bad_domains.txt",
        json_cache_file=".known_phishing_cache.json",
    )
    print(result)
