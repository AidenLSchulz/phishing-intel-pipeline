"""
database_check.py

Purpose:
Check submitted URLs and domains against the OpenPhish phishing database.

This module downloads the OpenPhish phishing feed and checks if a
submitted URL or its domain exists in the feed.

Returned values are structured so they can merge directly into
analysis_context in the phishing detection system.
"""

from __future__ import annotations

import time
import requests
from typing import Dict, Set
from urllib.parse import urlparse


# openphish public phishing feed
OPENPHISH_URL = "https://openphish.com/feed.txt"


# cache so the feed is not downloaded every request
openphishCache = {
    "data": set(),
    "lastUpdated": 0
}


# normalize urls so comparisons are consistent
def normalizeUrl(url: str) -> str:
    url = url.strip().lower()

    # add scheme if not provided
    if "://" not in url:
        url = f"http://{url}"

    return url


# extract the domain from a url
def extractDomain(url: str) -> str:
    parsed = urlparse(normalizeUrl(url))

    # remove port numbers if present
    return parsed.netloc.lower().split(":")[0]


# download the openphish feed
# cache result for 5 minutes
def loadOpenPhishFeed() -> Set[str]:

    global openphishCache

    # return cached data if still fresh
    if time.time() - openphishCache["lastUpdated"] < 300:
        return openphishCache["data"]

    try:
        response = requests.get(OPENPHISH_URL, timeout=10)

        urls = set()

        # each line is a phishing url
        for line in response.text.splitlines():
            entry = line.strip().lower()

            if entry:
                urls.add(entry)

        # update cache
        openphishCache["data"] = urls
        openphishCache["lastUpdated"] = time.time()

        return urls

    # if request fails return previous cache
    except Exception:
        return openphishCache["data"]


# main function used by the system
def check_known_phishing_database(url: str) -> Dict[str, object]:

    try:
        normalizedUrl = normalizeUrl(url)
        domain = extractDomain(normalizedUrl)

        openphishData = loadOpenPhishFeed()

        # check exact url match
        if normalizedUrl in openphishData:
            return {
                "found_in_known_phishing_database": True,
                "openphish_checked": True,
                "openphish_match_type": "url",
                "openphish_match_value": normalizedUrl,
                "openphish_error": None
            }

        # check domain match
        for entry in openphishData:
            try:
                entryDomain = urlparse(entry).netloc.lower()

                if domain == entryDomain:
                    return {
                        "found_in_known_phishing_database": True,
                        "openphish_checked": True,
                        "openphish_match_type": "domain",
                        "openphish_match_value": domain,
                        "openphish_error": None
                    }

            except Exception:
                continue

        # no match found
        return {
            "found_in_known_phishing_database": False,
            "openphish_checked": True,
            "openphish_match_type": None,
            "openphish_match_value": None,
            "openphish_error": None
        }

    # catch errors so system does not crash
    except Exception as e:
        return {
            "found_in_known_phishing_database": False,
            "openphish_checked": True,
            "openphish_match_type": None,
            "openphish_match_value": None,
            "openphish_error": str(e)
        }