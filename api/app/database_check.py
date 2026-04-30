from __future__ import annotations

import time
import requests
from typing import Dict, Set


# openphish public phishing feed
OPENPHISH_URL = "https://openphish.com/feed.txt"


# cache so feed is not downloaded every request
openphishCache = {
    "data": set(),
    "lastUpdated": 0
}


# normalize urls so comparisons are consistent
def normalizeUrl(url: str) -> str:

    # remove spaces and lowercase everything
    url = url.strip().lower()

    # add http if scheme is missing
    if "://" not in url:
        url = f"http://{url}"

    return url


# download openphish feed
def loadOpenPhishFeed() -> Set[str]:

    global openphishCache

    # use cached feed if downloaded recently
    if time.time() - openphishCache["lastUpdated"] < 300:
        return openphishCache["data"]

    try:

        # request phishing feed
        response = requests.get(OPENPHISH_URL, timeout=10)

        # store phishing urls
        urls = set()

        # process each line in feed
        for line in response.text.splitlines():

            # clean formatting
            entry = line.strip().lower()

            # ignore blank lines
            if entry:
                urls.add(entry)

        # update cache data
        openphishCache["data"] = urls

        # update cache timestamp
        openphishCache["lastUpdated"] = time.time()

        return urls

    # return old cache if request fails
    except Exception:
        return openphishCache["data"]


# main phishing database check
def check_known_phishing_database(url: str) -> Dict[str, object]:

    # starting score
    score = 0

    # list of findings
    details = []

    try:

        # normalize user url
        normalizedUrl = normalizeUrl(url)

        # load phishing database
        openphishData = loadOpenPhishFeed()

        # check for exact url match
        if normalizedUrl in openphishData:

            # high confidence phishing match
            score += 400

            # add finding message
            details.append("URL found in known phishing database.")

            return {
                "score": score,
                "status": "completed",
                "details": details
            }

        # no phishing match found
        details.append("No match in known phishing database.")

        return {
            "score": score,
            "status": "completed",
            "details": details
        }

    # handle unexpected errors
    except Exception as e:

        return {
            "score": 0,
            "status": "error",
            "details": [f"Database check failed: {str(e)}"]
        }