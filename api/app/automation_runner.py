"""
automation_runner.py

Runs the phishing intel pipeline automatically in small batches.

This version:
- Does NOT use a CSV file
- Generates domains dynamically each run
- Uses a 70% random / 30% keyword-enhanced split
- Calls main.py's existing analyze_domain() function
- Saves results through the existing SQLite database flow
"""

import logging
import os
import random
import string

from .main import analyze_domain, DomainRequest


# ----------------------------------------------------
# Settings
# ----------------------------------------------------

BATCH_SIZE = 250

TLDs = [".com", ".net", ".org", ".io", ".co", ".info", ".biz"]

KEYWORDS = [
    "login", "secure", "update", "verify", "account",
    "bank", "signin", "auth", "portal", "support",
    "billing", "alert", "confirm"
]

BRANDS = [
    "google", "microsoft", "paypal", "apple", "amazon",
    "facebook", "instagram", "netflix", "linkedin", "gmail",
    "chase", "bankofamerica", "outlook", "office365"
]


# ----------------------------------------------------
# Logging
# ----------------------------------------------------

LOG_FILE = os.path.join(os.path.dirname(__file__), "automation_runner.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


# ----------------------------------------------------
# Domain generation
# ----------------------------------------------------

def random_name(min_length=5, max_length=12):
    length = random.randint(min_length, max_length)
    return "".join(random.choices(string.ascii_lowercase, k=length))


def generate_random_domain():
    return random_name() + random.choice(TLDs)


def generate_keyword_domain():
    base = random_name(4, 8)
    keyword = random.choice(KEYWORDS)

    pattern = random.choice([
        f"{base}-{keyword}",
        f"{keyword}-{base}",
        f"{base}-{keyword}-{random_name(3, 5)}"
    ])

    return pattern + random.choice(TLDs)


def generate_batch():
    domains = []

    for _ in range(BATCH_SIZE):
        roll = random.random()
        if roll < 0.6:
            domains.append(generate_random_domain())
        elif roll < 0.85:
            domains.append(generate_keyword_domain())
        else:
            domains.append(generate_brand_domain())

    return domains

def generate_brand_domain():
    brand = random.choice(BRANDS)
    keyword = random.choice(KEYWORDS)

    pattern = random.choice([
        f"{brand}-{keyword}",
        f"{keyword}-{brand}",
        f"{brand}{random.randint(1,999)}",
        f"{brand}-{random_name(3,5)}",
        f"{brand}{random.choice(['login', 'secure', 'verify'])}"
    ])

    return pattern + random.choice(TLDs)


# ----------------------------------------------------
# Automation runner
# ----------------------------------------------------

def run_automation_batch():
    logging.info("Automation batch started.")

    domains = generate_batch()

    successful_scans = 0
    failed_scans = 0

    for domain in domains:
        try:
            logging.info(f"Scanning domain: {domain}")

            request = DomainRequest(domain=domain)
            result = analyze_domain(request)

            logging.info(
                f"Completed scan: {domain} | "
                f"Risk Level: {result.get('risk_level')} | "
                f"Score: {result.get('risk_score')} | "
                f"Notes: {result.get('notes')}"
            )

            successful_scans += 1

        except Exception as e:
            failed_scans += 1
            logging.error(f"Scan failed for {domain}: {e}")

    logging.info(
        f"Automation batch finished. "
        f"Successful: {successful_scans}, Failed: {failed_scans}"
    )


# ----------------------------------------------------
# Entry point
# ----------------------------------------------------

if __name__ == "__main__":
    print("Starting phishing intel automation batch...")
    run_automation_batch()
    print("Automation batch complete. Check automation_runner.log for details.")