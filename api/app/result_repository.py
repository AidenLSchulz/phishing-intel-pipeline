import json
import os
from datetime import datetime

# Path to results file
DATA_FILE = os.path.join(os.path.dirname(__file__), "analysis_results.json")


def _load_data():
    # Load existing results, or return empty list if file doesn't exist
    if not os.path.exists(DATA_FILE):
        return []

    with open(DATA_FILE, "r") as f:
        return json.load(f)


def _save_data(data):
    # Save updated results back to file
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)


def normalize_domain(domain: str) -> str:
    # Standardize domain format (prevents duplicates)
    return domain.lower().strip()


def domain_exists(domain: str) -> bool:
    # Check if domain already exists in stored results
    domain = normalize_domain(domain)
    data = _load_data()

    return any(entry["domain"] == domain for entry in data)


def save_result(result: dict) -> bool:
    data = _load_data()

    # Prevent duplicate entries
    if domain_exists(result["domain"]):
        return False

    # Save new result
    data.append(result)
    _save_data(data)

    return True