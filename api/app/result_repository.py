import json
import os
import sqlite3
from datetime import datetime

# SQLite database file
DB_FILE = os.path.join(os.path.dirname(__file__), "analysis_results.db")


def get_connection():
    return sqlite3.connect(DB_FILE)


def initialize_database():
    """
    Creates the analysis_results table if it does not already exist.
    The domain column is UNIQUE, which prevents duplicate stored results.
    """

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                final_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                indicators TEXT,
                raw_results TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()


def normalize_domain(domain: str) -> str:
    """
    Standardizes domain format before checking or saving.
    """

    return domain.lower().strip()


def domain_exists(domain: str) -> bool:
    """
    Checks whether a domain already exists in the database.
    """

    initialize_database()

    domain = normalize_domain(domain)

    with get_connection() as conn:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT 1 FROM analysis_results WHERE domain = ? LIMIT 1",
            (domain,)
        )

        return cursor.fetchone() is not None


def save_result(result: dict) -> bool:
    """
    Saves a new analysis result.

    Returns:
        True if saved
        False if duplicate and skipped
    """

    initialize_database()

    domain = normalize_domain(result["domain"])

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO analysis_results (
                    domain,
                    final_score,
                    risk_level,
                    indicators,
                    raw_results,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                domain,
                result.get("final_score", 0),
                result.get("risk_level", "Safe"),
                json.dumps(result.get("indicators", [])),
                json.dumps(result.get("raw_results", {})),
                result.get("timestamp", datetime.utcnow().isoformat())
            ))

            conn.commit()

        return True

    except sqlite3.IntegrityError:
        # Duplicate domain was blocked by UNIQUE constraint
        return False