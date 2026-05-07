import sqlite3
from pathlib import Path

# Finds analysis_results.db in the same folder as this script
db_path = Path(__file__).parent / "analysis_results.db"

print("Using database:", db_path)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT domain FROM analysis_results")
rows = cursor.fetchall()

print("Rows found:", len(rows))

with open("extracted_domains.txt", "w") as f:
    for row in rows:
        domain = row[0].replace("https://", "").replace("http://", "")
        f.write(domain + "\n")

conn.close()

print("Done. Saved domains to extracted_domains.txt")