import sqlite3
from pathlib import Path

DB_FILE = Path("cves.db")

def get_connection():
    return sqlite3.connect(str(DB_FILE))  # Convert Path to str for sqlite

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY,
            published TEXT,
            last_modified TEXT,
            description TEXT,
            cvss_v3_score REAL,
            cvss_v3_vector TEXT,
            cvss_v2_score REAL,
            cvss_v2_vector TEXT,
            reference_urls TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_cve(cve_item):
    cve = cve_item["cve"]
    metrics = cve.get("metrics", {})

    # English description
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    # CVSS v3 (sometimes cvssMetricV31)
    cvss_v3 = metrics.get("cvssMetricV31", [{}])
    cvss_v3_score = cvss_v3[0].get("cvssData", {}).get("baseScore") if cvss_v3 else None
    cvss_v3_vector = cvss_v3[0].get("cvssData", {}).get("vectorString") if cvss_v3 else None

    # CVSS v2
    cvss_v2 = metrics.get("cvssMetricV2", [{}])
    cvss_v2_score = cvss_v2[0].get("cvssData", {}).get("baseScore") if cvss_v2 else None
    cvss_v2_vector = cvss_v2[0].get("cvssData", {}).get("vectorString") if cvss_v2 else None

    # References
    references = cve.get("references", [])
    refs = ",".join([r["url"] for r in references])  # Store as comma-separated string

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO cve
        (id, published, last_modified, description, cvss_v3_score, cvss_v3_vector,
         cvss_v2_score, cvss_v2_vector, reference_urls)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        cve["id"], cve["published"], cve["lastModified"], desc_en,
        cvss_v3_score, cvss_v3_vector,
        cvss_v2_score, cvss_v2_vector,
        refs
    ))
    conn.commit()
    conn.close()
