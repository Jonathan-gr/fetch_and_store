import sqlite3
from pathlib import Path

DB_FILE = Path("cves.db")
urls = None
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
            cvss_v3_severity TEXT,  
            cvss_v2_score REAL,
            cvss_v2_severity TEXT,  
            reference_urls TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_cve(item):
    conn = get_connection()
    cursor = conn.cursor()

    cve_id = item["cve"]["id"]
    published = item["cve"]["published"]
    last_modified = item["cve"]["lastModified"]
    description = item["cve"]["descriptions"][0]["value"]

    # CVSS v3
    cvss_v3 = item["cve"]["metrics"].get("cvssMetricV31") or item["cve"]["metrics"].get("cvssMetricV30")
    cvss_v3_score = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else None
    #cvss_v3_vector = cvss_v3[0]["cvssData"]["vectorString"] if cvss_v3 else None
    cvss_v3_severity = cvss_v3[0]["cvssData"]["baseSeverity"] if cvss_v3 else None

    # CVSS v2
    cvss_v2 = item["cve"]["metrics"].get("cvssMetricV2")
    cvss_v2_score = cvss_v2[0]["cvssData"]["baseScore"] if cvss_v2 else None
    #cvss_v2_vector = cvss_v2[0]["cvssData"]["vectorString"] if cvss_v2 else None
    cvss_v2_severity = cvss_v2[0]["baseSeverity"] if cvss_v2 else None

    # References
    refs = item["cve"]["references"]
    print(refs)
    reference_urls = ",".join(ref["url"] for ref in refs)

    cursor.execute("""
        INSERT OR REPLACE INTO cve (
            id, published, last_modified, description,
            cvss_v3_score, cvss_v3_severity,
            cvss_v2_score, cvss_v2_severity,
            reference_urls
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        cve_id, published, last_modified, description,
        cvss_v3_score, cvss_v3_severity,
        cvss_v2_score, cvss_v2_severity,
        reference_urls
    ))

    conn.commit()
    conn.close()

