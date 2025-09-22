import sqlite3
from pathlib import Path

DB_FILE = Path("cves.db")

COLUMN_DICT = {
    "id": "TEXT PRIMARY KEY",
    "published": "TEXT",
    "last_modified": "TEXT",
    "description": "TEXT",
    "cvss_v3_score": "REAL",
    "cvss_v3_severity": "TEXT",
    "cvss_v2_score": "REAL",
    "cvss_v2_severity": "TEXT",
    "reference_urls": "TEXT",
}

def get_connection():
    return sqlite3.connect(str(DB_FILE))  # Convert Path to str for sqlite

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    column_defs = ",\n    ".join(f"{col} {col_type}" for col, col_type in COLUMN_DICT.items())
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS cve (
            {column_defs}
        )
    """)
    conn.commit()
    conn.close()

def save_cve(item):

    values_dict = {}

    # Extract values from API
    values_dict['id'] = item["cve"]["id"]
    values_dict['published'] = item["cve"]["published"]
    values_dict['last_modified'] = item["cve"]["lastModified"]
    values_dict['description'] = item["cve"]["descriptions"][0]["value"]

    # CVSS v3
    cvss_v3 = item["cve"]["metrics"].get("cvssMetricV31") or item["cve"]["metrics"].get("cvssMetricV30")
    values_dict['cvss_v3_score'] = cvss_v3[0]["cvssData"]["baseScore"] if cvss_v3 else None
    values_dict['cvss_v3_severity'] = cvss_v3[0]["cvssData"]["baseSeverity"] if cvss_v3 else None

    # CVSS v2
    cvss_v2 = item["cve"]["metrics"].get("cvssMetricV2")
    values_dict['cvss_v2_score'] = cvss_v2[0]["cvssData"]["baseScore"] if cvss_v2 else None
    values_dict['cvss_v2_severity'] = cvss_v2[0]["baseSeverity"] if cvss_v2 else None

    # References
    refs = item["cve"]["references"]
    values_dict['reference_urls'] = ",".join(ref["url"] for ref in refs)

    # Save to database
    conn = get_connection()
    cursor = conn.cursor()
    columns = ", ".join(COLUMN_DICT.keys())
    placeholders = ", ".join("?" for _ in COLUMN_DICT)
    sql = f"INSERT OR REPLACE INTO cve ({columns}) VALUES ({placeholders})"
    cursor.execute(sql, tuple(values_dict[col] for col in COLUMN_DICT.keys()))
    conn.commit()
    conn.close()

    return values_dict  # Return the processed CVE data for streaming

def save_cve_batch(cve_items):


    if not cve_items:
        return []

    conn = get_connection()
    cursor = conn.cursor()
    columns = ", ".join(COLUMN_DICT.keys())
    placeholders = ", ".join("?" for _ in COLUMN_DICT)
    sql = f"INSERT OR REPLACE INTO cve ({columns}) VALUES ({placeholders})"

    cve_data_list = []
    for item in cve_items:
        values_dict = {
            'id': item["cve"]["id"],
            'published': item["cve"]["published"],
            'last_modified': item["cve"]["lastModified"],
            'description': item["cve"]["descriptions"][0]["value"],
            # CVSS v3
            'cvss_v3_score': None,
            'cvss_v3_severity': None,
            # CVSS v2
            'cvss_v2_score': None,
            'cvss_v2_severity': None,
            'reference_urls': ",".join(ref["url"] for ref in item["cve"]["references"])
        }
        cvss_v3 = item["cve"]["metrics"].get("cvssMetricV31") or item["cve"]["metrics"].get("cvssMetricV30")
        if cvss_v3:
            values_dict['cvss_v3_score'] = cvss_v3[0]["cvssData"]["baseScore"]
            values_dict['cvss_v3_severity'] = cvss_v3[0]["cvssData"]["baseSeverity"]
        cvss_v2 = item["cve"]["metrics"].get("cvssMetricV2")
        if cvss_v2:
            values_dict['cvss_v2_score'] = cvss_v2[0]["cvssData"]["baseScore"]
            values_dict['cvss_v2_severity'] = cvss_v2[0]["baseSeverity"]

        cve_data_list.append(values_dict)

    # Batch insert
    cursor.executemany(sql, [tuple(cve[col] for col in COLUMN_DICT.keys()) for cve in cve_data_list])
    conn.commit()
    conn.close()

    return cve_data_list  # Return the list of processed CVE data for streaming

