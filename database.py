import sqlite3
from pathlib import Path
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

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

#check if url is malicious
def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.netloc:
            return False
        # Block local/loopback/internal hosts
        forbidden_hosts = ("localhost", "127.", "0.0.0.0", "[::1]")
        if parsed.hostname and parsed.hostname.startswith(forbidden_hosts):
            return False
        return True
    except Exception:
        return False

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
    values_dict['published'] = clean_datetime(item["cve"]["published"])
    values_dict['last_modified'] = clean_datetime(item["cve"]["lastModified"])
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
    safe_refs = [ref["url"] for ref in refs if is_safe_url(ref["url"])]
    values_dict['reference_urls'] = ",".join(safe_refs)

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

def clean_datetime(dt_str):
    # Parse full string, ignoring milliseconds if they exist
    return datetime.fromisoformat(dt_str.split(".")[0]).strftime("%Y-%m-%d %H:%M:%S")

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
            'reference_urls': ",".join(
                ref["url"] for ref in item["cve"]["references"] if is_safe_url(ref["url"])
            )
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

def get_cve_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve")
    cves = [dict(zip(COLUMN_DICT.keys(), row)) for row in cursor.fetchall()]
    conn.close()
    return cves

def load_cve_dataframe():
    cves  = get_cve_table()
    df = pd.DataFrame(cves)
    return df

def delete_all_from_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cve")
    conn.commit()
    conn.close()


def make_df_ready_for_display():
    try:
        df = load_cve_dataframe()
        if df.empty:
            print("No CVE data found in database.")
            return []

        # Convert dates
        df['published'] = pd.to_datetime(df['published'], errors='coerce').dt.strftime('%Y-%m-%d')
        df['last_modified'] = pd.to_datetime(df['last_modified'], errors='coerce').dt.strftime('%Y-%m-%d')

        # Replace NaN with None
        df = df.where(pd.notnull(df), None)

        # Convert DataFrame to list of dicts (NOT JSON string)
        return df.to_dict(orient="records")
    except Exception as e:
        print(f"Error preparing DataFrame: {e}")
        return []
