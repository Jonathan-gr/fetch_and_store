import sqlite3

conn = sqlite3.connect("cves.db")
cursor = conn.cursor()

# Fetch data
cursor.execute("SELECT * FROM cve LIMIT 5")
rows = cursor.fetchall()

# Define column names (same as in your table)
columns = [
    "id",
    "published",
    "last_modified",
    "description",
    "cvss_v3_score",

    "cvss_v3_severity",
    "cvss_v2_score",

    "cvss_v2_severity",
    "reference_urls"
]

# Convert each row tuple into a dictionary
cve_dicts = [dict(zip(columns, row)) for row in rows]
print(len(cve_dicts))
# Print nicely
for cve in cve_dicts:
    print(cve)
    print("-----------------------")

cursor.execute("DROP TABLE IF EXISTS cve")

