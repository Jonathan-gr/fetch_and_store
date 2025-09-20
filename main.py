from fastapi import FastAPI
import requests
from database import create_tables, save_cve, get_connection

app = FastAPI()


# Initialize database tables on startup
@app.get("/")
def startup_event():
    create_tables()
    return {"databse created"}


# Endpoint to fetch and store NIST CVE data (synchronous)
@app.get("/fetch-and-store")
def fetch_and_store_nist_data():
    try:
        # Fetch limited data to avoid overwhelming response
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607")
        response.raise_for_status()  # Check for HTTP errors
        data = response.json()

        # Process and store each CVE item
        cve_items = data.get("vulnerabilities", [])
        for item in cve_items:
            save_cve(item)  # Use your save_cve function

        return {"message": f"Stored {len(cve_items)} CVEs successfully"}
    except requests.exceptions.HTTPError as e:
        return {"error": f"Failed to fetch data: {str(e)}"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}


# Endpoint to retrieve stored CVEs as JSON
@app.get("/cves")
def get_cves_json():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve")
    cves = cursor.fetchall()
    conn.close()

    # Convert rows to list of dicts for JSON response
    columns = ["id", "published", "last_modified", "description", "cvss_v3_score",
               "cvss_v3_vector", "cvss_v2_score", "cvss_v2_vector", "reference_urls"]
    cve_list = [dict(zip(columns, row)) for row in cves]

    return cve_list