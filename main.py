from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
import requests
import httpx
from database import create_tables, save_cve, get_connection,COLUMN_DICT


app = FastAPI()

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE = "cpe:2.3:o:microsoft:windows_10:1607"
# setup templates directory
templates = Jinja2Templates(directory="templates")

# Homepage with two buttons
@app.get("/")
def home(request: Request):
    create_tables()
    return templates.TemplateResponse("main.html", {"request": request})


# Fetch and store data, then redirect to /view
@app.get("/fetch-and-store")
async def fetch_and_store_nist_data():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:o:microsoft:windows_10:1607"
            )
        response.raise_for_status()
        data = response.json()

        for item in data.get("vulnerabilities", []):
            save_cve(item)

        return RedirectResponse(url="/display", status_code=303)
    except Exception as e:
        return {"error": str(e)}

# View data as an HTML table
@app.get("/display")
def view_cves(request: Request):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve")
    cves = cursor.fetchall()
    conn.close()

    columns = COLUMN_DICT.keys()
    cve_list = [dict(zip(columns, row)) for row in cves]

    return templates.TemplateResponse("display.html", {"request": request, "cves": cve_list})
