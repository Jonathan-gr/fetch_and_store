from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import httpx
import json
from database import create_tables, save_cve, get_connection, COLUMN_DICT
import asyncio

app = FastAPI()

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE = "cpe:2.3:o:microsoft:windows_10:1607"
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Homepage with two buttons
@app.get("/")
def home(request: Request):
    create_tables()
    return templates.TemplateResponse("main.html", {"request": request})


# Stream CVE data using Server-Sent Events
@app.get("/stream-cves")
async def stream_cves():
    async def event_stream():
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{API_URL}?cpeName={CPE}"
                )
                response.raise_for_status()
                data = response.json()

                cve_batch = []
                batch_size = 20  # Send data in chunks of 20 CVEs

                for item in data.get("vulnerabilities", []):
                    cve = save_cve(item)  # Assume save_cve returns the saved CVE as a dict
                    if cve:
                        cve_batch.append(cve)

                    if len(cve_batch) >= batch_size:
                        # Send batch as SSE event
                        yield f"data: {json.dumps(cve_batch)}\n\n"
                        cve_batch = []  # Reset batch
                        await asyncio.sleep(0.1)  # Small delay to prevent overwhelming the client

                # Send any remaining CVEs
                if cve_batch:
                    yield f"data: {json.dumps(cve_batch)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# View data as an HTML table with SSE support
@app.get("/display")
def view_cves(request: Request):
    return templates.TemplateResponse("display.html", {"request": request})

@app.get("/display-stored")
def display_stored_cves(request: Request):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve")
    cves = [dict(zip(COLUMN_DICT.keys(), row)) for row in cursor.fetchall()]
    conn.close()
    if not cves:
        return templates.TemplateResponse(
        "error.html",
        {"request": request, "message": "No CVEs found in the database. You must fetch them first"}
    )
    return templates.TemplateResponse(
        "display_table.html",
        {"request": request, "cves": cves}
    )
