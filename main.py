
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def read_root():
    return {"message": "Hllo, FastAPI is runhuning!"}

@app.get("/hello/{name}")
def say_hello(name: str):
    return {"message": f"Hello {name}"}