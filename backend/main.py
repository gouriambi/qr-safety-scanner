from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from security_checks import full_scan

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    content: str

@app.post("/scan")
def scan(req: ScanRequest):
    return full_scan(req.content)