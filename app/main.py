"""
main.py — FastAPI layer over engine.py. Exposes:
  POST /scans          — start a scan, returns scan_id immediately
  GET  /scans/{id}      — poll for status/results
  GET  /scans/{id}/stream — Server-Sent Events stream of live progress
  GET  /owasp-categories — list categories for the UI checkboxes

Run with: uvicorn main:app --reload --port 8000
"""

import json
import queue
import threading
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from engine import run_scan
from rag import OwaspRAG

app = FastAPI(title="SentinelAI API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local dev only — tighten before deploying anywhere
    allow_methods=["*"],
    allow_headers=["*"],
)

_rag = OwaspRAG()
_scans: dict[str, dict] = {}
_streams: dict[str, "queue.Queue"] = {}


class ScanRequest(BaseModel):
    target_url: str
    endpoints: list[dict] | None = None
    categories: list[str] | None = None


DEFAULT_ENDPOINTS = [
    {"method": "GET", "path": "/api/v1/users/search"},
    {"method": "POST", "path": "/api/v1/orders/{id}/refund"},
    {"method": "POST", "path": "/api/v1/auth/login"},
    {"method": "GET", "path": "/api/v1/health"},
]


@app.get("/owasp-categories")
def owasp_categories():
    return [{"id": e.owasp_id, "category": e.category} for e in
             [type("C", (), {"owasp_id": e["id"], "category": e["category"]}) for e in _rag.entries]]


@app.post("/scans")
def create_scan(req: ScanRequest):
    scan_id = str(uuid.uuid4())[:8]
    q: "queue.Queue" = queue.Queue()
    _streams[scan_id] = q
    _scans[scan_id] = {"status": "running", "result": None}

    def progress_cb(event):
        q.put(event)

    def worker():
        result = run_scan(
            req.target_url,
            req.endpoints or DEFAULT_ENDPOINTS,
            categories=req.categories,
            progress_cb=progress_cb,
        )
        _scans[scan_id] = {"status": "done", "result": result}
        q.put({"type": "__end__"})

    threading.Thread(target=worker, daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    return _scans.get(scan_id, {"status": "not_found"})


@app.get("/scans/{scan_id}/stream")
def stream_scan(scan_id: str):
    q = _streams.get(scan_id)
    if q is None:
        return {"error": "unknown scan_id"}

    def event_gen():
        while True:
            event = q.get()
            if event.get("type") == "__end__":
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_gen(), media_type="text/event-stream")
