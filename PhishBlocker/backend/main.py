"""
PhishBlocker - Backend API
---------------------------
FastAPI service exposing:
  POST /analyze     -> URL Risk Engine (Phase 1)
  POST /telemetry    -> Endpoint telemetry ingestion (Phase 3, stub)
  GET  /incidents     -> Simple correlated-incident feed (Phase 9, stub)
  GET  /health        -> liveness check

Run with:  uvicorn main:app --reload --port 8000
"""
import uuid
from datetime import datetime, timezone
from collections import deque

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from models import (
    URLAnalysisRequest, URLAnalysisResponse,
    TelemetryEvent, TelemetryAck,
)
from risk_engine import analyze_url

app = FastAPI(
    title="PhishBlocker API",
    description="Defensive URL risk analysis & telemetry correlation backend",
    version="0.1.0",
)

# Allow the browser extension (runs from a chrome-extension:// origin) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # tighten this to your extension ID in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-memory stores (swap for SQLite/Postgres per the roadmap's Phase 2) ---
analysis_log = deque(maxlen=500)
telemetry_log = deque(maxlen=500)
incidents = deque(maxlen=100)


@app.get("/health")
def health():
    return {"status": "ok", "service": "PhishBlocker", "time": datetime.now(timezone.utc)}


@app.post("/analyze", response_model=URLAnalysisResponse)
def analyze(request: URLAnalysisRequest):
    """Core URL Risk Engine endpoint -- Phase 1 of the roadmap."""
    result = analyze_url(request.url)
    result["analyzed_at"] = datetime.now(timezone.utc)

    record = {**result, "source": request.source}
    analysis_log.append(record)

    # Simple correlation trigger: repeated CRITICAL hits from the same source
    if result["verdict"] == "BLOCK":
        _maybe_correlate()

    return result


@app.post("/telemetry", response_model=TelemetryAck)
def ingest_telemetry(event: TelemetryEvent):
    """Endpoint telemetry ingestion -- Phase 3 stub. Accepts synthetic
    events from the Go agent and stores them for correlation."""
    event_id = str(uuid.uuid4())
    telemetry_log.append({"id": event_id, **event.dict(), "received_at": datetime.now(timezone.utc)})

    correlated = _maybe_correlate()
    return TelemetryAck(received=True, event_id=event_id, correlated_incident=correlated)


@app.get("/incidents")
def get_incidents():
    return list(incidents)


@app.get("/log/analysis")
def get_analysis_log():
    return list(analysis_log)


@app.get("/log/telemetry")
def get_telemetry_log():
    return list(telemetry_log)


def _maybe_correlate() -> str | None:
    """Minimal stand-in for Phase 9 (Attack Correlation). If we have both
    a recent BLOCK-level URL verdict and a recent high-severity telemetry
    event, raise a single correlated incident."""
    recent_block = any(a["verdict"] == "BLOCK" for a in list(analysis_log)[-5:])
    recent_high_telemetry = any(
        t.get("severity") in ("HIGH", "CRITICAL") for t in list(telemetry_log)[-5:]
    )
    if recent_block and recent_high_telemetry:
        incident_id = f"INC-{len(incidents) + 1:04d}"
        incidents.append({
            "id": incident_id,
            "title": "Potential Multi-Stage Compromise Detected",
            "created_at": datetime.now(timezone.utc),
            "status": "OPEN",
        })
        return incident_id
    return None
