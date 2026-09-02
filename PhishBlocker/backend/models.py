"""
PhishBlocker - API data models
"""
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze")
    source: Optional[str] = Field(
        default="browser_extension",
        description="Where this URL came from, e.g. browser_extension, sms, email"
    )


class SignalHit(BaseModel):
    name: str
    weight: int
    detail: str


class URLAnalysisResponse(BaseModel):
    url: str
    risk_score: int
    verdict: str  # SAFE / WARN / BLOCK
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    signals: List[SignalHit]
    threat_category: Optional[str] = None
    analyzed_at: datetime


class TelemetryEvent(BaseModel):
    device_id: str
    event_type: str          # e.g. "process_start", "powershell_command"
    description: str
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    severity: Optional[str] = "LOW"


class TelemetryAck(BaseModel):
    received: bool
    event_id: str
    correlated_incident: Optional[str] = None
