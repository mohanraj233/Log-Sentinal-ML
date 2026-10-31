from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class LogRecord(BaseModel):
    log_id: str
    timestamp: str
    ip: str
    method: str
    path: str
    status: int
    bytes_sent: int
    user_agent: str
    referer: str
    username: str
    auth_result: str
    response_time_ms: int
    endpoint: str
    protocol: str
    host: str
    request_size_bytes: int
    session_id: str
    country: str

class SingleLogPayload(BaseModel):
    current_log: LogRecord
    historical_window: List[LogRecord] = []

class AlertDetails(BaseModel):
    alert_id: str
    rule_id: str
    scenario: str
    title: str
    severity: str
    source_ip: str
    username: Optional[str] = "-"
    event_count: Optional[int] = None
    detection_source: str
    evidence: List[str]
    status: str = "needs_review"
    recommendation: Optional[str] = None
    additional_metadata: Optional[Dict[str, Any]] = None

class ScoreResponse(BaseModel):
    is_suspicious: bool
    anomaly_score: float
    triggered_rules: List[str]
    alerts: List[AlertDetails]

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str
    unsupervised_threshold: float
