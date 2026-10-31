import pytest
import pandas as pd
from fastapi.testclient import TestClient
import sys
import os

sys.path.append(os.path.abspath("LogSentinel_ML/api"))

from main import app
from detection_rules import run_rule_based_detection

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]

def test_deterministic_rules():
    # Test SQL injection rule detection logic
    mock_data = pd.DataFrame([
        {
            "log_id": "LOG-TEST-1",
            "timestamp": "2023-10-01 12:00:00",
            "ip": "1.1.1.1",
            "method": "GET",
            "path": "/products?id=1%20UNION%20SELECT%20NULL",
            "endpoint": "/products",
            "status": 200,
            "bytes_sent": 500,
            "username": "-",
            "auth_result": "not_applicable",
            "response_time_ms": 10,
            "protocol": "HTTP/1.1",
            "host": "vibetalk.com",
            "request_size_bytes": 100,
            "session_id": "sess_123",
            "country": "US"
        }
    ])
    alerts = run_rule_based_detection(mock_data)
    assert len(alerts) > 0
    assert any(a["rule_id"] == "LS004" for a in alerts)
