"""
Integration Tests for FastAPI Endpoints & Threat Simulation
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models.user import User

@pytest.fixture(autouse=True)
def unlock_test_users():
    """Ensure test users are unlocked prior to each test."""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for u in users:
            u.is_locked = False
        db.commit()
    finally:
        db.close()

def test_root_serves_html():
    with TestClient(app) as test_client:
        response = test_client.get("/")
        assert response.status_code == 200
        assert "AuthSentinel" in response.text

def test_api_analytics():
    with TestClient(app) as test_client:
        response = test_client.get("/api/analytics")
        assert response.status_code == 200
        data = response.json()
        assert "summary" in data
        assert "severity_distribution" in data
        assert "attack_distribution" in data

def test_api_benign_login():
    with TestClient(app) as test_client:
        payload = {
            "username": "alice_smith",
            "password": "SecurePassword123!",
            "ip_address": "103.21.124.5",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "device_fingerprint": "fp_alice_workstation_dell"
        }
        response = test_client.post("/api/auth/login", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["evaluation"]["risk_level"] == "LOW"
        assert data["evaluation"]["action"] == "ALLOW"

def test_api_impossible_travel_simulation():
    with TestClient(app) as test_client:
        response = test_client.post("/api/simulate/scenario", json={"scenario": "impossible_travel", "target_user": "alice_smith"})
        assert response.status_code == 200
        data = response.json()
        assert data["scenario"] == "impossible_travel"
        assert len(data["executions"]) == 2
        
        # Step 2 must be flagged as impossible travel
        step2_eval = data["executions"][1]["result"]["evaluation"]
        assert any(r["rule_id"] == "RULE_IMPOSSIBLE_TRAVEL" for r in step2_eval["triggered_rules"])
        assert step2_eval["risk_score"] >= 50

def test_api_alerts_retrieval():
    with TestClient(app) as test_client:
        response = test_client.get("/api/alerts")
        assert response.status_code == 200
        alerts = response.json()
        assert isinstance(alerts, list)

def test_api_logs_retrieval():
    with TestClient(app) as test_client:
        response = test_client.get("/api/logs")
        assert response.status_code == 200
        logs = response.json()
        assert isinstance(logs, list)
