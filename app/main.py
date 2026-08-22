"""
AuthSentinel - Main FastAPI Application
Provides RESTful APIs for authentication, risk analysis, alert streaming, and attack simulations.
Supports local execution, Docker, and Vercel Serverless deployments.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, Depends, HTTPException, Query, Body, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import init_db, get_db
from app.models.user import User, UserBaseline
from app.models.login_log import LoginLog
from app.models.alert import SecurityAlert
from app.core.engine import DetectionEngine
from app.core.baseline import update_user_baseline_after_verified_login
from app.core.geo import resolve_ip_location

# Base path resolution for static assets (ensures serverless & Vercel compatibility)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

# ----------------- Pydantic Request/Response Schemas -----------------

class LoginRequest(BaseModel):
    username: str = Field(..., json_schema_extra={"example": "alice_smith"})
    password: str = Field(..., json_schema_extra={"example": "SecurePassword123!"})
    ip_address: str = Field(..., json_schema_extra={"example": "198.51.100.22"})
    user_agent: str = Field(
        ...,
        json_schema_extra={"example": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"}
    )
    device_fingerprint: Optional[str] = Field(None, json_schema_extra={"example": "fp_win_chrome_9a8b7c"})
    timestamp: Optional[datetime] = None
    override_geo: Optional[Dict[str, Any]] = None

class ScenarioSimulationRequest(BaseModel):
    scenario: str = Field(
        ...,
        description="Preset scenario: 'impossible_travel', 'brute_force', 'tor_proxy', 'midnight_access', 'benign_login'",
        json_schema_extra={"example": "impossible_travel"}
    )
    target_user: Optional[str] = Field("alice_smith", json_schema_extra={"example": "alice_smith"})

# ----------------- Database Seeder -----------------

def seed_demo_data(db: Session):
    """Seed initial demo accounts and baselines if database is fresh."""
    if db.query(User).first():
        return

    # User 1: Alice (Based in New Delhi, India)
    user_alice = User(
        username="alice_smith",
        email="alice.smith@enterprise.corp",
        full_name="Alice Smith",
        role="Senior Cloud Engineer",
        is_locked=False
    )
    db.add(user_alice)
    db.commit()
    db.refresh(user_alice)

    now = datetime.now(timezone.utc)

    baseline_alice = UserBaseline(
        user_id=user_alice.id,
        typical_hours_json=json.dumps([9, 10, 11, 12, 13, 14, 15, 16, 17]),
        known_countries_json=json.dumps(["India"]),
        known_devices_json=json.dumps([
            {
                "fingerprint": "fp_alice_workstation_dell",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
            }
        ]),
        known_ips_json=json.dumps(["103.21.124.5", "103.22.100.1"]),
        last_login_at=now - timedelta(minutes=5),
        last_ip="103.21.124.5",
        last_city="New Delhi",
        last_country="India",
        last_latitude=28.6139,
        last_longitude=77.2090,
        last_device_fingerprint="fp_alice_workstation_dell"
    )
    db.add(baseline_alice)

    # Initial normal login log for Alice
    initial_log = LoginLog(
        user_id=user_alice.id,
        username="alice_smith",
        ip_address="103.21.124.5",
        city="New Delhi",
        country="India",
        latitude=28.6139,
        longitude=77.2090,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
        device_fingerprint="fp_alice_workstation_dell",
        device_type="Desktop",
        os_name="Windows",
        browser="Chrome",
        is_success=True,
        risk_score=0,
        risk_level="LOW",
        action_taken="ALLOW",
        triggered_rules_json="[]",
        timestamp=now - timedelta(minutes=5)
    )
    db.add(initial_log)

    # User 2: Bob (Based in San Francisco, USA)
    user_bob = User(
        username="bob_jones",
        email="bob.jones@enterprise.corp",
        full_name="Bob Jones",
        role="Product Manager",
        is_locked=False
    )
    db.add(user_bob)
    db.commit()
    db.refresh(user_bob)

    baseline_bob = UserBaseline(
        user_id=user_bob.id,
        typical_hours_json=json.dumps([8, 9, 10, 11, 12, 13, 14, 15, 16]),
        known_countries_json=json.dumps(["United States"]),
        known_devices_json=json.dumps([
            {
                "fingerprint": "fp_bob_macbook_pro",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"
            }
        ]),
        known_ips_json=json.dumps(["198.51.100.99"]),
        last_login_at=now - timedelta(hours=2),
        last_ip="198.51.100.99",
        last_city="San Francisco",
        last_country="United States",
        last_latitude=37.7749,
        last_longitude=-122.4194,
        last_device_fingerprint="fp_bob_macbook_pro"
    )
    db.add(baseline_bob)

    db.commit()

# ----------------- Lifespan Context Manager -----------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = next(get_db())
    try:
        seed_demo_data(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="AuthSentinel - Suspicious Login & Anomaly Detection System",
    description="Industry-grade behavioral and geospatial anomaly detection engine with MITRE ATT&CK mapping.",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ----------------- UI / Root Endpoints (Compatible with all Vercel routes) -----------------

@app.get("/")
@app.get("/api")
@app.get("/api/")
@app.get("/api/index.py")
def serve_ui():
    """Serves the interactive Cyber Threat Intelligence Dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        content = index_file.read_text(encoding="utf-8")
        return HTMLResponse(content=content)
    return {"message": "AuthSentinel API Active", "docs": "/docs"}

@app.get("/static/css/style.css")
def serve_css():
    css_file = STATIC_DIR / "css" / "style.css"
    if css_file.exists():
        return Response(content=css_file.read_text(encoding="utf-8"), media_type="text/css")
    return Response(content="", media_type="text/css")

@app.get("/static/js/dashboard.js")
def serve_js():
    js_file = STATIC_DIR / "js" / "dashboard.js"
    if js_file.exists():
        return Response(content=js_file.read_text(encoding="utf-8"), media_type="application/javascript")
    return Response(content="", media_type="application/javascript")

# ----------------- API Endpoints -----------------

@app.post("/api/auth/login")
def process_login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Main authentication & threat evaluation endpoint.
    Evaluates geospatial anomaly, device mismatch, brute-force velocity, and off-hour deviations.
    """
    user = db.query(User).filter(User.username == payload.username).first()
    
    # Check if account is already locked
    if user and user.is_locked:
        raise HTTPException(
            status_code=403,
            detail="Account is locked due to high-risk security triggers. Contact SOC Admin."
        )

    is_password_valid = (payload.password == "SecurePassword123!")
    fingerprint = payload.device_fingerprint or f"fp_{abs(hash(payload.user_agent)) % 1000000}"

    engine = DetectionEngine(db)
    analysis = engine.analyze_login_attempt(
        user=user,
        username=payload.username,
        ip_address=payload.ip_address,
        user_agent=payload.user_agent,
        device_fingerprint=fingerprint,
        is_password_valid=is_password_valid,
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        override_geo=payload.override_geo
    )

    # Persist login audit record
    login_log = LoginLog(
        user_id=user.id if user else None,
        username=payload.username,
        ip_address=payload.ip_address,
        city=analysis["geolocation"]["city"],
        country=analysis["geolocation"]["country"],
        latitude=analysis["geolocation"]["latitude"],
        longitude=analysis["geolocation"]["longitude"],
        user_agent=payload.user_agent,
        device_fingerprint=fingerprint,
        is_success=is_password_valid and not analysis["is_blocked"],
        failure_reason="Authentication failed" if not is_password_valid else ("Security Block" if analysis["is_blocked"] else None),
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        action_taken=analysis["action"],
        triggered_rules_json=json.dumps(analysis["triggered_rules"]),
        timestamp=payload.timestamp or datetime.now(timezone.utc)
    )
    db.add(login_log)
    db.commit()
    db.refresh(login_log)

    # Create security alert if high/critical or impossible travel triggered
    if analysis["risk_score"] >= 30 or any(r["rule_id"] == "RULE_IMPOSSIBLE_TRAVEL" for r in analysis["triggered_rules"]):
        primary_rule = analysis["triggered_rules"][0] if analysis["triggered_rules"] else {
            "name": "Elevated Risk Login",
            "rule_id": "RULE_ANOMALY",
            "mitre": None,
            "details": "Suspicious login indicators detected"
        }

        alert = SecurityAlert(
            user_id=user.id if user else None,
            username=payload.username,
            login_log_id=login_log.id,
            alert_type=primary_rule.get("rule_id", "ANOMALY_DETECTED"),
            severity=analysis["risk_level"],
            title=f"Suspicious Login: {primary_rule.get('name')}",
            description=primary_rule.get("details", analysis["action_description"]),
            evidence_json=json.dumps({
                "risk_score": analysis["risk_score"],
                "ip": payload.ip_address,
                "city": analysis["geolocation"]["city"],
                "country": analysis["geolocation"]["country"],
                "all_rules": analysis["triggered_rules"],
                "impossible_travel": analysis.get("impossible_travel_telemetry")
            }),
            mitre_technique_id=primary_rule.get("mitre", {}).get("technique_id") if primary_rule.get("mitre") else "T1078",
            mitre_technique_name=primary_rule.get("mitre", {}).get("technique_name") if primary_rule.get("mitre") else "Valid Accounts",
            status="OPEN"
        )
        db.add(alert)

    # Mitigation updates
    if user:
        if analysis["action"] == "BLOCK_AND_LOCK":
            user.is_locked = True
        elif analysis["action"] == "ALLOW" and is_password_valid:
            update_user_baseline_after_verified_login(
                baseline=user.baseline,
                login_time=payload.timestamp or datetime.now(timezone.utc),
                ip=payload.ip_address,
                city=analysis["geolocation"]["city"],
                country=analysis["geolocation"]["country"],
                lat=analysis["geolocation"]["latitude"],
                lon=analysis["geolocation"]["longitude"],
                device_fingerprint=fingerprint,
                user_agent=payload.user_agent
            )

    db.commit()

    return {
        "status": "success",
        "login_log_id": login_log.id,
        "evaluation": analysis
    }

@app.get("/api/alerts")
def get_alerts(
    limit: int = Query(25, ge=1, le=100),
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieve recent security alerts with optional severity filtering."""
    query = db.query(SecurityAlert).order_by(desc(SecurityAlert.created_at))
    if severity:
        query = query.filter(SecurityAlert.severity == severity.upper())
    
    alerts = query.limit(limit).all()
    return [
        {
            "id": a.id,
            "username": a.username,
            "alert_type": a.alert_type,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "evidence": json.loads(a.evidence_json) if a.evidence_json else {},
            "mitre": {
                "id": a.mitre_technique_id,
                "name": a.mitre_technique_name
            },
            "status": a.status,
            "created_at": a.created_at.isoformat()
        }
        for a in alerts
    ]

@app.get("/api/logs")
def get_logs(limit: int = Query(30, ge=1, le=100), db: Session = Depends(get_db)):
    """Retrieve recent login audit logs."""
    logs = db.query(LoginLog).order_by(desc(LoginLog.timestamp)).limit(limit).all()
    return [
        {
            "id": l.id,
            "username": l.username,
            "ip_address": l.ip_address,
            "city": l.city,
            "country": l.country,
            "latitude": l.latitude,
            "longitude": l.longitude,
            "user_agent": l.user_agent,
            "is_success": l.is_success,
            "risk_score": l.risk_score,
            "risk_level": l.risk_level,
            "action_taken": l.action_taken,
            "triggered_rules": json.loads(l.triggered_rules_json) if l.triggered_rules_json else [],
            "timestamp": l.timestamp.isoformat()
        }
        for l in logs
    ]

@app.get("/api/analytics")
def get_analytics(db: Session = Depends(get_db)):
    """Computes high-level SOC analytics, threat distribution, and impossible travel vectors."""
    total_logins = db.query(LoginLog).count()
    successful_logins = db.query(LoginLog).filter(LoginLog.is_success == True).count()
    blocked_logins = db.query(LoginLog).filter(LoginLog.action_taken == "BLOCK_AND_LOCK").count()
    total_alerts = db.query(SecurityAlert).count()

    critical_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL").count()
    high_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "HIGH").count()
    medium_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "MEDIUM").count()
    low_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "LOW").count()

    impossible_travel_count = db.query(SecurityAlert).filter(SecurityAlert.alert_type == "RULE_IMPOSSIBLE_TRAVEL").count()
    brute_force_count = db.query(SecurityAlert).filter(SecurityAlert.alert_type.in_(["RULE_BRUTE_FORCE_BURST", "RULE_BRUTE_FORCE_CRITICAL"])).count()
    new_device_count = db.query(SecurityAlert).filter(SecurityAlert.alert_type == "RULE_NEW_DEVICE").count()
    high_risk_ip_count = db.query(SecurityAlert).filter(SecurityAlert.alert_type == "RULE_HIGH_RISK_IP").count()

    travel_alerts = (
        db.query(SecurityAlert)
        .filter(SecurityAlert.alert_type == "RULE_IMPOSSIBLE_TRAVEL")
        .order_by(desc(SecurityAlert.created_at))
        .limit(10)
        .all()
    )

    travel_arcs = []
    for a in travel_alerts:
        evidence = json.loads(a.evidence_json) if a.evidence_json else {}
        telemetry = evidence.get("impossible_travel")
        if telemetry:
            travel_arcs.append({
                "alert_id": a.id,
                "username": a.username,
                "origin": telemetry.get("origin"),
                "origin_coords": telemetry.get("origin_coords"),
                "destination": telemetry.get("destination"),
                "destination_coords": telemetry.get("destination_coords"),
                "distance_km": telemetry.get("distance_km"),
                "speed_kmh": telemetry.get("speed_kmh"),
                "created_at": a.created_at.isoformat()
            })

    return {
        "summary": {
            "total_logins": total_logins,
            "successful_logins": successful_logins,
            "blocked_logins": blocked_logins,
            "total_alerts": total_alerts
        },
        "severity_distribution": {
            "CRITICAL": critical_alerts,
            "HIGH": high_alerts,
            "MEDIUM": medium_alerts,
            "LOW": low_alerts
        },
        "attack_distribution": {
            "Impossible Travel": impossible_travel_count,
            "Brute Force / Credential Stuffing": brute_force_count,
            "New Device / Fingerprint": new_device_count,
            "High Risk / Tor IP": high_risk_ip_count
        },
        "travel_arcs": travel_arcs
    }

@app.post("/api/simulate/scenario")
def trigger_scenario(payload: ScenarioSimulationRequest, db: Session = Depends(get_db)):
    """
    Executes live realistic demonstration scenarios with preset telemetry.
    """
    target = payload.target_user or "alice_smith"
    user = db.query(User).filter(User.username == target).first()
    if not user:
        raise HTTPException(status_code=404, detail=f"Target user '{target}' not found.")

    user.is_locked = False
    db.commit()

    results = []
    now = datetime.now(timezone.utc)

    if payload.scenario == "impossible_travel":
        t1 = now - timedelta(minutes=5)
        req1 = LoginRequest(
            username=target,
            password="SecurePassword123!",
            ip_address="103.21.124.5",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
            device_fingerprint="fp_alice_workstation_dell",
            timestamp=t1
        )
        res1 = process_login(req1, db)
        results.append({"step": 1, "description": "Normal Login in New Delhi, India (10:00 AM)", "result": res1})

        t2 = now
        req2 = LoginRequest(
            username=target,
            password="SecurePassword123!",
            ip_address="198.51.100.22",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            device_fingerprint="fp_unknown_macbook_nyc",
            timestamp=t2
        )
        res2 = process_login(req2, db)
        results.append({"step": 2, "description": "Suspicious Login in New York, USA 5 minutes later (10:05 AM) -> ALERT!", "result": res2})

    elif payload.scenario == "brute_force":
        base_time = now - timedelta(minutes=2)
        for i in range(1, 6):
            req = LoginRequest(
                username=target,
                password=f"WrongPassword{i}!",
                ip_address="198.51.100.99",
                user_agent="Python-Requests/2.31.0 (Automated Tool)",
                device_fingerprint="fp_attacker_bot",
                timestamp=base_time + timedelta(seconds=i * 5)
            )
            res = process_login(req, db)
            results.append({"attempt": i, "result": res})

    elif payload.scenario == "tor_proxy":
        req = LoginRequest(
            username=target,
            password="SecurePassword123!",
            ip_address="185.220.101.5",
            user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            device_fingerprint="fp_tor_browser_bundle",
            timestamp=now
        )
        res = process_login(req, db)
        results.append({"description": "Login via Frankfurt Tor Exit Node", "result": res})

    elif payload.scenario == "midnight_access":
        midnight_time = now.replace(hour=3, minute=30, second=0)
        req = LoginRequest(
            username=target,
            password="SecurePassword123!",
            ip_address="103.24.150.10",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            device_fingerprint="fp_novel_iphone15",
            timestamp=midnight_time
        )
        res = process_login(req, db)
        results.append({"description": "Off-hours (3:30 AM) novel mobile access", "result": res})

    elif payload.scenario == "benign_login":
        req = LoginRequest(
            username=target,
            password="SecurePassword123!",
            ip_address="103.21.124.5",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36",
            device_fingerprint="fp_alice_workstation_dell",
            timestamp=now
        )
        res = process_login(req, db)
        results.append({"description": "Authorized daily login from registered corporate workstation", "result": res})

    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{payload.scenario}'")

    return {
        "scenario": payload.scenario,
        "target_user": target,
        "executions": results
    }

@app.get("/api/users")
def get_users(db: Session = Depends(get_db)):
    """List registered users and baseline details."""
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "role": u.role,
            "is_locked": u.is_locked,
            "baseline": {
                "last_login_at": u.baseline.last_login_at.isoformat() if u.baseline and u.baseline.last_login_at else None,
                "last_city": u.baseline.last_city if u.baseline else None,
                "last_country": u.baseline.last_country if u.baseline else None,
                "known_countries": json.loads(u.baseline.known_countries_json) if u.baseline and u.baseline.known_countries_json else [],
                "typical_hours": json.loads(u.baseline.typical_hours_json) if u.baseline and u.baseline.typical_hours_json else []
            } if u.baseline else None
        }
        for u in users
    ]

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, status: str = Body("RESOLVED", embed=True), db: Session = Depends(get_db)):
    """SOC Analyst action: Resolve or update alert status."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    alert.status = status
    db.commit()
    return {"status": "success", "alert_id": alert.id, "new_status": alert.status}
