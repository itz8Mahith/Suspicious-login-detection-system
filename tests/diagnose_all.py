"""
Comprehensive Diagnostic Script for AuthSentinel
Tests all routes, simulation endpoints, unlock mechanisms, and static file deliveries.
"""

import sys
from pathlib import Path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from fastapi.testclient import TestClient
from app.main import app

def run_diagnostics():
    print("Running Full System Diagnostics...")
    with TestClient(app) as client:
        # 1. Test Root UI
        r = client.get("/")
        assert r.status_code == 200, f"Root / failed: {r.status_code}"
        assert "<!DOCTYPE html>" in r.text, "Root did not return HTML"
        print("[PASS] GET / (Dashboard UI): OK")

        # 2. Test /login UI
        r = client.get("/login")
        assert r.status_code == 200, f"/login failed: {r.status_code}"
        assert "Corporate Identity Login" in r.text, "/login did not return login portal"
        print("[PASS] GET /login (Login Portal UI): OK")

        # 3. Test Static Assets
        r_css = client.get("/static/css/style.css")
        assert r_css.status_code == 200 and "text/css" in r_css.headers["content-type"], "CSS delivery failed"
        print("[PASS] GET /static/css/style.css: OK")

        r_js = client.get("/static/js/dashboard.js")
        assert r_js.status_code == 200, "JS delivery failed"
        print("[PASS] GET /static/js/dashboard.js: OK")

        # 4. Test Analytics Endpoint
        r_analytics = client.get("/api/analytics")
        assert r_analytics.status_code == 200, f"/api/analytics failed: {r_analytics.status_code}"
        data = r_analytics.json()
        assert "summary" in data and "travel_arcs" in data, "Analytics schema mismatch"
        print(f"[PASS] GET /api/analytics: OK (Total Logins: {data['summary']['total_logins']}, Travel Arcs: {len(data['travel_arcs'])})")

        # 5. Test Alerts Endpoint
        r_alerts = client.get("/api/alerts")
        assert r_alerts.status_code == 200 and isinstance(r_alerts.json(), list), "/api/alerts failed"
        print(f"[PASS] GET /api/alerts: OK ({len(r_alerts.json())} alerts loaded)")

        # 6. Test Logs Endpoint
        r_logs = client.get("/api/logs")
        assert r_logs.status_code == 200 and isinstance(r_logs.json(), list), "/api/logs failed"
        print(f"[PASS] GET /api/logs: OK ({len(r_logs.json())} logs loaded)")

        # 7. Test Users Endpoint
        r_users = client.get("/api/users")
        assert r_users.status_code == 200 and len(r_users.json()) >= 2, "/api/users failed"
        print(f"[PASS] GET /api/users: OK ({len(r_users.json())} demo users)")

        # 8. Test Unlock Endpoint
        r_unlock = client.post("/api/users/alice_smith/unlock")
        assert r_unlock.status_code == 200, "Unlock failed"
        print("[PASS] POST /api/users/alice_smith/unlock: OK")

        # 9. Test Scenarios
        for sc in ["impossible_travel", "brute_force", "tor_proxy", "midnight_access", "benign_login"]:
            r_sc = client.post("/api/simulate/scenario", json={"scenario": sc, "target_user": "alice_smith"})
            assert r_sc.status_code == 200, f"Scenario '{sc}' failed: {r_sc.status_code}"
            print(f"[PASS] Scenario Simulation '{sc}': OK")

    print("\n==========================================")
    print("ALL BACKEND & API TESTS PASSED 100%!")
    print("==========================================")

if __name__ == "__main__":
    run_diagnostics()
