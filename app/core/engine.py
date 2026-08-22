"""
AuthSentinel - Multi-Factor Risk Scoring & Detection Engine
Orchestrates anomaly detectors, calculates risk scores, attaches forensic evidence, and maps to MITRE ATT&CK.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.config import (
    WEIGHT_IMPOSSIBLE_TRAVEL,
    WEIGHT_BRUTE_FORCE_BURST,
    WEIGHT_NEW_DEVICE,
    WEIGHT_UNUSUAL_TIME,
    WEIGHT_HIGH_RISK_IP,
    WEIGHT_UNUSUAL_COUNTRY,
    BRUTE_FORCE_WINDOW_MINUTES,
    BRUTE_FORCE_FAIL_LIMIT,
    BRUTE_FORCE_LOCK_LIMIT,
    MITRE_MAPPINGS
)
from app.models.user import User, UserBaseline
from app.models.login_log import LoginLog
from app.core.geo import evaluate_travel_velocity, resolve_ip_location
from app.core.baseline import (
    is_unusual_login_hour,
    is_new_device,
    is_unusual_country
)
from app.core.mitigations import determine_risk_level_and_action

class DetectionEngine:
    def __init__(self, db: Session):
        self.db = db

    def analyze_login_attempt(
        self,
        user: Optional[User],
        username: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str,
        is_password_valid: bool,
        timestamp: Optional[datetime] = None,
        override_geo: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes comprehensive behavioral and telemetry anomaly detection on an incoming login request.
        """
        if timestamp is None:
            timestamp = datetime.utcnow()
        elif timestamp.tzinfo is not None:
            timestamp = timestamp.replace(tzinfo=None)

        # Step 1: Geolocation resolution
        geo = override_geo if override_geo else resolve_ip_location(ip_address)
        city = geo.get("city", "Unknown")
        country = geo.get("country", "Unknown")
        lat = geo.get("lat", 0.0)
        lon = geo.get("lon", 0.0)
        is_proxy = geo.get("is_proxy", False)
        proxy_type = geo.get("proxy_type", "None")

        triggered_rules: List[Dict[str, Any]] = []
        raw_risk_score = 0
        baseline = user.baseline if user else None

        # --- Rule 1: High-Risk IP / Tor Exit Node Check ---
        if is_proxy:
            raw_risk_score += WEIGHT_HIGH_RISK_IP
            triggered_rules.append({
                "rule_id": "RULE_HIGH_RISK_IP",
                "name": "High-Risk / Anonymizing Proxy Detected",
                "score_added": WEIGHT_HIGH_RISK_IP,
                "mitre": MITRE_MAPPINGS["HIGH_RISK_IP"],
                "details": f"Connection originating from known anonymizer ({proxy_type})"
            })

        # --- Rule 2: Brute-Force & Credential Stuffing Velocity ---
        sliding_window_start = timestamp - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        recent_failures_count = (
            self.db.query(LoginLog)
            .filter(
                (LoginLog.username == username) | (LoginLog.ip_address == ip_address),
                LoginLog.is_success == False,
                LoginLog.timestamp >= sliding_window_start
            )
            .count()
        )

        if not is_password_valid:
            recent_failures_count += 1

        if recent_failures_count >= BRUTE_FORCE_LOCK_LIMIT:
            raw_risk_score += 55
            triggered_rules.append({
                "rule_id": "RULE_BRUTE_FORCE_CRITICAL",
                "name": "High-Velocity Brute Force Attack",
                "score_added": 55,
                "mitre": MITRE_MAPPINGS["BRUTE_FORCE"],
                "details": f"{recent_failures_count} failed login attempts detected in the last {BRUTE_FORCE_WINDOW_MINUTES} minutes."
            })
        elif recent_failures_count >= BRUTE_FORCE_FAIL_LIMIT:
            raw_risk_score += WEIGHT_BRUTE_FORCE_BURST
            triggered_rules.append({
                "rule_id": "RULE_BRUTE_FORCE_BURST",
                "name": "Multiple Failed Login Attempts",
                "score_added": WEIGHT_BRUTE_FORCE_BURST,
                "mitre": MITRE_MAPPINGS["BRUTE_FORCE"],
                "details": f"{recent_failures_count} consecutive failed attempts detected in a short time window."
            })

        # Behavioral and Velocity Checks (if user exists and baseline is present)
        impossible_travel_meta = None
        if baseline and baseline.last_latitude is not None and baseline.last_login_at is not None:
            # --- Rule 3: Impossible Travel Physics Check ---
            travel_eval = evaluate_travel_velocity(
                prev_lat=baseline.last_latitude,
                prev_lon=baseline.last_longitude,
                prev_time=baseline.last_login_at,
                curr_lat=lat,
                curr_lon=lon,
                curr_time=timestamp
            )
            
            if travel_eval["is_impossible"]:
                raw_risk_score += WEIGHT_IMPOSSIBLE_TRAVEL
                impossible_travel_meta = {
                    "origin": f"{baseline.last_city}, {baseline.last_country}",
                    "origin_coords": [baseline.last_latitude, baseline.last_longitude],
                    "destination": f"{city}, {country}",
                    "destination_coords": [lat, lon],
                    "distance_km": travel_eval["distance_km"],
                    "elapsed_seconds": travel_eval["elapsed_seconds"],
                    "speed_kmh": travel_eval["speed_kmh"],
                    "last_login_time": baseline.last_login_at.isoformat()
                }
                triggered_rules.append({
                    "rule_id": "RULE_IMPOSSIBLE_TRAVEL",
                    "name": "Impossible Travel Velocity Anomaly",
                    "score_added": WEIGHT_IMPOSSIBLE_TRAVEL,
                    "mitre": MITRE_MAPPINGS["IMPOSSIBLE_TRAVEL"],
                    "details": travel_eval["reason"],
                    "telemetry": impossible_travel_meta
                })
            else:
                # --- Rule 4: Unusual Foreign Country (if travel was physically possible but country is novel) ---
                is_novel_country, country_reason = is_unusual_country(baseline, country)
                if is_novel_country:
                    raw_risk_score += WEIGHT_UNUSUAL_COUNTRY
                    triggered_rules.append({
                        "rule_id": "RULE_UNUSUAL_COUNTRY",
                        "name": "Unusual Geographic Region",
                        "score_added": WEIGHT_UNUSUAL_COUNTRY,
                        "mitre": MITRE_MAPPINGS["IMPOSSIBLE_TRAVEL"],
                        "details": country_reason
                    })

        # --- Rule 5: New Device & Fingerprint Discrepancy ---
        if baseline:
            is_new_dev, dev_reason = is_new_device(baseline, device_fingerprint, user_agent)
            if is_new_dev:
                raw_risk_score += WEIGHT_NEW_DEVICE
                triggered_rules.append({
                    "rule_id": "RULE_NEW_DEVICE",
                    "name": "Unrecognized Client Device Fingerprint",
                    "score_added": WEIGHT_NEW_DEVICE,
                    "mitre": MITRE_MAPPINGS["NEW_DEVICE_ANOMALY"],
                    "details": dev_reason
                })

        # --- Rule 6: Unusual Login Time (Off-Hours) ---
        if baseline:
            is_off_hour, hour_reason = is_unusual_login_hour(baseline, timestamp)
            if is_off_hour:
                raw_risk_score += WEIGHT_UNUSUAL_TIME
                triggered_rules.append({
                    "rule_id": "RULE_UNUSUAL_HOUR",
                    "name": "Off-Hours Login Deviation",
                    "score_added": WEIGHT_UNUSUAL_TIME,
                    "mitre": MITRE_MAPPINGS["UNUSUAL_TIME_ANOMALY"],
                    "details": hour_reason
                })

        # If credentials were wrong, add baseline penalty
        if not is_password_valid:
            raw_risk_score += 15

        # Normalize total composite risk score (0 to 100)
        final_risk_score = min(100, max(0, raw_risk_score))
        mitigation = determine_risk_level_and_action(final_risk_score)

        return {
            "username": username,
            "ip_address": ip_address,
            "geolocation": {
                "city": city,
                "country": country,
                "latitude": lat,
                "longitude": lon,
                "is_proxy": is_proxy,
                "proxy_type": proxy_type
            },
            "device": {
                "fingerprint": device_fingerprint,
                "user_agent": user_agent
            },
            "timestamp": timestamp.isoformat(),
            "is_password_valid": is_password_valid,
            "risk_score": final_risk_score,
            "risk_level": mitigation["risk_level"],
            "action": mitigation["action"],
            "action_description": mitigation["action_description"],
            "requires_mfa": mitigation["requires_mfa"],
            "is_blocked": mitigation["is_blocked"],
            "triggered_rules": triggered_rules,
            "impossible_travel_telemetry": impossible_travel_meta,
            "recent_failed_attempts": recent_failures_count
        }
