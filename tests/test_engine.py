"""
Unit Tests for Detection Engine Rules & Risk Scoring
"""

import json
from datetime import datetime, timedelta
from app.models.user import User, UserBaseline
from app.core.engine import DetectionEngine
from app.core.baseline import is_unusual_login_hour, is_new_device, is_unusual_country
from app.core.mitigations import determine_risk_level_and_action

def test_risk_mitigation_mapping():
    assert determine_risk_level_and_action(15)["action"] == "ALLOW"
    assert determine_risk_level_and_action(45)["action"] == "MFA_CHALLENGE"
    assert determine_risk_level_and_action(70)["action"] == "STEP_UP_VERIFICATION"
    assert determine_risk_level_and_action(95)["action"] == "BLOCK_AND_LOCK"

def test_is_unusual_login_hour():
    baseline = UserBaseline(
        typical_hours_json=json.dumps([9, 10, 11, 12, 13, 14, 15, 16, 17])
    )
    # Normal hour (11 AM)
    is_off, _ = is_unusual_login_hour(baseline, datetime(2026, 8, 21, 11, 0, 0))
    assert is_off is False

    # Off hour (3 AM)
    is_off_3am, reason = is_unusual_login_hour(baseline, datetime(2026, 8, 21, 3, 0, 0))
    assert is_off_3am is True
    assert "outside normal schedule" in reason

def test_is_new_device():
    baseline = UserBaseline(
        known_devices_json=json.dumps([{"fingerprint": "fp_known_device", "user_agent": "Chrome/122"}])
    )
    # Known device
    is_new, _ = is_new_device(baseline, "fp_known_device", "Chrome/122")
    assert is_new is False

    # Novel device
    is_new_unknown, _ = is_new_device(baseline, "fp_hacker_kali", "Hydra")
    assert is_new_unknown is True

def test_is_unusual_country():
    baseline = UserBaseline(
        known_countries_json=json.dumps(["India"])
    )
    # India is known
    is_novel, _ = is_unusual_country(baseline, "India")
    assert is_novel is False

    # Brazil is novel
    is_novel_brazil, _ = is_unusual_country(baseline, "Brazil")
    assert is_novel_brazil is True
