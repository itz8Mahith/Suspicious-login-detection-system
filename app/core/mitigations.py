"""
AuthSentinel - Automated Threat Mitigation & Response Policy
Enforces policy actions based on multi-factor composite risk scores.
"""

from typing import Dict, Any
from app.config import (
    RISK_LEVEL_LOW, RISK_LEVEL_MEDIUM, RISK_LEVEL_HIGH, RISK_LEVEL_CRITICAL
)

def determine_risk_level_and_action(risk_score: int) -> Dict[str, Any]:
    """
    Maps numeric risk score (0-100) to risk level classification and automated security response.
    """
    if risk_score < 30:
        return {
            "risk_level": RISK_LEVEL_LOW,
            "action": "ALLOW",
            "action_description": "Standard login granted without secondary friction.",
            "requires_mfa": False,
            "is_blocked": False
        }
    elif risk_score < 60:
        return {
            "risk_level": RISK_LEVEL_MEDIUM,
            "action": "MFA_CHALLENGE",
            "action_description": "Secondary Multi-Factor Authentication (MFA / Push Token) required.",
            "requires_mfa": True,
            "is_blocked": False
        }
    elif risk_score < 80:
        return {
            "risk_level": RISK_LEVEL_HIGH,
            "action": "STEP_UP_VERIFICATION",
            "action_description": "High threat detected. Out-of-band Email OTP verification required & SOC alerted.",
            "requires_mfa": True,
            "is_blocked": False
        }
    else:
        return {
            "risk_level": RISK_LEVEL_CRITICAL,
            "action": "BLOCK_AND_LOCK",
            "action_description": "Severe attack pattern detected. Login blocked immediately and account temporarily locked.",
            "requires_mfa": False,
            "is_blocked": True
        }
