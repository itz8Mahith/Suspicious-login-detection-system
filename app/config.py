"""
AuthSentinel - Detection Engine Configuration
Defines threat thresholds, risk scoring weights, and MITRE ATT&CK mappings.
"""

from typing import Dict

# Geographic & Travel Physics Constraints
MAX_AIRLINER_SPEED_KMH: float = 900.0   # Commercial jet cruising speed limit
MIN_TRANSIT_TIME_BUFFER_SEC: float = 300.0  # 5 minutes buffer for fast IP jumps (VPN vs true travel)
EARTH_RADIUS_KM: float = 6371.0

# Behavioral & Velocity Thresholds
BRUTE_FORCE_WINDOW_MINUTES: int = 5      # Window to evaluate failed attempts
BRUTE_FORCE_FAIL_LIMIT: int = 4          # Failed attempts triggering Medium risk
BRUTE_FORCE_LOCK_LIMIT: int = 8          # Failed attempts triggering Critical risk
UNUSUAL_HOUR_STD_DEV_FACTOR: float = 2.0 # Standard deviations from average login hour

# Risk Weight Allocation (0 to 100 maximum normalized)
WEIGHT_IMPOSSIBLE_TRAVEL: int = 50
WEIGHT_BRUTE_FORCE_BURST: int = 40
WEIGHT_NEW_DEVICE: int = 20
WEIGHT_UNUSUAL_TIME: int = 15
WEIGHT_HIGH_RISK_IP: int = 25
WEIGHT_UNUSUAL_COUNTRY: int = 20

# Risk Level Classification
RISK_LEVEL_LOW: str = "LOW"             # Score 0 - 29 (Action: ALLOW)
RISK_LEVEL_MEDIUM: str = "MEDIUM"       # Score 30 - 59 (Action: MFA_CHALLENGE)
RISK_LEVEL_HIGH: str = "HIGH"           # Score 60 - 79 (Action: STEP_UP_VERIFICATION)
RISK_LEVEL_CRITICAL: str = "CRITICAL"   # Score 80 - 100 (Action: BLOCK_AND_LOCK)

# MITRE ATT&CK Mapping
MITRE_MAPPINGS: Dict[str, Dict[str, str]] = {
    "IMPOSSIBLE_TRAVEL": {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts (Geographic Anomaly)",
        "tactic": "Initial Access / Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/004/"
    },
    "BRUTE_FORCE": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/"
    },
    "CREDENTIAL_STUFFING": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/004/"
    },
    "NEW_DEVICE_ANOMALY": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Unrecognized Device / User-Agent)",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "UNUSUAL_TIME_ANOMALY": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Off-Hours Access)",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "HIGH_RISK_IP": {
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop Proxy / Tor Exit Node",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1090/003/"
    }
}
