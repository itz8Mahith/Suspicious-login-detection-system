"""
AuthSentinel - User Behavioral Profiler & Baseline Engine
Learns and evaluates normal working hours, trusted devices, and regional locations.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
from app.models.user import User, UserBaseline

def parse_json_list(json_str: str) -> List[Any]:
    try:
        return json.loads(json_str) if json_str else []
    except Exception:
        return []

def is_unusual_login_hour(baseline: UserBaseline, login_time: datetime) -> Tuple[bool, str]:
    """
    Checks whether the login hour falls significantly outside the user's historical profile.
    """
    if not baseline or not baseline.typical_hours_json:
        return False, "No historical baseline established."
    
    typical_hours = parse_json_list(baseline.typical_hours_json)
    if not typical_hours:
        return False, "Empty hour profile."

    current_hour = login_time.hour
    
    if current_hour not in typical_hours:
        # Check closest distance to normal working window
        min_distance = min(abs(current_hour - h) for h in typical_hours)
        if min_distance >= 3:
            return True, f"Login at hour {current_hour:02d}:00 is {min_distance} hours outside normal schedule {typical_hours}"
        return False, f"Minor deviation ({min_distance} hr difference)."
    
    return False, "Login time aligns with typical user profile."

def is_new_device(baseline: UserBaseline, device_fingerprint: str, user_agent: str) -> Tuple[bool, str]:
    """
    Evaluates whether the client fingerprint or User-Agent is new.
    """
    if not baseline:
        return True, "No baseline; treating as new device."
    
    known_devices = parse_json_list(baseline.known_devices_json)
    
    if not known_devices:
        return False, "First recorded device."
    
    # Check fingerprint match or exact user-agent match
    for dev in known_devices:
        if isinstance(dev, dict):
            if dev.get("fingerprint") == device_fingerprint or dev.get("user_agent") == user_agent:
                return False, "Known & recognized device."
        elif isinstance(dev, str):
            if dev == device_fingerprint or dev == user_agent:
                return False, "Known & recognized device."

    return True, f"Unrecognized device fingerprint ({device_fingerprint[:12]}...)"

def is_unusual_country(baseline: UserBaseline, country: str) -> Tuple[bool, str]:
    """
    Evaluates whether the country has never been visited by the user.
    """
    if not baseline or not country:
        return False, "No country baseline available."
    
    known_countries = parse_json_list(baseline.known_countries_json)
    if not known_countries:
        return False, "First location registration."
    
    if country not in known_countries:
        return True, f"First-time access from foreign country: '{country}' (Known: {', '.join(known_countries)})"
    
    return False, f"Location '{country}' is in user's trusted country list."

def update_user_baseline_after_verified_login(
    baseline: UserBaseline,
    login_time: datetime,
    ip: str,
    city: str,
    country: str,
    lat: float,
    lon: float,
    device_fingerprint: str,
    user_agent: str
):
    """
    Updates the user's baseline state after a successfully authenticated & verified login.
    """
    if not baseline:
        return
    
    baseline.last_login_at = login_time
    baseline.last_ip = ip
    baseline.last_city = city
    baseline.last_country = country
    baseline.last_latitude = lat
    baseline.last_longitude = lon
    baseline.last_device_fingerprint = device_fingerprint

    # Update typical hours list
    typical_hours = parse_json_list(baseline.typical_hours_json)
    if login_time.hour not in typical_hours:
        typical_hours.append(login_time.hour)
        typical_hours.sort()
        baseline.typical_hours_json = json.dumps(typical_hours)

    # Update known countries
    known_countries = parse_json_list(baseline.known_countries_json)
    if country and country not in known_countries:
        known_countries.append(country)
        baseline.known_countries_json = json.dumps(known_countries)

    # Update known devices
    known_devices = parse_json_list(baseline.known_devices_json)
    device_entry = {"fingerprint": device_fingerprint, "user_agent": user_agent}
    if not any(d.get("fingerprint") == device_fingerprint for d in known_devices if isinstance(d, dict)):
        known_devices.append(device_entry)
        baseline.known_devices_json = json.dumps(known_devices)
