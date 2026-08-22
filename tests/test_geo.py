"""
Unit Tests for Geographic Distance & Velocity Physics Engine
"""

import pytest
from datetime import datetime, timedelta
from app.core.geo import calculate_haversine_distance, evaluate_travel_velocity, resolve_ip_location

def test_haversine_delhi_to_new_york():
    # New Delhi (28.6139, 77.2090) to New York (40.7128, -74.0060) is approx ~11,750 km
    delhi_lat, delhi_lon = 28.6139, 77.2090
    nyc_lat, nyc_lon = 40.7128, -74.0060

    dist = calculate_haversine_distance(delhi_lat, delhi_lon, nyc_lat, nyc_lon)
    assert 11500 <= dist <= 12000

def test_haversine_same_location():
    dist = calculate_haversine_distance(28.6139, 77.2090, 28.6139, 77.2090)
    assert dist == 0.0

def test_impossible_travel_detected():
    # 11,750 km in 5 minutes = 141,000 km/h (impossible)
    t1 = datetime(2026, 8, 21, 10, 0, 0)
    t2 = datetime(2026, 8, 21, 10, 5, 0)

    res = evaluate_travel_velocity(
        prev_lat=28.6139, prev_lon=77.2090, prev_time=t1,
        curr_lat=40.7128, curr_lon=-74.0060, curr_time=t2
    )

    assert res["is_impossible"] is True
    assert res["speed_kmh"] > 900.0
    assert res["distance_km"] > 11000

def test_plausible_travel_allowed():
    # 11,750 km in 24 hours = ~490 km/h (plausible long-haul flight)
    t1 = datetime(2026, 8, 21, 10, 0, 0)
    t2 = datetime(2026, 8, 22, 10, 0, 0)

    res = evaluate_travel_velocity(
        prev_lat=28.6139, prev_lon=77.2090, prev_time=t1,
        curr_lat=40.7128, curr_lon=-74.0060, curr_time=t2
    )

    assert res["is_impossible"] is False
    assert res["speed_kmh"] < 900.0

def test_local_switch_allowed():
    # Distance < 50 km in 1 minute
    t1 = datetime(2026, 8, 21, 10, 0, 0)
    t2 = datetime(2026, 8, 21, 10, 1, 0)

    res = evaluate_travel_velocity(
        prev_lat=28.6139, prev_lon=77.2090, prev_time=t1,
        curr_lat=28.7041, curr_lon=77.1025, curr_time=t2
    )

    assert res["is_impossible"] is False

def test_resolve_known_and_unknown_ip():
    known = resolve_ip_location("103.21.124.5")
    assert known["city"] == "New Delhi"
    assert known["country"] == "India"

    unknown = resolve_ip_location("1.2.3.4")
    assert "city" in unknown
    assert "lat" in unknown
