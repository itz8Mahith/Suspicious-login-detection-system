#!/usr/bin/env python3
"""
AuthSentinel - Autonomous Attack & Telemetry Simulation CLI
Generates realistic user baselines and triggers live cyber attack scenarios with formatted terminal output.
"""

import sys
import time
from datetime import datetime, timezone, timedelta
from colorama import init, Fore, Style
from fastapi import HTTPException

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from app.database import init_db, SessionLocal
from app.models.user import User, UserBaseline
from app.core.engine import DetectionEngine
from app.core.baseline import update_user_baseline_after_verified_login
from app.main import LoginRequest, process_login

init(autoreset=True)

def print_banner():
    banner = rf"""
{Fore.CYAN}================================================================================
{Fore.CYAN}     ___         __  __    ____             __  _            __
{Fore.CYAN}    /   | __  __/ /_/ /_  / __/___  ____   / /_(_)___  ___  / /
{Fore.CYAN}   / /| |/ / / / __/ __ \/ /_/ __ \/ __ \ / __/ / __ \/ _ \/ / 
{Fore.CYAN}  / ___ / /_/ / /_/ / / / __/ /_/ / / / // /_/ / / / /  __/ /  
{Fore.CYAN} /_/  |_\__,_/\__/_/ /_/_/  \____/_/ /_/ \__/_/_/ /_/\___/_/   
{Fore.CYAN}================================================================================
{Fore.WHITE}      Suspicious Login & Impossible Travel Detection Simulation Suite
{Fore.CYAN}================================================================================
    """
    print(banner)

def run_simulation():
    print_banner()
    init_db()
    db = SessionLocal()

    try:
        print(f"{Fore.YELLOW}[*] Initializing Database & Target Identities...")
        user = db.query(User).filter(User.username == "alice_smith").first()
        if not user:
            print(f"{Fore.YELLOW}[*] Seeding default identities into database...")
            from app.main import seed_demo_data
            seed_demo_data(db)
            user = db.query(User).filter(User.username == "alice_smith").first()

        user.is_locked = False
        db.commit()
        print(f"{Fore.GREEN}[+] Target Identity: {user.username} ({user.full_name} - {user.role})")
        print(f"{Fore.GREEN}[+] Primary Baseline: New Delhi, India (Lat: 28.6139, Lon: 77.2090)\n")

        time.sleep(0.5)

        now = datetime.utcnow()

        # ---------------------------------------------------------
        # Scenario 1: Benign Login (India - 10:00 AM)
        # ---------------------------------------------------------
        print(f"{Fore.CYAN}[SCENARIO 1] Normal Authorized Login from India")
        print(f"{Fore.WHITE}Timestamp: 10:00 AM | Location: New Delhi, India | IP: 103.21.124.5")
        
        t1 = now - timedelta(minutes=5)
        req1 = LoginRequest(
            username="alice_smith",
            password="SecurePassword123!",
            ip_address="103.21.124.5",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            device_fingerprint="fp_alice_workstation_dell",
            timestamp=t1
        )
        res1 = process_login(req1, db)
        eval1 = res1["evaluation"]

        print(f"  {Fore.GREEN}[PASS] Status: ALLOWED (Risk Score: {eval1['risk_score']}/100 [{eval1['risk_level']}])")
        print(f"  {Fore.WHITE}  Device Recognized: Verified Corporate Workstation")
        print(f"  {Fore.WHITE}  Mitigation: {eval1['action_description']}\n")

        time.sleep(0.8)

        # ---------------------------------------------------------
        # Scenario 2: Impossible Travel Anomaly (USA - 10:05 AM)
        # ---------------------------------------------------------
        print(f"{Fore.RED}[SCENARIO 2] Impossible Travel Velocity Anomaly (India -> USA in 5 Minutes)")
        print(f"{Fore.WHITE}Timestamp: 10:05 AM | Location: New York, USA | IP: 198.51.100.22")

        t2 = now
        req2 = LoginRequest(
            username="alice_smith",
            password="SecurePassword123!",
            ip_address="198.51.100.22",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            device_fingerprint="fp_unauthorized_mac_nyc",
            timestamp=t2
        )
        res2 = process_login(req2, db)
        eval2 = res2["evaluation"]
        travel_meta = eval2.get("impossible_travel_telemetry", {})

        print(f"  {Fore.RED}[ALERT] CRITICAL/HIGH THREAT DETECTED!")
        print(f"  {Fore.RED}  Risk Score: {eval2['risk_score']}/100 | Action: {eval2['action']}")
        if travel_meta:
            print(f"  {Fore.YELLOW}  [Forensics] Origin: {travel_meta.get('origin')} -> Destination: {travel_meta.get('destination')}")
            print(f"  {Fore.YELLOW}  [Forensics] Distance: {travel_meta.get('distance_km')} km | Time Elapsed: {int(travel_meta.get('elapsed_seconds', 0)/60)} minutes")
            print(f"  {Fore.RED}  [Physics] Calculated Velocity: {travel_meta.get('speed_kmh')} km/h (Limit: 900 km/h)")
        print(f"  {Fore.MAGENTA}  [MITRE ATT&CK] T1078.004 - Valid Accounts: Cloud Accounts (Geographic Anomaly)\n")

        time.sleep(0.8)

        # ---------------------------------------------------------
        # Scenario 3: Brute Force Burst
        # ---------------------------------------------------------
        print(f"{Fore.YELLOW}[SCENARIO 3] High-Velocity Brute Force / Password Guessing Attack")
        print(f"{Fore.WHITE}Target: bob_jones | Attacker IP: 198.51.100.99 | Sliding Window: 5 Minutes")

        # Ensure Bob is unlocked
        user_bob = db.query(User).filter(User.username == "bob_jones").first()
        if user_bob:
            user_bob.is_locked = False
            db.commit()

        base_time = now
        for i in range(1, 6):
            try:
                req_bf = LoginRequest(
                    username="bob_jones",
                    password=f"GuessedPassword{i}!",
                    ip_address="198.51.100.99",
                    user_agent="Hydra/9.5 (Kali Linux Brute Force Tool)",
                    device_fingerprint="fp_attacker_kali_tool",
                    timestamp=base_time + timedelta(seconds=i * 5)
                )
                res_bf = process_login(req_bf, db)
                score = res_bf["evaluation"]["risk_score"]
                action = res_bf["evaluation"]["action"]
                print(f"  Attempt {i}/5: {Fore.RED}FAIL {Fore.WHITE}| Risk: {score}/100 | Action: {action}")
            except HTTPException as e:
                print(f"  Attempt {i}/5: {Fore.RED}[403 BLOCKED] {e.detail}")

        print(f"  {Fore.RED}[LOCKOUT] Account lockout enforced dynamically.")
        print(f"  {Fore.MAGENTA}  [MITRE ATT&CK] T1110.001 - Brute Force: Password Guessing\n")

        time.sleep(0.8)

        # ---------------------------------------------------------
        # Scenario 4: Anonymizing Tor Exit Node Access
        # ---------------------------------------------------------
        print(f"{Fore.MAGENTA}[SCENARIO 4] Connection via Anonymizing Tor Exit Node")
        print(f"{Fore.WHITE}Target: alice_smith | Location: Frankfurt, Germany | IP: 185.220.101.5 (Known Tor Node)")

        # Unlock Alice for Tor demonstration
        user.is_locked = False
        db.commit()

        req_tor = LoginRequest(
            username="alice_smith",
            password="SecurePassword123!",
            ip_address="185.220.101.5",
            user_agent="Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
            device_fingerprint="fp_tor_bundle_node",
            timestamp=now
        )
        res_tor = process_login(req_tor, db)
        eval_tor = res_tor["evaluation"]

        print(f"  {Fore.YELLOW}[WARN] High-Risk IP / Tor Exit Node Detected")
        print(f"  {Fore.WHITE}  Risk Score: {eval_tor['risk_score']}/100 [{eval_tor['risk_level']}] | Action: {eval_tor['action']}")
        print(f"  {Fore.MAGENTA}  [MITRE ATT&CK] T1090.003 - Multi-hop Proxy: Tor Exit Node\n")

        print(f"{Fore.CYAN}================================================================================")
        print(f"{Fore.GREEN}[+] Simulation Complete! View live alerts & map in browser: http://localhost:8000")
        print(f"{Fore.CYAN}================================================================================")

    finally:
        db.close()

if __name__ == "__main__":
    run_simulation()
