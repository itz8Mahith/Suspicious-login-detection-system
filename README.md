<div align="center">

# 🛡️ AuthSentinel: Suspicious Login & Anomaly Detection System

**Industry-Grade Behavioral Telemetry, Geospatial Velocity & Impossible Travel Anomaly Detection Engine**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-critical.svg?style=for-the-badge&logo=shield)](https://attack.mitre.org/)
[![Tests](https://img.shields.io/badge/Pytest-16%2F16%20Passing-success.svg?style=for-the-badge&logo=pytest)](https://docs.pytest.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=for-the-badge&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

[Live Features](#-key-features) • [Threat Model](#-threat-model--mitre-attck) • [Mathematical Model](#-impossible-travel-mathematics) • [Quickstart](#-quickstart) • [API Docs](#-api-reference)

</div>

---

## 📌 Problem Statement

In enterprise environments, account takeover (ATO) and credential-based attacks are among the top causes of data breaches. Attackers frequently utilize stolen credentials, session hijacking, or automated credential stuffing tools from disparate regions across the globe.

A critical security challenge is distinguishing **legitimate user access** from **adversarial takeover** in real-time.

```
[Normal Access]      India — 10:00 AM  (Baseline Workstation)  --> Status: ALLOWED (Score: 0/100)
[Suspicious Access]  USA   — 10:05 AM  (Unknown MacBook)       --> ALERT: Impossible Travel (141,000+ km/h) -> BLOCKED!
```

**AuthSentinel** provides an autonomous multi-factor risk scoring engine that correlates geospatial velocity, device fingerprint entropy, sliding-window authentication failures, and historical behavioral baselines to detect and neutralize unauthorized access attempts in sub-milliseconds.

---

## 🌟 Key Features

- ✈️ **Geospatial Impossible Travel Detection**: Uses the **Haversine Great-Circle formula** to compute distances and travel speeds between successive logins, flagging physical violations (>900 km/h commercial airliner speed).
- 💻 **Client Device & Fingerprint Entropy**: Analyzes User-Agent, browser engine, operating system, and hardware hashes against user baseline history.
- 🕒 **Behavioral Working Hour Deviation**: Computes active operational baselines and flags anomalous off-hours access (e.g., 3:30 AM anomalies).
- 🛑 **Sliding-Window Brute Force & Credential Stuffing Guard**: Tracks failure velocities within a rolling 5-minute epoch to trigger dynamic MFA challenges and automated account lockouts.
- 🌐 **Threat Intelligence & Tor Exit Node Detection**: Identifies known anonymizing proxies, Tor relays, and high-risk VPN endpoints.
- 📊 **Interactive SOC Threat Intelligence Dashboard**: Dark-mode Cyber Operations Center UI featuring a **Leaflet.js interactive world map** with animated flight vectors, Chart.js analytics, live alert feeds, and one-click attack simulation buttons.
- ⚡ **Autonomous Simulation CLI**: Built-in `simulate_attacks.py` script for live terminal demonstrations and SOC testing.

---

## 🎯 Threat Model & MITRE ATT&CK Mapping

| Threat / Anomaly Vector | MITRE Technique ID | MITRE Technique Name | Tactical Objective | Automated Mitigation Action |
| :--- | :--- | :--- | :--- | :--- |
| **Impossible Travel Anomaly** | `T1078.004` | Valid Accounts: Cloud Accounts (Geo Anomaly) | Initial Access / Persistence | **Step-Up Email OTP / Step-Up Auth** |
| **Password Guessing / Brute Force** | `T1110.001` | Brute Force: Password Guessing | Credential Access | **Account Lockout & SOC Alert** |
| **Credential Stuffing** | `T1110.004` | Brute Force: Credential Stuffing | Credential Access | **IP Rate Limit & Temporary Block** |
| **Unrecognized Device / UA** | `T1078` | Valid Accounts (Device Entropy) | Defense Evasion | **MFA Push Challenge** |
| **Tor Exit Node / High-Risk Proxy** | `T1090.003` | Proxy: Multi-hop Proxy | Command & Control | **Session Block & Quarantine** |
| **Off-Hours / Night Anomaly** | `T1078` | Valid Accounts (Off-Hours Access) | Persistence | **Risk Score Penalty (+15)** |

---

## 📐 Impossible Travel Mathematics

The system calculates the spherical surface distance between two latitude/longitude points \((\phi_1, \lambda_1)\) and \((\phi_2, \lambda_2)\) using the **Haversine Formula**:

$$a = \sin^2\left(\frac{\Delta\phi}{2}\right) + \cos(\phi_1)\cos(\phi_2)\sin^2\left(\frac{\Delta\lambda}{2}\right)$$

$$c = 2 \cdot \text{atan2}\left(\sqrt{a}, \sqrt{1-a}\right)$$

$$d = R \cdot c \quad (\text{where } R = 6371\text{ km})$$

The apparent travel velocity $v$ is determined by:

$$v = \frac{d}{\Delta t} \quad (\text{km/h})$$

$$\text{Decision} = \begin{cases} \text{ANOMALY (Impossible Travel)}, & \text{if } v > 900\text{ km/h} \text{ and } d > 50\text{ km} \\ \text{NORMAL (Plausible Travel)}, & \text{otherwise} \end{cases}$$

---

## 🏗️ System Architecture

```
                                +---------------------------+
                                | Incoming Login Request    |
                                | (IP, User-Agent, Time)    |
                                +-------------+-------------+
                                              |
                                              v
                                +-------------+-------------+
                                |  FastAPI Gateway Layer    |
                                +-------------+-------------+
                                              |
               +------------------------------+------------------------------+
               |                              |                              |
               v                              v                              v
    +--------------------+         +--------------------+         +--------------------+
    | Geo Physics Engine |         |  Behavioral Engine |         |  Velocity Engine   |
    | (Haversine & Speed)|         | (Device & Working) |         | (Sliding Window BF)|
    +----------+---------+         +----------+---------+         +----------+---------+
               |                              |                              |
               +------------------------------+------------------------------+
                                              |
                                              v
                                +-------------+-------------+
                                | Multi-Factor Risk Engine  |
                                | Composite Score: 0 - 100  |
                                +-------------+-------------+
                                              |
                     +------------------------+------------------------+
                     |                        |                        |
              Score 0 - 29             Score 30 - 79            Score 80 - 100
                     |                        |                        |
                     v                        v                        v
            +----------------+       +----------------+       +----------------+
            |  ALLOW LOGIN   |       | MFA / STEP-UP  |       | BLOCK & LOCK   |
            | Update Baseline|       | Trigger Alert  |       | Notify SOC     |
            +----------------+       +----------------+       +----------------+
```

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- Git

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/<YOUR_USERNAME>/suspicious-login-detection-system.git
cd suspicious-login-detection-system

python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Run the Autonomous Attack Simulation
```bash
python simulate_attacks.py
```

### 3. Launch the SOC Web Dashboard & API
```bash
uvicorn app.main:app --reload --port 8000
```
Open your browser and navigate to: **`http://localhost:8000`**

---

## 🐳 Docker Deployment

Run with Docker in a single command:

```bash
docker-compose up --build
```
Access the dashboard at `http://localhost:8000`.

---

## 🧪 Running the Test Suite

Run full mathematical and endpoint test suites with coverage:

```bash
python -m pytest -v
```

---

## 📡 API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Evaluates login telemetry and enforces threat mitigations |
| `GET` | `/api/analytics` | Returns SOC threat stats, KPI counts, and impossible travel vectors |
| `GET` | `/api/alerts` | Streams real-time security alerts and MITRE ATT&CK evidence |
| `GET` | `/api/logs` | Audit trail of all authentication events |
| `POST` | `/api/simulate/scenario` | Triggers preset attack scenarios (`impossible_travel`, `brute_force`, `tor_proxy`, etc.) |
| `GET` | `/api/users` | Lists registered accounts and learned baselines |

---

## 👤 Author & Portfolio Showcase

- **Author**: Cybersecurity Analyst & Detection Engineer
- **Project**: Suspicious Login & Anomaly Detection System (AuthSentinel)
- **Domain**: Identity and Access Management (IAM), SOC Threat Detection, Threat Intelligence
