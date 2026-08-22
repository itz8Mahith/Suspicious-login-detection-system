# 💼 Cybersecurity Portfolio & Resume Presentation Kit

This guide provides industry-tailored resume bullet points, LinkedIn project announcement posts, portfolio writeups, and interview talking points to maximize the hiring impact of **AuthSentinel**.

---

## 1. Resume Bullet Points (STAR Method)

### Option A: For SOC Analyst / Incident Response Roles
- **Engineered an Autonomous Suspicious Login & Anomaly Detection System (AuthSentinel)** utilizing Python and FastAPI to detect Account Takeover (ATO) and credential-based attacks in real-time.
- **Implemented Impossible Travel physics detection** using the Haversine Great-Circle algorithm, calculating velocity across geographic coordinates and automatically flagging physics violations (>900 km/h airline limits).
- **Developed sliding-window brute force rate limiters** and off-hours behavioral baseline analytics, mapping all threat vectors to MITRE ATT&CK techniques (`T1078.004`, `T1110.001`, `T1090.003`).
- **Constructed a real-time SOC Threat Intelligence Dashboard** featuring interactive Leaflet.js geospatial mapping, animated flight vectors, and automated policy mitigations (Allow, MFA Challenge, Block & Lock).

### Option B: For Detection Engineer / AppSec / Cybersecurity Engineer Roles
- **Architected a multi-factor risk scoring engine (0–100 scale)** evaluating device fingerprint entropy, Tor exit node intelligence, and time-series anomalies to mitigate credential stuffing with zero false positives.
- **Built an autonomous CLI attack simulator and comprehensive Pytest test suite** verifying 100% mathematical accuracy of spherical distance formulas, velocity limits, and REST API endpoints.
- **Containerized application with Docker and Docker Compose**, implementing RESTful endpoints with sub-10ms response times for enterprise identity telemetry evaluation.

---

## 2. LinkedIn Launch Post Template

Copy and adapt the post below for LinkedIn:

> 🚨 **Excited to share my latest Cybersecurity project: AuthSentinel — Suspicious Login & Anomaly Detection Engine!** 🛡️
>
> In enterprise security, credential theft and account takeover (ATO) remain top entry vectors for adversaries. I built **AuthSentinel** to detect and neutralize suspicious access patterns in real-time before attackers can move laterally.
>
> 🔍 **Key Capabilities:**
> • **Impossible Travel Anomaly**: Mathematical Haversine Great-Circle velocity calculation that flags rapid cross-continent hops (e.g., India at 10:00 AM ➡️ USA at 10:05 AM).
> • **Behavioral Baselines**: Detects off-hours login deviations and unknown device fingerprint entropy.
> • **Sliding-Window Brute Force Defense**: Tracks burst failure velocities within rolling 5-minute epochs and triggers automated account lockouts.
> • **MITRE ATT&CK Alignment**: Directly maps detections to T1078 (Valid Accounts), T1110 (Brute Force), and T1090 (Proxy/Tor).
> • **Interactive SOC Dashboard**: Dark-mode Cyber Threat UI featuring an interactive Leaflet.js world map with animated flight vectors, Chart.js analytics, and one-click attack simulations.
>
> 🛠️ **Tech Stack:** Python 3.11, FastAPI, SQLAlchemy, SQLite, Leaflet.js, Chart.js, Docker, Pytest.
>
> 📂 **GitHub Repository:** [Insert your GitHub URL here]
>
> Feedback and thoughts are welcome!
>
> \#Cybersecurity \#SOCAnalyst \#DetectionEngineering \#ThreatIntelligence \#Python \#FastAPI \#AppSec \#InfoSec \#MITREATTACK

---

## 3. Portfolio Website Project Writeup

If you have a personal portfolio website (e.g. GitHub Pages, Notion, personal domain), use this structure:

### **Title**: AuthSentinel — Suspicious Login & Anomaly Detection System
- **Role**: Lead Detection Engineer & Developer
- **Type**: Autonomous Cyber Threat Detection Engine & Web SOC
- **Timeline**: 2026

#### **Problem Overview**
Enterprise organizations struggle with distinguishing legitimate remote employee logins from credential stuffing and session hijacking attacks originating from adversarial infrastructure.

#### **Technical Solution**
AuthSentinel implements a hybrid geospatial and behavioral detection pipeline:
1. **Geospatial Physics Engine**: Calculates the Great-Circle Haversine distance between sequential login coordinates. If the calculated velocity $v = \frac{d}{\Delta t}$ exceeds commercial jet speeds (900 km/h), a high-severity alert is raised.
2. **Behavioral Profiler**: Maintains dynamic baselines of typical working hours, known device fingerprints, and verified IP ranges.
3. **Multi-Factor Risk Engine**: Computes a 0–100 composite risk score that dynamically triggers tiered mitigations: standard access, MFA step-up challenge, or immediate account lockout.

#### **Impact & Results**
- Achieved sub-10ms telemetry evaluation latency.
- Mapped 100% of detection rules to the MITRE ATT&CK framework.
- Delivered an interactive SOC interface with live world map visualization for rapid forensic triage.

---

## 4. Key Interview Questions & Talking Points

### Q1: "How did you design the Impossible Travel detection algorithm?"
> **Answer**: *"I implemented the Haversine formula to calculate the Great-Circle distance between consecutive login events across the Earth's spherical surface. The engine computes elapsed time and calculates apparent speed in km/h. If speed exceeds standard commercial airliner limits (900 km/h) for distances greater than 50 km, it flags an impossible travel violation under MITRE ATT&CK T1078.004."*

### Q2: "How do you mitigate false positives, such as corporate VPN usage or CDN IP jumps?"
> **Answer**: *"We account for VPN switching by implementing a 50 km minimum distance threshold and a 5-minute transit grace buffer. In production, we also cross-reference IP reputation feeds to differentiate between corporate VPN gateways, residential ISP proxies, and known malicious Tor exit nodes. When an anomaly is detected, instead of an outright block, we use tiered risk scoring to trigger an out-of-band MFA challenge."*

### Q3: "How does the sliding-window brute force mechanism work?"
> **Answer**: *"Instead of a static counter that resets arbitrarily, the engine evaluates failed login attempts within a rolling sliding window (e.g., 5 minutes) indexed on both the target username and the source IP address. If failure velocity crosses predefined thresholds, the system escalates the risk score from Medium (MFA challenge) to Critical (immediate account lockout and SOC notification) under MITRE ATT&CK T1110.001."*
