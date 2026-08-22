# 🐙 Step-by-Step GitHub Publication Guide

Follow these exact steps to publish **AuthSentinel (Suspicious Login Detection System)** to your GitHub profile and showcase it as a high-impact cybersecurity portfolio project.

---

## 1. Create a New Repository on GitHub

1. Log into your account at [github.com](https://github.com).
2. Click the **+** (plus icon) in the top right corner &rarr; select **New repository**.
3. Fill in the repository details:
   - **Repository Name**: `suspicious-login-detection-system` (or `auth-sentinel`)
   - **Description**: `🛡️ Industry-grade cybersecurity detection engine for Impossible Travel, Brute Force, and Behavioral Anomalies with interactive SOC Dashboard & MITRE ATT&CK mapping.`
   - **Visibility**: **Public** (recommended for portfolio visibility)
   - **Do NOT check** "Add a README file", "Add .gitignore", or "Choose a license" (we already created them locally).
4. Click **Create repository**.

---

## 2. Initialize Git & Push from Local Terminal

Open your terminal (PowerShell, Command Prompt, or VS Code terminal) in the project directory:

```bash
cd "C:\Users\91808\.gemini\antigravity\scratch\suspicious-login-detection-system"
```

Run the following commands in sequence:

```bash
# Step 1: Initialize Git repository
git init

# Step 2: Add all files
git add .

# Step 3: Create initial commit
git commit -m "feat: initial commit for AuthSentinel suspicious login detection engine"

# Step 4: Rename branch to main
git branch -M main

# Step 5: Link to your remote GitHub repo (Replace <YOUR_USERNAME> with your GitHub username)
git remote add origin https://github.com/<YOUR_USERNAME>/suspicious-login-detection-system.git

# Step 6: Push your code to GitHub
git push -u origin main
```

---

## 3. Add GitHub Repository Topics & Tags

Adding relevant topics dramatically improves discovery and recruiter search ranking:

1. On your GitHub repository page, click the ⚙️ **gear icon** next to **About** in the right-hand sidebar.
2. Under **Topics**, add:
   ```
   cybersecurity
   anomaly-detection
   mitre-attack
   threat-intelligence
   impossible-travel
   soc-analyst
   fastapi
   python
   incident-response
   identity-and-access-management
   ```
3. Under **Website**, if you deploy to Render / Railway / Vercel or have a portfolio site, enter the URL.
4. Click **Save changes**.

---

## 4. Pin the Repository to Your GitHub Profile

1. Go to your GitHub profile: `https://github.com/<YOUR_USERNAME>`.
2. Click **Customize your pins** (or **Edit pins**).
3. Check **`suspicious-login-detection-system`**.
4. Click **Save pins**.

---

## 5. Embed in Your GitHub Profile README (`username/username`)

Add this formatted project card into your main profile README:

```markdown
### 🛡️ Featured Cybersecurity Project

#### [AuthSentinel — Suspicious Login & Anomaly Detection System](https://github.com/<YOUR_USERNAME>/suspicious-login-detection-system)
*Real-time Behavioral & Geospatial Telemetry Threat Engine with MITRE ATT&CK Mapping*

- **Impossible Travel Engine**: Calculates Great-Circle Haversine distance and flags supersonic velocity anomalies (>900 km/h airline limits).
- **Behavioral Profiling**: Learns user working hours and device fingerprint entropy to detect account takeover (ATO).
- **Interactive SOC Dashboard**: Real-time Leaflet.js world map with animated attack vectors, live threat analytics, and one-click attack simulations.
- **Tech Stack**: Python 3.11+, FastAPI, SQLAlchemy, SQLite, Leaflet.js, Chart.js, Docker, Pytest.
```
