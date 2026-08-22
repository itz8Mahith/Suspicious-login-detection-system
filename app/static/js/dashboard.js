/**
 * AuthSentinel - SOC Threat Intelligence Dashboard Script
 * Handles real-time telemetry polling, Leaflet map flight-vector rendering, Chart.js analytics, and scenario simulations.
 */

let threatMap = null;
let mapLayers = {
    markers: [],
    vectors: []
};
let threatChart = null;
let currentSeverityFilter = 'ALL';

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    initMap();
    initChart();
    fetchAllData();

    // Live refresh loop every 3 seconds
    setInterval(fetchAllData, 3000);
});

// 1. Header UTC Clock
function initClock() {
    function updateClock() {
        const now = new Date();
        const timeStr = now.toUTCString().split(' ')[4] + ' UTC';
        const clockEl = document.getElementById('clockTime');
        if (clockEl) clockEl.textContent = timeStr;
    }
    updateClock();
    setInterval(updateClock, 1000);
}

// 2. Leaflet Threat Map
function initMap() {
    threatMap = L.map('threatMap', {
        center: [25.0, 15.0],
        zoom: 2,
        minZoom: 2,
        maxZoom: 10,
        zoomControl: true,
        attributionControl: false
    });

    // Dark-themed CartoDB map tiles
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(threatMap);
}

// Custom Leaflet Icons
function createGlowMarker(color) {
    return L.divIcon({
        className: 'custom-map-marker',
        html: `<div style="
            width: 14px;
            height: 14px;
            background-color: ${color};
            border: 2px solid #ffffff;
            border-radius: 50%;
            box-shadow: 0 0 12px ${color};
        "></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
    });
}

// 3. Chart.js Threat Distribution
function initChart() {
    const ctx = document.getElementById('threatPieChart').getContext('2d');
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Impossible Travel', 'Brute Force', 'New Device', 'Tor / Proxy'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#ef4444', // Red
                    '#f59e0b', // Yellow
                    '#06b6d4', // Cyan
                    '#8b5cf6'  // Purple
                ],
                borderColor: '#111827',
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#9ca3af',
                        font: { family: 'Plus Jakarta Sans', size: 11 },
                        padding: 12
                    }
                }
            },
            cutout: '70%'
        }
    });
}

// 4. Data Fetching & Polling
async function fetchAllData() {
    try {
        await Promise.all([
            fetchAnalytics(),
            fetchAlerts(),
            fetchLogs()
        ]);
    } catch (err) {
        console.error('Error fetching dashboard telemetry:', err);
    }
}

async function fetchAnalytics() {
    const res = await fetch('/api/analytics');
    const data = await res.json();

    // Update KPI counters
    document.getElementById('statTotalLogins').textContent = data.summary.total_logins;
    document.getElementById('statBlockedLogins').textContent = data.summary.blocked_logins;
    document.getElementById('statHighAlerts').textContent = (data.severity_distribution.HIGH || 0) + (data.severity_distribution.CRITICAL || 0);
    document.getElementById('statTravelAlerts').textContent = data.attack_distribution['Impossible Travel'] || 0;

    // Update Chart
    if (threatChart) {
        threatChart.data.datasets[0].data = [
            data.attack_distribution['Impossible Travel'] || 0,
            data.attack_distribution['Brute Force / Credential Stuffing'] || 0,
            data.attack_distribution['New Device / Fingerprint'] || 0,
            data.attack_distribution['High Risk / Tor IP'] || 0
        ];
        threatChart.update();
    }

    // Render Travel Vectors on World Map
    renderTravelVectors(data.travel_arcs);
}

function renderTravelVectors(arcs) {
    if (!threatMap || !arcs) return;

    // Clear old map layers
    mapLayers.markers.forEach(m => threatMap.removeLayer(m));
    mapLayers.vectors.forEach(v => threatMap.removeLayer(v));
    mapLayers.markers = [];
    mapLayers.vectors = [];

    arcs.forEach(arc => {
        if (!arc.origin_coords || !arc.destination_coords) return;

        const origin = [arc.origin_coords[0], arc.origin_coords[1]];
        const destination = [arc.destination_coords[0], arc.destination_coords[1]];

        // Origin Marker (Green)
        const originMarker = L.marker(origin, { icon: createGlowMarker('#10b981') })
            .bindPopup(`<b>Origin: ${arc.origin}</b><br>User: ${arc.username}`)
            .addTo(threatMap);
        mapLayers.markers.push(originMarker);

        // Destination Marker (Red - Suspicious)
        const destMarker = L.marker(destination, { icon: createGlowMarker('#ef4444') })
            .bindPopup(`<b>Destination: ${arc.destination}</b><br>Velocity: <b>${arc.speed_kmh} km/h</b><br>Distance: ${arc.distance_km} km`)
            .addTo(threatMap);
        mapLayers.markers.push(destMarker);

        // Red Dashed Vector connecting the jump
        const vectorLine = L.polyline([origin, destination], {
            color: '#ef4444',
            weight: 2.5,
            opacity: 0.85,
            dashArray: '6, 8',
            className: 'pulsing-vector'
        }).bindTooltip(`Impossible Travel: ${arc.speed_kmh} km/h`, { sticky: true }).addTo(threatMap);
        mapLayers.vectors.push(vectorLine);
    });
}

async function fetchAlerts() {
    let url = '/api/alerts?limit=20';
    if (currentSeverityFilter !== 'ALL') {
        url += `&severity=${currentSeverityFilter}`;
    }

    const res = await fetch(url);
    const alerts = await res.json();
    const tbody = document.getElementById('alertsBody');

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No security alerts triggered for this filter.</td></tr>`;
        return;
    }

    tbody.innerHTML = alerts.map(a => {
        const sevClass = a.severity.toLowerCase();
        const evidence = a.evidence || {};
        const impossibleTravel = evidence.impossible_travel;

        let evidenceSummary = `${a.description}`;
        if (impossibleTravel) {
            evidenceSummary = `<strong class="text-red">Velocity: ${impossibleTravel.speed_kmh} km/h</strong> (${impossibleTravel.distance_km} km jump from ${impossibleTravel.origin} to ${impossibleTravel.destination})`;
        }

        return `
            <tr>
                <td class="font-mono text-muted">${new Date(a.created_at).toLocaleTimeString()}</td>
                <td><span class="badge badge-${sevClass}">${a.severity}</span></td>
                <td><strong>${a.username}</strong></td>
                <td>${a.title}</td>
                <td>
                    <span class="badge badge-mitre" title="${a.mitre?.name || 'T1078'}">
                        ${a.mitre?.id || 'T1078'}
                    </span>
                </td>
                <td><span class="font-mono text-secondary" style="font-size: 0.75rem;">${evidenceSummary}</span></td>
                <td>
                    <span class="font-mono ${a.severity === 'CRITICAL' ? 'text-red font-weight-bold' : 'text-yellow'}">
                        ${a.severity === 'CRITICAL' ? 'BLOCKED & LOCKED' : (a.severity === 'HIGH' ? 'STEP-UP AUTH' : 'MFA CHALLENGE')}
                    </span>
                </td>
            </tr>
        `;
    }).join('');
}

async function fetchLogs() {
    const res = await fetch('/api/logs?limit=10');
    const logs = await res.json();
    const tbody = document.getElementById('logsBody');

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-3 text-muted">No audit logs recorded.</td></tr>`;
        return;
    }

    tbody.innerHTML = logs.map(l => {
        const scoreColor = l.risk_score > 60 ? 'text-red' : (l.risk_score > 25 ? 'text-yellow' : 'text-green');
        return `
            <tr>
                <td class="font-mono text-muted">${new Date(l.timestamp).toLocaleTimeString()}</td>
                <td><strong>${l.username}</strong></td>
                <td>${l.city ? `${l.city}, ${l.country}` : 'Unknown'}</td>
                <td class="font-mono">${l.ip_address}</td>
                <td class="font-mono ${scoreColor}"><strong>${l.risk_score}/100</strong></td>
                <td><span class="badge badge-${l.risk_level.toLowerCase()}">${l.action_taken}</span></td>
            </tr>
        `;
    }).join('');
}

// 5. Scenario Simulation Trigger
async function runScenario(scenarioType) {
    try {
        const res = await fetch('/api/simulate/scenario', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scenario: scenarioType, target_user: 'alice_smith' })
        });

        const data = await res.json();
        openModal(scenarioType, data);
        fetchAllData(); // Instant refresh
    } catch (err) {
        alert('Simulation failed: ' + err.message);
    }
}

// 6. Custom Login Tester Form
async function handleCustomLogin(event) {
    event.preventDefault();
    const user = document.getElementById('customUser').value;
    const pass = document.getElementById('customPass').value;
    const ip = document.getElementById('customIP').value;
    const ua = document.getElementById('customUA').value;

    try {
        const res = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user,
                password: pass,
                ip_address: ip,
                user_agent: ua
            })
        });

        const data = await res.json();
        openModal('custom_evaluation', data);
        fetchAllData();
    } catch (err) {
        alert('Evaluation failed: ' + err.message);
    }
}

// 7. Modal Presentation
function openModal(title, payload) {
    const modal = document.getElementById('resultModal');
    const titleEl = document.getElementById('modalScenarioTitle');
    const contentEl = document.getElementById('modalResultContent');

    titleEl.textContent = `Simulation Execution: ${title.toUpperCase().replace('_', ' ')}`;

    let html = '';

    if (payload.scenario === 'impossible_travel') {
        const step1 = payload.executions[0].result.evaluation;
        const step2 = payload.executions[1].result.evaluation;
        const travel = step2.impossible_travel_telemetry;

        html = `
            <div style="margin-bottom: 1rem;">
                <h4 class="text-cyan"><i class="fa-solid fa-plane-departure"></i> Impossible Travel Scenario Flow</h4>
                <p class="text-secondary" style="font-size: 0.85rem; margin-top: 0.2rem;">
                    Demonstrating a physically impossible transition between geographic coordinates within 5 minutes.
                </p>
            </div>

            <div class="telemetry-box" style="border-left: 3px solid var(--accent-green);">
                <div class="telemetry-row">
                    <span>Step 1: Baseline Login</span>
                    <strong class="text-green">${step1.geolocation.city}, ${step1.geolocation.country} (10:00 AM)</strong>
                </div>
                <div class="telemetry-row">
                    <span>Risk Score / Decision</span>
                    <span class="badge badge-low">${step1.risk_score} / ALLOW</span>
                </div>
            </div>

            <div class="telemetry-box" style="border-left: 3px solid var(--accent-red); margin-top: 0.75rem;">
                <div class="telemetry-row">
                    <span>Step 2: Impossible Login</span>
                    <strong class="text-red">${step2.geolocation.city}, ${step2.geolocation.country} (10:05 AM)</strong>
                </div>
                <div class="telemetry-row">
                    <span>Great-Circle Distance</span>
                    <span>${travel ? travel.distance_km : 11700} km</span>
                </div>
                <div class="telemetry-row">
                    <span>Calculated Velocity</span>
                    <strong class="text-red">${travel ? travel.speed_kmh : '140,400'} km/h (Supersonic Anomaly)</strong>
                </div>
                <div class="telemetry-row">
                    <span>Max Physical Airliner Speed</span>
                    <span>900 km/h</span>
                </div>
                <div class="telemetry-row">
                    <span>Calculated Risk Score</span>
                    <strong class="text-red">${step2.risk_score} / 100 [${step2.risk_level}]</strong>
                </div>
                <div class="telemetry-row">
                    <span>Mitigation Action</span>
                    <strong class="text-red">${step2.action} (${step2.action_description})</strong>
                </div>
            </div>
        `;
    } else if (payload.scenario === 'brute_force') {
        html = `
            <div style="margin-bottom: 1rem;">
                <h4 class="text-yellow"><i class="fa-solid fa-keyboard"></i> Brute Force Velocity Burst</h4>
                <p class="text-secondary" style="font-size: 0.85rem;">
                    Executed 5 rapid authentication failures within a 25-second sliding window.
                </p>
            </div>
            <div class="telemetry-box">
                <div class="telemetry-row">
                    <span>Total Attempts</span>
                    <strong>5 Failed Logins</strong>
                </div>
                <div class="telemetry-row">
                    <span>Sliding Window Epoch</span>
                    <span>5 Minutes</span>
                </div>
                <div class="telemetry-row">
                    <span>MITRE ATT&CK ID</span>
                    <span class="badge badge-mitre">T1110.001 (Password Guessing)</span>
                </div>
                <div class="telemetry-row">
                    <span>Response Action</span>
                    <strong class="text-yellow">MFA Step-Up Challenge & Alert Raised</strong>
                </div>
            </div>
        `;
    } else {
        const evalData = payload.evaluation || (payload.executions && payload.executions[0] ? payload.executions[0].result.evaluation : {});
        html = `
            <div class="telemetry-box">
                <div class="telemetry-row">
                    <span>Evaluated Target</span>
                    <strong>${evalData.username || 'user'}</strong>
                </div>
                <div class="telemetry-row">
                    <span>Calculated Risk Score</span>
                    <strong class="${evalData.risk_score > 50 ? 'text-red' : 'text-green'}">${evalData.risk_score || 0} / 100</strong>
                </div>
                <div class="telemetry-row">
                    <span>Threat Classification</span>
                    <span class="badge badge-${(evalData.risk_level || 'LOW').toLowerCase()}">${evalData.risk_level || 'LOW'}</span>
                </div>
                <div class="telemetry-row">
                    <span>Automated Action</span>
                    <strong>${evalData.action || 'ALLOW'}</strong>
                </div>
                <div class="telemetry-row">
                    <span>Triggered Security Rules</span>
                    <span>${(evalData.triggered_rules || []).map(r => r.name).join(', ') || 'None (Normal Access)'}</span>
                </div>
            </div>
        `;
    }

    contentEl.innerHTML = html;
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('resultModal').classList.add('hidden');
}

function filterAlerts(severity) {
    currentSeverityFilter = severity;
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    fetchAlerts();
}
