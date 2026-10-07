// app.js - Main application logic, WebSocket, and UI updates
import { init as initScene, fireAttack, fireDefense, fireBenign } from './scene.js?v=8';

// State
let ws;
let feedItems = [];
const seenEventKeys = new Set();
const MAX_FEED_ITEMS = 50;
let dashboardPollTimer;
let heartbeatTimer;

// Metrics state
let stats = {
    totalEvents: 0,
    tp: 0, fp: 0, tn: 0, fn: 0,
    ttdSum: 0, ttdCount: 0
};

// Charts
let perfChart, threatChart;
let perfData = { labels: [], precision: [], recall: [] };
let threatCounts = {};

document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize 3D Scene
    initScene('canvas-container');
    
    // 2. Initialize Charts
    initCharts();
    
    // 3. Connect WebSocket
    connectWebSocket();

    // 4. Bootstrap existing state before live events arrive
    loadDashboardSnapshot();
    // 5. Setup Controls
    setupControls();
    
    // 6. Start clock
    setInterval(updateClock, 1000);
    updateClock();
    dashboardPollTimer = setInterval(loadDashboardSnapshot, 3000);
});

function updateClock() {
    const now = new Date();
    document.getElementById('system-clock').textContent = now.toISOString().split('T')[1].split('.')[0] + " UTC";
}

async function loadDashboardSnapshot() {
    const apiUrl = window.location.protocol === 'file:' ? 'http://localhost:8000/api/dashboard' : '/api/dashboard';
    try {
        const response = await fetch(apiUrl);
        if (!response.ok) throw new Error(`Dashboard request failed (${response.status})`);
        const snapshot = await response.json();
        updateAgentHealth(snapshot);
        updateCampaignStatus(snapshot.red_campaign);
        (snapshot.events || []).slice().reverse().forEach(event => {
            event._ws_type = event.is_attack ? 'attack' : 'traffic';
            handleEvent(event, true);
        });
        updateMetricsFromServer(snapshot.metrics);
    } catch (error) {
        updateAgentHealth({ status: 'degraded', mode: 'offline' });
        console.error('Unable to load dashboard snapshot:', error);
    }
}

function safeText(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[char]));
}

function initCharts() {
    // Global defaults for dark theme
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';

    const ctxPerf = document.getElementById('performanceChart').getContext('2d');
    perfChart = new Chart(ctxPerf, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Precision',
                    data: [],
                    borderColor: '#06b6d4',
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                },
                {
                    label: 'Recall',
                    data: [],
                    borderColor: '#10b981',
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: { maxTicksLimit: 6, autoSkip: true, color: '#64748b', font: { family: 'monospace', size: 10 } },
                    grid: { color: 'rgba(148,163,184,0.08)' }
                },
                y: {
                    min: 0, max: 1,
                    ticks: { stepSize: 0.5, color: '#64748b', font: { family: 'monospace', size: 10 } },
                    grid: { color: 'rgba(148,163,184,0.08)' }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    align: 'start',
                    labels: { usePointStyle: true, pointStyle: 'line', boxWidth: 18, padding: 14, color: '#cbd5e1', font: { size: 11, weight: '600' } }
                }
            },
            animation: { duration: 0 }
        }
    });

    const ctxThreat = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(ctxThreat, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#ec4899', '#06b6d4'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 12 } }
            }
        }
    });
}

function connectWebSocket() {
    const statusEl = document.getElementById('connection-status');
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws`; // Served from FastAPI
    // Fallback if running as static file locally:
    const url = window.location.protocol === 'file:' ? 'ws://localhost:8000/ws' : wsUrl;
    
    if (ws) {
        try { ws.close(); } catch(e) {}
    }
    
    ws = new WebSocket(url);
    
    ws.onopen = () => {
        statusEl.textContent = 'System Active';
        statusEl.style.color = 'var(--color-defense)';
        document.querySelector('.pulse-dot').style.backgroundColor = 'var(--color-defense)';
        clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping');
        }, 15000);
    };
    
    ws.onclose = () => {
        clearInterval(heartbeatTimer);
        statusEl.textContent = 'Connection Lost - Retrying...';
        statusEl.style.color = 'var(--color-attack)';
        document.querySelector('.pulse-dot').style.backgroundColor = 'var(--color-attack)';
        setTimeout(connectWebSocket, 5000); // Reconnect
    };

    ws.onerror = () => {
        statusEl.textContent = 'Connection Lost - Retrying...';
    };
    
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'pong') return;
            if (msg.type === 'metrics') {
                updateMetricsFromServer(msg.data);
                return;
            }
            if (msg.type === 'campaign') {
                updateCampaignStatus(msg.data);
                return;
            }
            // Unwrap the {type, data} envelope from our API
            const payload = msg.data || msg;
            payload._ws_type = msg.type; // 'attack' or 'traffic'
            handleEvent(payload, true);
        } catch (e) {
            console.error('Failed to parse WS message:', e);
        }
    };
}

function handleEvent(event, renderFeed = true) {
    const eventKey = [
        event.timestamp || '',
        event.source_ip || event.source || '',
        event.endpoint || '',
        event.attack_type || '',
        event.action || ''
    ].join('|');
    if (eventKey !== '||||' && seenEventKeys.has(eventKey)) return;
    if (eventKey !== '||||') seenEventKeys.add(eventKey);

    stats.totalEvents++;
    
    // Add to feed
    if (renderFeed) addFeedItem(event);
    
    const isAttack = event._ws_type === 'attack' || event.is_attack === true;
    const isMitigated = event.action === 'blocked' || event.action === 'block';
    updateAttackPath(event);
    
    // Trigger 3D Effects
    if (isAttack) {
        fireAttack();
        
        // Track threat types
        const attackType = event.attack_type || 'Unknown';
        threatCounts[attackType] = (threatCounts[attackType] || 0) + 1;
        updateThreatChart();
        
        if (isMitigated) {
            setTimeout(fireDefense, 1000); // Fire defense after attack arrives
            stats.tp++;
        } else {
            stats.fn++;
        }
    } else {
        fireBenign(); // Visualize Green Agent traffic
        
        if (isMitigated) {
            stats.fp++;
        } else {
            stats.tn++;
        }
    }
    
    if (event.ttd_ms) {
        stats.ttdSum += event.ttd_ms;
        stats.ttdCount++;
    }
    
    updateMetrics();
    updateAgentHealth({ status: 'operational', event_count: stats.totalEvents, last_event_at: event.timestamp });
}

function addFeedItem(event) {
    const feed = document.getElementById('event-feed');
    const isAttack = event._ws_type === 'attack' || event.is_attack === true;
    const isMitigated = event.action === 'blocked' || event.action === 'block';
    
    let typeClass = 'benign';
    if (isAttack) typeClass = 'attack';
    if (isAttack && isMitigated) typeClass = 'mitigated';
    
    const time = new Date().toLocaleTimeString();
    const title = isAttack ? (event.attack_type || 'Attack Detected') : 'Benign Traffic';
    const source = event.source_ip || 'Unknown IP';
    const action = isMitigated ? 'BLOCKED' : 'ALLOWED';
    
    const el = document.createElement('div');
    el.className = `feed-item ${typeClass}`;
    el.innerHTML = `
        <div class="feed-header">
            <span>${safeText(time)}</span>
            <span>${action}</span>
        </div>
        <div class="feed-title">${safeText(title)}</div>
        <div class="feed-details">SRC: ${safeText(source)} | DST: ${safeText(event.endpoint || '/api')}</div>
    `;
    
    feed.prepend(el);
    feedItems.unshift(el);
    
    // Prune old items
    if (feedItems.length > MAX_FEED_ITEMS) {
        const removed = feedItems.pop();
        removed.remove();
    }
}

function updateMetrics() {
    // Total Events
    document.getElementById('val-total-events').textContent = stats.totalEvents;
    
    // Calculate Precision & Recall
    const precision = (stats.tp + stats.fp) === 0 ? 0 : stats.tp / (stats.tp + stats.fp);
    const recall = (stats.tp + stats.fn) === 0 ? 0 : stats.tp / (stats.tp + stats.fn);
    
    document.getElementById('val-precision').textContent = precision.toFixed(2);
    document.getElementById('val-recall').textContent = recall.toFixed(2);
    
    // Avg TTD
    const avgTtd = stats.ttdCount === 0 ? 0 : Math.round(stats.ttdSum / stats.ttdCount);
    document.getElementById('val-ttd').textContent = avgTtd + 'ms';
    
    // Update Perf Chart
    const now = `E${stats.totalEvents}`;
    perfData.labels.push(now);
    perfData.precision.push(precision);
    perfData.recall.push(recall);
    
    if (perfData.labels.length > 30) {
        perfData.labels.shift();
        perfData.precision.shift();
        perfData.recall.shift();
    }

    perfChart.data.labels = perfData.labels;
    perfChart.data.datasets[0].data = perfData.precision;
    perfChart.data.datasets[1].data = perfData.recall;
    perfChart.update();
}

function updateAttackPath(event) {
    const title = event.is_attack ? (event.attack_type || 'Attack detected') : 'Legitimate traffic observed';
    document.getElementById('path-title').textContent = title;
    document.getElementById('path-outcome').textContent = (event.outcome || (event.action === 'blocked' ? 'BLOCKED' : 'ALLOWED')).replace('_', ' ');
    document.getElementById('path-source').textContent = event.source_ip || '—';
    document.getElementById('path-route').textContent = `${(event.decision_path || 'fast').toUpperCase()}${event.confidence ? ` · ${(event.confidence * 100).toFixed(0)}%` : ''}`;
    document.getElementById('path-action').textContent = event.defense_action || event.action || 'observe';
    document.getElementById('path-validation').textContent = event.validation || '—';
    document.querySelectorAll('.pipeline-step').forEach((step, index) => {
        step.classList.toggle('complete', index < 6);
        step.classList.toggle('active', index === 5);
    });
    const timeline = document.getElementById('event-timeline');
    if (timeline) {
        const item = document.createElement('span');
        item.className = event.is_attack ? 'timeline-event attack' : 'timeline-event benign';
        item.textContent = `${event.attack_type || 'traffic'} · ${event.action || 'observe'}`;
        timeline.prepend(item);
        while (timeline.children.length > 5) timeline.lastElementChild.remove();
    }
}

function updateThreatChart() {
    threatChart.data.labels = Object.keys(threatCounts);
    threatChart.data.datasets[0].data = Object.values(threatCounts);
    threatChart.update();
}

function setupControls() {
    const buttons = document.querySelectorAll('.sim-btn:not(.autonomous-btn)');
    buttons.forEach(btn => {
        const originalText = btn.textContent;
        btn.addEventListener('click', async (e) => {
            const scenario = btn.getAttribute('data-scenario');
            
            // Disable buttons temporarily
            buttons.forEach(b => b.disabled = true);
            btn.textContent = 'Launching...';
            
            try {
                // Determine API URL
                const apiUrl = window.location.protocol === 'file:' 
                    ? 'http://localhost:8000/api/simulate' 
                    : '/api/simulate';
                    
                const res = await fetch(apiUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scenario: scenario, rounds: 1 })
                });
                
                if (!res.ok) throw new Error('Simulation API failed');
                
            } catch (err) {
                document.getElementById('connection-status').textContent = 'Backend unavailable';
                console.error("Simulation API failed; no synthetic event was rendered:", err);
            }
            
            setTimeout(() => {
                buttons.forEach(b => b.disabled = false);
                btn.textContent = originalText;
            }, 1000);
        });
    });

    const autonomousButton = document.getElementById('autonomous-campaign');
    autonomousButton.addEventListener('click', async () => {
        autonomousButton.disabled = true;
        autonomousButton.textContent = 'Campaign running...';
        updateCampaignStatus({ status: 'started', rounds: 5, max_events: 25 });
        const apiUrl = window.location.protocol === 'file:'
            ? 'http://localhost:8000/api/red/campaign/start'
            : '/api/red/campaign/start';
        try {
            const response = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rounds: 5, max_events: 25 })
            });
            if (!response.ok) throw new Error(`Campaign API failed (${response.status})`);
            const result = await response.json();
            updateCampaignStatus(result.campaign);
        } catch (error) {
            updateCampaignStatus({ status: 'failed' });
            console.error('Autonomous campaign failed:', error);
        } finally {
            autonomousButton.disabled = false;
            autonomousButton.textContent = 'Start Autonomous';
        }
    });
}

// Handle metrics update from server
function updateMetricsFromServer(data) {
    if (!data) return;
    document.getElementById('val-total-events').textContent = data.event_count ?? stats.totalEvents;
    document.getElementById('val-precision').textContent = (data.precision || 0).toFixed(2);
    document.getElementById('val-recall').textContent = (data.recall || 0).toFixed(2);
    document.getElementById('val-ttd').textContent = Math.round(data.time_to_detect_ms || 0) + 'ms';
    updateAgentHealth({ status: 'operational', event_count: data.event_count ?? stats.totalEvents });
}

function updateAgentHealth(data) {
    if (!data) return;
    const status = data.status || 'operational';
    const isHealthy = status === 'operational' || status === 'ok';
    document.getElementById('agent-status').textContent = isHealthy ? 'Operational' : 'Degraded';
    document.getElementById('agent-mode').textContent = `${data.mode || 'live'} mode`;
    document.getElementById('health-dot').style.backgroundColor = isHealthy ? 'var(--color-defense)' : 'var(--color-attack)';
    document.getElementById('health-dot').style.boxShadow = `0 0 10px ${isHealthy ? 'var(--color-defense)' : 'var(--color-attack)'}`;
    document.getElementById('val-session-events').textContent = data.event_count ?? stats.totalEvents;
    document.getElementById('last-signal').textContent = data.last_event_at
        ? new Date(data.last_event_at).toLocaleTimeString()
        : 'Idle — no events';
}

function updateCampaignStatus(data) {
    if (!data) return;
    const status = data.status || 'idle';
    const rounds = data.rounds ?? 0;
    const events = data.events ?? 0;
    const maxRounds = data.max_rounds ?? data.rounds ?? 5;
    const maxEvents = data.max_events ?? 25;
    const label = status === 'started' ? 'RUNNING' : status.toUpperCase();
    const mode = data.execution_mode ||
        (data.simulation_only === false ? 'live HTTP' : 'simulation');
    const el = document.getElementById('campaign-status');
    el.textContent = `${label}  ·  ${rounds}/${maxRounds} ROUNDS  ·  ${events}/${maxEvents} EVENTS  ·  ${mode}`;
    el.dataset.status = status;
}
