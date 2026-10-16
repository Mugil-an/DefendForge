import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import TargetConfigCard from './components/TargetConfigCard';
import AttackTriggerDeck from './components/AttackTriggerDeck';
import ArenaBattlefield from './components/ArenaBattlefield';
import MetricsHUD from './components/MetricsHUD';
import LiveEventFeed from './components/LiveEventFeed';

export default function App() {
  const [targetUrl, setTargetUrl] = useState('');
  const [targetPath, setTargetPath] = useState('');
  const [isRunning, setIsRunning] = useState(false);
  const [activeRound, setActiveRound] = useState(1);
  const [isConnected, setIsConnected] = useState(false);

  const [events, setEvents] = useState([]);
  const [currentAttack, setCurrentAttack] = useState(null);
  const [currentDefense, setCurrentDefense] = useState(null);
  const [metrics, setMetrics] = useState({
    precision: 0,
    recall: 0,
    time_to_detect_ms: 0,
    time_to_remediate_ms: 0,
  });
  const [totalAttacks, setTotalAttacks] = useState(0);
  const [blockedAttacks, setBlockedAttacks] = useState(0);
  const [wafRulesCount, setWafRulesCount] = useState(0);
  const [lastAttackResult, setLastAttackResult] = useState(null);
  const [discoveredSurface, setDiscoveredSurface] = useState(null);

  const wsRef = useRef(null);
  const seenEventsRef = useRef(new Set());

  // Initialize WebSocket connection with strict lifecycle management & timer cleanup
  useEffect(() => {
    let ws = null;
    let reconnectTimer = null;
    let isDisposed = false;

    const connect = () => {
      if (isDisposed) return;
      if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
        return;
      }

      const wsUrl = window.location.protocol === 'https:'
        ? `wss://${window.location.host}/ws`
        : `ws://${window.location.hostname || 'localhost'}:8000/ws`;

      try {
        ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isDisposed) {
            ws.close();
            return;
          }
          setIsConnected(true);
          console.log('[WS] Connected to DefendForge Telemetry Mesh');
        };

        ws.onmessage = (event) => {
          if (isDisposed) return;
          try {
            const data = JSON.parse(event.data);
            handleIncomingEvent(data);
          } catch (err) {
            console.error('Failed to parse WS payload', err);
          }
        };

        ws.onclose = () => {
          setIsConnected(false);
          if (!isDisposed) {
            reconnectTimer = setTimeout(connect, 3000);
          }
        };

        ws.onerror = () => {
          setIsConnected(false);
        };
      } catch (e) {
        setIsConnected(false);
        if (!isDisposed) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      }
    };

    connect();

    return () => {
      isDisposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) {
        ws.onclose = null; // Prevent onclose callback from scheduling an orphan reconnect
        ws.close();
      }
      wsRef.current = null;
    };
  }, []);

  // Fetch initial telemetry, dashboard snapshot, and WAF rules from backend on mount
  useEffect(() => {
    fetch('/api/dashboard')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) {
          if (data.metrics) setMetrics(data.metrics);
          if (data.active_round) setActiveRound(data.active_round);
          if (typeof data.arena_running === 'boolean') setIsRunning(data.arena_running);
          if (typeof data.total_attacks === 'number') setTotalAttacks(data.total_attacks);
          if (typeof data.blocked_attacks === 'number') setBlockedAttacks(data.blocked_attacks);
          if (typeof data.active_rules_count === 'number') setWafRulesCount(data.active_rules_count);
          if (Array.isArray(data.recent_events) && data.recent_events.length > 0) {
            setEvents(data.recent_events);
          }
          if (data.current_attack) setCurrentAttack(data.current_attack);
          if (data.current_defense) setCurrentDefense(data.current_defense);
        }
      })
      .catch(() => {});

    fetch('/api/metrics')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && typeof data.precision === 'number') {
          setMetrics(data);
          if (data.round) setActiveRound(data.round);
        }
      })
      .catch(() => {});

    fetch('/api/rules')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.waf_rules?.rules) {
          setWafRulesCount(data.waf_rules.rules.length);
        }
      })
      .catch(() => {});
  }, []);

  const handleIncomingEvent = (msg) => {
    const { type, data } = msg;

    if (type === 'sync' && data) {
      if (data.metrics) setMetrics(data.metrics);
      if (data.active_round) setActiveRound(data.active_round);
      if (typeof data.arena_running === 'boolean') setIsRunning(data.arena_running);
      if (typeof data.total_attacks === 'number') setTotalAttacks(data.total_attacks);
      if (typeof data.blocked_attacks === 'number') setBlockedAttacks(data.blocked_attacks);
      if (typeof data.active_rules_count === 'number') setWafRulesCount(data.active_rules_count);
      if (Array.isArray(data.recent_events) && data.recent_events.length > 0) {
        setEvents(data.recent_events);
      }
      if (data.current_attack) setCurrentAttack(data.current_attack);
      if (data.current_defense) setCurrentDefense(data.current_defense);
      return;
    }

    if (type === 'attack' || type === 'traffic') {
      // Deduplicate by event_id, request_id, or composite signature
      const eventKey = data.event_id || data.request_id || `${data.endpoint}_${data.method}_${data.timestamp}_${data.attack_type || 'benign'}`;
      if (seenEventsRef.current.has(eventKey)) {
        return; // Ignore duplicate
      }
      seenEventsRef.current.add(eventKey);
      if (seenEventsRef.current.size > 1000) {
        const iter = seenEventsRef.current.values();
        for (let i = 0; i < 400; i++) seenEventsRef.current.delete(iter.next().value);
      }

      setEvents((prev) => [data, ...prev.slice(0, 150)]);

      if (data.is_attack) {
        setTotalAttacks((c) => c + 1);
        setCurrentAttack({
          attack_type: data.attack_type || 'Unknown Exploit',
          endpoint: data.endpoint || data.path || '/',
          method: data.method || 'GET',
          payload: data.payload || data.body || data.query || (data.params ? JSON.stringify(data.params) : 'N/A'),
          mitre_technique: data.mitre_technique || 'T1190',
          evasion: data.evasion || 'none',
        });

        const isBlock = ['blocked', 'block_ip', 'block_source_ip', 'rate_limit', 'update_security_rule', 'apply_known_patch'].includes(data.action);
        if (isBlock) {
          setBlockedAttacks((c) => c + 1);
        }

        setCurrentDefense({
          action: data.action || (isBlock ? 'block_ip' : 'allowed'),
          anomaly_score: data.confidence || data.anomaly_score || 0.85,
          decision_path: data.decision_path || (isBlock ? 'fast' : 'slow'),
          reasoning: data.rationale || (isBlock ? 'Attacking payload flagged by ML detector; blocked via WAF policy.' : 'Traffic allowed.'),
        });
      } else {
        // Legitimate user traffic generated locally
        setCurrentAttack(null);
        setCurrentDefense({
          action: 'allowed',
          anomaly_score: data.confidence || data.anomaly_score || 0.05,
          decision_path: 'fast',
          reasoning: data.rationale || 'Legitimate local traffic verified by anomaly detector; permitted without disruption.',
        });
      }
    } else if (type === 'campaign' || type === 'arena') {
      if (data.status === 'started' || data.status === 'running') {
        setIsRunning(true);
      } else if (data.status === 'stopped' || data.status === 'completed' || data.status === 'idle') {
        setIsRunning(false);
      }
      if (data.round || data.rounds) {
        setActiveRound(data.round || data.rounds);
      }
    } else if (type === 'metrics') {
      setMetrics(data);
    } else if (type === 'surface_discovered') {
      setDiscoveredSurface(data);
    }
  };

  const handleLaunch = async (config) => {
    setIsRunning(true);
    setActiveRound(1);
    setTotalAttacks(0);
    setBlockedAttacks(0);

    const apiUrl = window.location.protocol === 'file:'
      ? 'http://localhost:8000/api/arena/start'
      : '/api/arena/start';

    try {
      const resp = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: config.targetUrl,
          target_path: config.targetPath,
          use_llm: config.useLLM ?? true,
        }),
      });

      if (!resp.ok) {
        throw new Error(`Arena launch failed with status ${resp.status}`);
      }

      const res = await resp.json();
      console.log('[+] Arena continuous battle active:', res);
      if (res && res.total_routes) {
        setDiscoveredSurface(res);
      }
      // Arena continues running asynchronously until STOP ARENA is clicked!
    } catch (err) {
      console.error('Backend API error starting arena:', err);
      setIsRunning(false);
      alert(`Could not start arena battle: ${err.message}. Ensure DefendForge backend is running on :8000.`);
    }
  };

  const handleStop = async () => {
    setIsRunning(false);
    const stopUrl = window.location.protocol === 'file:'
      ? 'http://localhost:8000/api/arena/stop'
      : '/api/arena/stop';
    try {
      await fetch(stopUrl, { method: 'POST' });
    } catch (err) {
      console.error('Error stopping arena:', err);
    }
  };

  const handleReset = async () => {
    setIsRunning(false);
    seenEventsRef.current.clear();
    setEvents([]);
    setCurrentAttack(null);
    setCurrentDefense(null);
    setTotalAttacks(0);
    setBlockedAttacks(0);
    setActiveRound(1);
    setDiscoveredSurface(null);
    try {
      await fetch('/api/arena/stop', { method: 'POST' });
      await fetch('/api/red/campaign/reset', { method: 'POST' });
    } catch (_) {}
  };

  const handleTriggerAttack = async (attackParams) => {
    setIsRunning(true);
    setLastAttackResult(null);

    const apiUrl = window.location.protocol === 'file:'
      ? 'http://localhost:8000/api/attack/trigger'
      : '/api/attack/trigger';

    try {
      const resp = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(attackParams),
      });

      if (!resp.ok) {
        throw new Error(`Attack execution failed with HTTP ${resp.status}`);
      }

      const res = await resp.json();
      setLastAttackResult(res);

      if (res.event) {
        handleIncomingEvent({ type: 'attack', data: res.event });
      }
    } catch (err) {
      console.error('Attack execution failed:', err);
      alert(`Attack trigger error: ${err.message}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '24px' }}>
      <Header
        isConnected={isConnected}
        targetUrl={targetUrl}
        activeRound={activeRound}
        isRunning={isRunning}
      />

      <TargetConfigCard
        targetUrl={targetUrl}
        setTargetUrl={setTargetUrl}
        targetPath={targetPath}
        setTargetPath={setTargetPath}
        onLaunch={handleLaunch}
        onStop={handleStop}
        onReset={handleReset}
        isRunning={isRunning}
        discoveredSurface={discoveredSurface}
      />

      <AttackTriggerDeck
        targetUrl={targetUrl}
        onTriggerAttack={handleTriggerAttack}
        isRunning={isRunning}
        lastAttackResult={lastAttackResult}
      />

      <ArenaBattlefield
        currentAttack={currentAttack}
        currentDefense={currentDefense}
        isRunning={isRunning}
      />

      <MetricsHUD
        metrics={metrics}
        totalAttacks={totalAttacks}
        blockedAttacks={blockedAttacks}
        wafRulesCount={wafRulesCount}
      />

      <LiveEventFeed events={events} />
    </div>
  );
}
