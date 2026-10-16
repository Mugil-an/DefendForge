import React, { useState } from 'react';
import {
  Skull,
  Zap,
  Terminal,
  Send,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Flame,
  KeyRound,
  FileSearch,
  Globe,
  Radio,
} from 'lucide-react';

export default function AttackTriggerDeck({
  targetUrl,
  onTriggerAttack,
  isRunning,
  lastAttackResult,
}) {
  const [showCustomBuilder, setShowCustomBuilder] = useState(false);

  // Custom fuzzer state
  const [customEndpoint, setCustomEndpoint] = useState('/login');
  const [customMethod, setCustomMethod] = useState('POST');
  const [customParam, setCustomParam] = useState('username');
  const [customPayload, setCustomPayload] = useState("' OR '1'='1' --");
  const [customEvasion, setCustomEvasion] = useState('space_to_comment');
  const [customAttackType, setCustomAttackType] = useState('sql_injection');

  // Quick attack presets
  const quickAttacks = [
    {
      id: 'sql_injection',
      label: 'SQL Injection',
      icon: Flame,
      color: '#f43f5e',
      endpoint: '/login',
      method: 'POST',
      param: 'username',
      payload: "' OR 1=1--",
      mitre: 'T1190',
      badge: 'CWE-89',
    },
    {
      id: 'command_injection',
      label: 'Command Injection',
      icon: Zap,
      color: '#ef4444',
      endpoint: '/ping',
      method: 'GET',
      param: 'host',
      payload: '; cat /etc/passwd',
      mitre: 'T1059',
      badge: 'CWE-78',
    },
    {
      id: 'xss',
      label: 'Cross-Site Scripting (XSS)',
      icon: AlertTriangle,
      color: '#f59e0b',
      endpoint: '/greet',
      method: 'GET',
      param: 'name',
      payload: '<script>alert(1)</script>',
      mitre: 'T1189',
      badge: 'CWE-79',
    },
    {
      id: 'path_traversal',
      label: 'Path Traversal',
      icon: FileSearch,
      color: '#eab308',
      endpoint: '/file',
      method: 'GET',
      param: 'name',
      payload: '../../../../etc/passwd',
      mitre: 'T1083',
      badge: 'CWE-22',
    },
    {
      id: 'brute_force',
      label: 'Brute Force Login',
      icon: KeyRound,
      color: '#a855f7',
      endpoint: '/login',
      method: 'POST',
      param: 'username',
      payload: 'admin:password',
      mitre: 'T1110',
      badge: 'CWE-307',
    },
    {
      id: 'ssrf',
      label: 'SSRF Metadata Probe',
      icon: Globe,
      color: '#38bdf8',
      endpoint: '/fetch',
      method: 'GET',
      param: 'url',
      payload: 'http://169.254.169.254/latest/meta-data/',
      mitre: 'T1190',
      badge: 'CWE-918',
    },
    {
      id: 'reconnaissance',
      label: 'Recon Scanner UA',
      icon: Radio,
      color: '#06b6d4',
      endpoint: '/',
      method: 'GET',
      param: '',
      payload: 'sqlmap/1.5 probe',
      mitre: 'T1595',
      badge: 'CWE-200',
    },
  ];

  const handleQuickFire = (atk) => {
    onTriggerAttack({
      attack_type: atk.id,
      endpoint: atk.endpoint,
      method: atk.method,
      param_name: atk.param,
      payload: atk.payload,
      target_url: targetUrl,
      evasion: 'space_to_comment',
    });
  };

  const handleCustomFire = (e) => {
    e.preventDefault();
    onTriggerAttack({
      attack_type: customAttackType,
      endpoint: customEndpoint,
      method: customMethod,
      param_name: customParam,
      payload: customPayload,
      target_url: targetUrl,
      evasion: customEvasion,
    });
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '20px', borderLeft: '4px solid var(--red-primary)' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '8px',
            background: 'var(--red-surface)',
            border: '1px solid rgba(244, 63, 94, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}>
            <Skull size={18} color="var(--red-primary)" />
          </div>
          <div>
            <h3 style={{ fontSize: '0.95rem', fontWeight: 800, fontFamily: 'var(--font-heading)', color: 'var(--text-main)' }}>
              LIVE ATTACK TRIGGER CONSOLE
            </h3>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Target: <strong style={{ color: targetUrl ? 'var(--blue-primary)' : 'var(--amber-primary)' }}>{targetUrl || 'None (Enter URL in Arena Control)'}</strong> — Real HTTP requests dispatched across live network
            </span>
          </div>
        </div>

        <button
          className="btn-secondary"
          onClick={() => setShowCustomBuilder(!showCustomBuilder)}
          disabled={!targetUrl || !targetUrl.trim()}
          style={{ fontSize: '0.75rem', padding: '6px 14px', display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <Terminal size={14} />
          <span>{showCustomBuilder ? 'Hide Custom Builder' : 'Custom Exploit Fuzzer'}</span>
          {showCustomBuilder ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Quick Attack Trigger Buttons */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '10px', marginBottom: '14px' }}>
        {quickAttacks.map((atk) => {
          const IconComponent = atk.icon;
          const isDisabled = isRunning || !targetUrl || !targetUrl.trim();
          return (
            <button
              key={atk.id}
              onClick={() => handleQuickFire(atk)}
              disabled={isDisabled}
              title={!targetUrl || !targetUrl.trim() ? 'Enter Target URL above to enable attack triggers' : ''}
              style={{
                background: 'rgba(15, 23, 42, 0.75)',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '8px',
                padding: '10px 12px',
                textAlign: 'left',
                cursor: isDisabled ? 'not-allowed' : 'pointer',
                opacity: isDisabled ? 0.45 : 1,
                transition: 'all 0.2s ease',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                gap: '8px',
              }}
              onMouseEnter={(e) => {
                if (!isDisabled) {
                  e.currentTarget.style.borderColor = atk.color;
                  e.currentTarget.style.boxShadow = `0 0 12px ${atk.color}44`;
                  e.currentTarget.style.transform = 'translateY(-2px)';
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.08)';
                e.currentTarget.style.boxShadow = 'none';
                e.currentTarget.style.transform = 'translateY(0)';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <IconComponent size={15} color={atk.color} />
                  <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-main)' }}>
                    {atk.label}
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                  {atk.method} {atk.endpoint}
                </span>
                <span className="badge badge-red" style={{ fontSize: '0.62rem', padding: '1px 5px' }}>
                  {atk.mitre}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Custom Exploit Builder (Collapsible) */}
      {showCustomBuilder && (
        <form
          onSubmit={handleCustomFire}
          style={{
            background: 'rgba(10, 14, 23, 0.95)',
            border: '1px solid rgba(244, 63, 94, 0.25)',
            borderRadius: '10px',
            padding: '16px',
            marginBottom: '14px',
            animation: 'fadeIn 0.2s ease',
          }}
        >
          <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--red-primary)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Terminal size={14} />
            CUSTOM PAYLOAD INJECTION FUZZER
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '120px 2fr 1.5fr 1.5fr', gap: '10px', marginBottom: '12px' }}>
            {/* Method */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                METHOD
              </label>
              <select
                className="cyber-input"
                value={customMethod}
                onChange={(e) => setCustomMethod(e.target.value)}
                disabled={isRunning}
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>

            {/* Target Endpoint */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                ENDPOINT
              </label>
              <input
                type="text"
                className="cyber-input"
                value={customEndpoint}
                onChange={(e) => setCustomEndpoint(e.target.value)}
                placeholder="/login or /ping"
                disabled={isRunning}
              />
            </div>

            {/* Parameter Name */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                PARAMETER NAME
              </label>
              <input
                type="text"
                className="cyber-input"
                value={customParam}
                onChange={(e) => setCustomParam(e.target.value)}
                placeholder="username or host"
                disabled={isRunning}
              />
            </div>

            {/* Attack Category */}
            <div>
              <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                ATTACK CATEGORY
              </label>
              <select
                className="cyber-input"
                value={customAttackType}
                onChange={(e) => setCustomAttackType(e.target.value)}
                disabled={isRunning}
              >
                <option value="sql_injection">SQL Injection</option>
                <option value="command_injection">Command Injection</option>
                <option value="xss">Cross-Site Scripting</option>
                <option value="path_traversal">Path Traversal</option>
                <option value="brute_force">Brute Force</option>
                <option value="ssrf">SSRF</option>
                <option value="reconnaissance">Reconnaissance</option>
              </select>
            </div>
          </div>

          {/* Payload textarea */}
          <div style={{ marginBottom: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <label style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                ATTACK PAYLOAD STRING
              </label>
              <div style={{ display: 'flex', gap: '4px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.65rem', padding: '2px 6px' }}
                  onClick={() => setCustomPayload("' UNION SELECT username,password FROM users--")}
                >
                  Preset SQLi
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.65rem', padding: '2px 6px' }}
                  onClick={() => setCustomPayload("; cat /etc/passwd")}
                >
                  Preset Cmd
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.65rem', padding: '2px 6px' }}
                  onClick={() => setCustomPayload("<script>alert('XSS')</script>")}
                >
                  Preset XSS
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ fontSize: '0.65rem', padding: '2px 6px' }}
                  onClick={() => setCustomPayload("../../../../etc/passwd")}
                >
                  Preset Traversal
                </button>
              </div>
            </div>
            <textarea
              className="cyber-input"
              rows={2}
              value={customPayload}
              onChange={(e) => setCustomPayload(e.target.value)}
              placeholder="e.g. ' OR 1=1--"
              disabled={isRunning}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', resize: 'vertical' }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            {/* Evasion selection */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Evasion:</span>
              <select
                className="cyber-input"
                style={{ fontSize: '0.72rem', padding: '4px 8px' }}
                value={customEvasion}
                onChange={(e) => setCustomEvasion(e.target.value)}
                disabled={isRunning}
              >
                <option value="none">None (Raw Payload)</option>
                <option value="space_to_comment">Space to Comment (/**/)</option>
                <option value="url_encode">URL Encoded (%27)</option>
                <option value="double_url_encode">Double URL Encoded (%2527)</option>
                <option value="unicode_escape">Unicode Hex Escape</option>
              </select>
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={isRunning}
              style={{ padding: '8px 22px', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Send size={14} />
              <span>FIRE LIVE ATTACK 🚀</span>
            </button>
          </div>
        </form>
      )}

      {/* Immediate Attack Result Banner */}
      {lastAttackResult && (
        <div style={{
          background: lastAttackResult.is_blocked ? 'rgba(16, 185, 129, 0.12)' : 'rgba(244, 63, 94, 0.12)',
          border: `1px solid ${lastAttackResult.is_blocked ? 'var(--green-primary)' : 'var(--red-primary)'}`,
          borderRadius: '8px',
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{
              fontSize: '1rem',
              color: lastAttackResult.is_blocked ? 'var(--green-primary)' : 'var(--red-primary)',
            }}>
              {lastAttackResult.is_blocked ? '🛡️' : '💥'}
            </span>
            <div>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-main)' }}>
                {lastAttackResult.is_blocked
                  ? `HTTP ${lastAttackResult.response_code || 403} FORBIDDEN — Threat Neutralized & Blocked!`
                  : `HTTP ${lastAttackResult.response_code || 200} OK — Payload Received by Target App`}
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                Endpoint: {lastAttackResult.method} {lastAttackResult.endpoint} | Type: {lastAttackResult.attack_type}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <span className={`badge ${lastAttackResult.is_blocked ? 'badge-green' : 'badge-red'}`}>
              {lastAttackResult.is_blocked ? 'WAF / ML BLOCKED' : 'PROCESSED'}
            </span>
            {lastAttackResult.defense?.action && (
              <span className="badge badge-blue">
                Action: {lastAttackResult.defense.action}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
