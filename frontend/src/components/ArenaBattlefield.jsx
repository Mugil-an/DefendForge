import React, { useState } from 'react';
import {
  Skull,
  Shield,
  Zap,
  Sparkles,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Cpu,
  ArrowRight,
  Activity,
  Layers,
} from 'lucide-react';
import ThreeArenaScene from './ThreeArenaScene';

export default function ArenaBattlefield({ currentAttack, currentDefense, isRunning }) {
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [copiedReasoning, setCopiedReasoning] = useState(false);

  const anomalyScore = currentDefense?.anomaly_score ?? currentDefense?.confidence ?? 0;
  const isBlocked = currentDefense?.action && [
    'blocked',
    'block_ip',
    'block_source_ip',
    'rate_limit',
    'update_security_rule',
    'apply_known_patch',
  ].includes(currentDefense.action);

  const getScoreColor = (score) => {
    if (score >= 0.75) return 'var(--red-primary)';
    if (score >= 0.5) return 'var(--amber-primary)';
    return 'var(--green-primary)';
  };

  const handleCopy = (text, type) => {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (type === 'payload') {
        setCopiedPayload(true);
        setTimeout(() => setCopiedPayload(false), 2000);
      } else {
        setCopiedReasoning(true);
        setTimeout(() => setCopiedReasoning(false), 2000);
      }
    });
  };

  // Generate clear descriptive sentence of what Red Agent is doing
  const getRedAgentDoing = () => {
    if (!currentAttack) {
      return isRunning
        ? 'Red Agent is scanning surface and preparing next exploit iteration...'
        : 'Red Agent is idle in standby mode. Ready to launch attacks against the target application.';
    }
    const attackName = currentAttack.attack_type?.replace(/_/g, ' ') || 'exploit';
    const endpoint = `${currentAttack.method || 'GET'} ${currentAttack.endpoint || '/'}`;
    const evasion = currentAttack.evasion && currentAttack.evasion !== 'none'
      ? ` using ${currentAttack.evasion.replace(/_/g, ' ')} evasion`
      : '';
    return `Injecting ${attackName} payload into ${endpoint}${evasion}.`;
  };

  // Generate clear descriptive sentence of what Blue Agent is doing and its decision
  const getBlueAgentDoing = () => {
    if (!currentDefense && !currentAttack) {
      return 'Blue Agent is actively monitoring telemetry traffic with 24-dimensional anomaly detection models.';
    }
    const action = (currentDefense?.action || 'observing').toUpperCase();
    const engine = currentDefense?.decision_path === 'fast'
      ? 'PPO RL Policy'
      : currentDefense?.decision_path === 'slow'
        ? 'Gemini 3.8 Flash'
        : 'Neural Net';
    const scoreStr = anomalyScore ? anomalyScore.toFixed(2) : '0.00';

    if (isBlocked) {
      return `Detected threat with anomaly score ${scoreStr}. Escalated to ${engine}. DECISION: ${action} to neutralize attack.`;
    }
    return `Analyzed traffic (anomaly score ${scoreStr}). Evaluated by ${engine}. DECISION: ALLOWED without disruption.`;
  };

  return (
    <div style={{ marginBottom: '20px' }}>
      {/* 3D WebGL Multi-Agent Battlefield */}
      <ThreeArenaScene
        currentAttack={currentAttack}
        currentDefense={currentDefense}
        isRunning={isRunning}
      />

      {/* Live Agent Action & Decision Console */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(320px, 1fr) 130px minmax(320px, 1fr)',
        gap: '16px',
        alignItems: 'stretch',
      }}>
        {/* 🔴 RED AGENT CARD: WHAT IS IT DOING? */}
        <div className={`glass-panel ${isRunning ? 'glow-red' : ''}`} style={{
          padding: '20px',
          borderLeft: '4px solid var(--red-primary)',
          background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.06), rgba(14, 19, 29, 0.9))',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}>
          <div>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
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
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 800, fontFamily: 'var(--font-heading)', color: 'var(--red-primary)' }}>
                    RED AGENT (ATTACKER)
                  </h3>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
                    ADVERSARIAL EXPLOIT ENGINE
                  </span>
                </div>
              </div>
              <span className={`badge ${currentAttack ? 'badge-red pulse' : isRunning ? 'badge-amber pulse' : 'badge-amber'}`}>
                {currentAttack ? 'ATTACKING' : isRunning ? 'SCANNING' : 'STANDBY'}
              </span>
            </div>

            {/* WHAT IS THE RED AGENT DOING? (Clear Narrative Status) */}
            <div style={{
              background: 'rgba(244, 63, 94, 0.08)',
              border: '1px solid rgba(244, 63, 94, 0.25)',
              borderRadius: '8px',
              padding: '10px 12px',
              marginBottom: '14px',
            }}>
              <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--red-primary)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Activity size={12} />
                <span>CURRENT ACTION</span>
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-main)', lineHeight: 1.4, fontWeight: 500 }}>
                {getRedAgentDoing()}
              </div>
            </div>

            {/* Attack Specs Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '3px' }}>MITRE ATT&CK</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span className="badge badge-red" style={{ fontSize: '0.72rem' }}>
                    {currentAttack?.mitre_technique || 'T1190'}
                  </span>
                  <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-main)' }}>
                    {currentAttack?.attack_type || 'Standby'}
                  </span>
                </div>
              </div>

              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '3px' }}>EVASION METHOD</div>
                <span className="badge badge-purple" style={{ fontSize: '0.72rem' }}>
                  {currentAttack?.evasion || 'none'}
                </span>
              </div>
            </div>
          </div>

          {/* Actual Delivered Payload String */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                <Terminal size={12} />
                <span>DELIVERED PAYLOAD STRING</span>
              </div>
              {currentAttack?.payload && (
                <button
                  onClick={() => handleCopy(currentAttack.payload, 'payload')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedPayload ? 'var(--green-primary)' : 'var(--text-dim)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '0.68rem',
                  }}
                >
                  {copiedPayload ? <Check size={11} /> : <Copy size={11} />}
                  <span>{copiedPayload ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>
            <div style={{
              background: 'rgba(0, 0, 0, 0.7)',
              padding: '10px 12px',
              borderRadius: '6px',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.76rem',
              color: '#fca5a5',
              wordBreak: 'break-all',
              maxHeight: '65px',
              overflowY: 'auto',
            }}>
              {currentAttack?.payload || (isRunning ? 'Preparing attack payload...' : 'Awaiting attack launch.')}
            </div>
          </div>
        </div>

        {/* ⚡ THE TARGET GATEWAY (MIDDLE TUNNEL) */}
        <div className="glass-panel" style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '14px 10px',
          textAlign: 'center',
          background: 'rgba(10, 15, 24, 0.9)',
        }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '50%',
            background: isBlocked ? 'var(--green-surface)' : 'rgba(56, 189, 248, 0.1)',
            border: `1px solid ${isBlocked ? 'var(--green-primary)' : 'var(--blue-primary)'}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            marginBottom: '8px',
            boxShadow: isBlocked ? '0 0 18px var(--green-glow)' : '0 0 18px var(--blue-glow)',
          }}>
            {isBlocked ? (
              <CheckCircle2 size={22} color="var(--green-primary)" />
            ) : (
              <Zap size={22} color="var(--blue-primary)" />
            )}
          </div>

          <div style={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: '4px' }}>
            GATEWAY
          </div>

          <span className={`badge ${isBlocked ? 'badge-green' : 'badge-blue'}`} style={{ fontSize: '0.68rem', marginBottom: '8px' }}>
            {isBlocked ? 'BLOCKED' : 'FORWARDED'}
          </span>

          <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
            Reverse Proxy
          </div>
        </div>

        {/* 🔵 BLUE AGENT CARD: WHAT DID IT DO & DECISION? */}
        <div className={`glass-panel ${isRunning ? 'glow-blue' : ''}`} style={{
          padding: '20px',
          borderLeft: '4px solid var(--blue-primary)',
          background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.06), rgba(14, 19, 29, 0.9))',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}>
          <div>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: 'var(--blue-surface)',
                  border: '1px solid rgba(6, 182, 212, 0.4)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}>
                  <Shield size={18} color="var(--blue-primary)" />
                </div>
                <div>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 800, fontFamily: 'var(--font-heading)', color: 'var(--blue-primary)' }}>
                    BLUE AGENT (DEFENDER)
                  </h3>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-dim)', letterSpacing: '0.04em' }}>
                    AI DEFENSE & HARMONY
                  </span>
                </div>
              </div>
              <span className={`badge ${currentAttack ? (isBlocked ? 'badge-green' : 'badge-blue') : 'badge-cyan'}`}>
                {currentAttack ? (isBlocked ? 'THREAT NEUTRALIZED' : 'ANALYZED') : 'MONITORING'}
              </span>
            </div>

            {/* WHAT IS THE BLUE AGENT DOING & DECISION? (Clear Narrative Status) */}
            <div style={{
              background: isBlocked ? 'rgba(16, 185, 129, 0.08)' : 'rgba(6, 182, 212, 0.08)',
              border: `1px solid ${isBlocked ? 'rgba(16, 185, 129, 0.25)' : 'rgba(6, 182, 212, 0.25)'}`,
              borderRadius: '8px',
              padding: '10px 12px',
              marginBottom: '14px',
            }}>
              <div style={{ fontSize: '0.68rem', fontWeight: 700, color: isBlocked ? 'var(--green-primary)' : 'var(--blue-primary)', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Sparkles size={12} />
                <span>DEFENSE EVALUATION & DECISION</span>
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-main)', lineHeight: 1.4, fontWeight: 500 }}>
                {getBlueAgentDoing()}
              </div>
            </div>

            {/* Decision Specs Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px' }}>
              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '3px' }}>DECISION ENGINE</div>
                <span className="badge badge-blue" style={{ fontSize: '0.72rem' }}>
                  {currentDefense?.decision_path === 'fast'
                    ? '⚡ PPO RL Policy'
                    : currentDefense?.decision_path === 'slow'
                      ? '🧠 Gemini 3.8 Flash'
                      : 'Standby / Ready'}
                </span>
              </div>

              <div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '3px' }}>FINAL ACTION</div>
                <span className={`badge ${isBlocked ? 'badge-green' : 'badge-amber'}`} style={{ fontSize: '0.72rem' }}>
                  {currentDefense?.action || 'observing'}
                </span>
              </div>
            </div>
          </div>

          {/* Defense Reasoning & Hardening Rationale */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                <Sparkles size={12} color="var(--blue-primary)" />
                <span>REASONING & HARDENING APPLIED</span>
              </div>
              {currentDefense?.reasoning && (
                <button
                  onClick={() => handleCopy(currentDefense.reasoning, 'reasoning')}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: copiedReasoning ? 'var(--green-primary)' : 'var(--text-dim)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '0.68rem',
                  }}
                >
                  {copiedReasoning ? <Check size={11} /> : <Copy size={11} />}
                  <span>{copiedReasoning ? 'Copied' : 'Copy'}</span>
                </button>
              )}
            </div>
            <div style={{
              background: 'rgba(0, 0, 0, 0.7)',
              padding: '10px 12px',
              borderRadius: '6px',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.76rem',
              color: '#a7f3d0',
              wordBreak: 'break-word',
              maxHeight: '65px',
              overflowY: 'auto',
            }}>
              {currentDefense?.reasoning || (currentAttack ? 'Analyzing telemetry with models.' : 'Defense models loaded and ready.')}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
