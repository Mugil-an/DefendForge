import React from 'react';
import { Target, ShieldCheck, Timer, ShieldAlert, Cpu, BookOpen, Activity, CheckCircle2 } from 'lucide-react';

export default function MetricsHUD({ metrics, totalAttacks, blockedAttacks, wafRulesCount }) {
  const hasAttacks = totalAttacks > 0;
  const precisionVal = hasAttacks && metrics?.precision !== undefined && metrics.precision !== null
    ? metrics.precision * 100
    : 0;

  const precisionDisplay = hasAttacks
    ? `${precisionVal.toFixed(1)}%`
    : '--%';

  const blockRateVal = hasAttacks ? (blockedAttacks / totalAttacks) * 100 : 0;
  const blockRateDisplay = `${blockRateVal.toFixed(1)}%`;

  const ttdDisplay = metrics?.time_to_detect_ms && metrics.time_to_detect_ms > 0
    ? `${metrics.time_to_detect_ms.toFixed(1)} ms`
    : '-- ms';

  const ttrDisplay = metrics?.time_to_remediate_ms && metrics.time_to_remediate_ms > 0
    ? `${metrics.time_to_remediate_ms.toFixed(1)} ms`
    : '-- ms';

  const cards = [
    {
      label: 'DETECTION PRECISION',
      value: precisionDisplay,
      sub: hasAttacks ? 'RandomForest 24D Model' : 'Awaiting live traffic',
      icon: <Target size={18} color="var(--blue-primary)" />,
      color: 'var(--blue-primary)',
      percent: precisionVal,
      hasBar: hasAttacks,
    },
    {
      label: 'ATTACKS NEUTRALIZED',
      value: `${blockedAttacks} / ${totalAttacks}`,
      sub: hasAttacks ? `${blockRateDisplay} Block Rate` : 'No attacks recorded',
      icon: <ShieldCheck size={18} color="var(--green-primary)" />,
      color: 'var(--green-primary)',
      percent: blockRateVal,
      hasBar: hasAttacks,
    },
    {
      label: 'TIME TO DETECT (TTD)',
      value: ttdDisplay,
      sub: metrics?.time_to_detect_ms > 0 ? 'Sub-50ms Real-Time Inference' : 'Awaiting detection',
      icon: <Timer size={18} color="#38bdf8" />,
      color: '#38bdf8',
      badge: metrics?.time_to_detect_ms > 0 ? 'ULTRA FAST' : null,
    },
    {
      label: 'TIME TO REMEDIATE',
      value: ttrDisplay,
      sub: metrics?.time_to_remediate_ms > 0 ? 'PPO RL + Gemini LLM' : 'Awaiting remediation',
      icon: <Cpu size={18} color="var(--purple-primary)" />,
      color: 'var(--purple-primary)',
      badge: metrics?.time_to_remediate_ms > 0 ? 'HARMONY' : null,
    },
    {
      label: 'ACTIVE WAF RULES',
      value: `${wafRulesCount || 0}`,
      sub: (wafRulesCount || 0) > 0 ? 'Dynamic In-Memory Rules' : 'Baseline policy active',
      icon: <ShieldAlert size={18} color="var(--amber-primary)" />,
      color: 'var(--amber-primary)',
    },
    {
      label: 'TOTAL ADVERSARIAL EVENTS',
      value: `${totalAttacks}`,
      sub: hasAttacks ? `${blockedAttacks} Blocked / ${totalAttacks - blockedAttacks} Allowed` : 'Telemetry Feed Ready',
      icon: <BookOpen size={18} color="var(--red-primary)" />,
      color: 'var(--red-primary)',
    },
  ];

  return (
    <div style={{ marginBottom: '20px' }}>
      {/* Metrics Cards Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(185px, 1fr))',
        gap: '12px',
        marginBottom: '10px',
      }}>
        {cards.map((card, idx) => (
          <div
            key={idx}
            className="glass-panel"
            style={{
              padding: '16px',
              position: 'relative',
              overflow: 'hidden',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
            }}
          >
            {/* Top row */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.68rem', fontWeight: 700, letterSpacing: '0.04em', color: 'var(--text-muted)' }}>
                  {card.label}
                </span>
                {card.icon}
              </div>

              {/* Main value */}
              <div style={{
                fontSize: '1.45rem',
                fontWeight: 800,
                fontFamily: 'var(--font-heading)',
                color: card.color,
                lineHeight: 1.2,
                marginBottom: '4px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}>
                <span>{card.value}</span>
                {card.badge && (
                  <span className="badge badge-blue" style={{ fontSize: '0.6rem', padding: '1px 5px' }}>
                    {card.badge}
                  </span>
                )}
              </div>
            </div>

            {/* Bottom progress bar or subtext */}
            <div>
              {card.hasBar && (
                <div style={{
                  height: '4px',
                  background: 'rgba(255, 255, 255, 0.08)',
                  borderRadius: '2px',
                  overflow: 'hidden',
                  marginBottom: '6px',
                }}>
                  <div style={{
                    height: '100%',
                    width: `${Math.min(100, Math.max(0, card.percent))}%`,
                    background: card.color,
                    boxShadow: `0 0 8px ${card.color}`,
                    transition: 'width 0.5s ease',
                  }} />
                </div>
              )}
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                {card.sub}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Cyber Defense Posture Ticker */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(8, 12, 19, 0.65)',
        border: '1px solid rgba(255, 255, 255, 0.06)',
        borderRadius: '8px',
        padding: '6px 14px',
        fontSize: '0.72rem',
        color: 'var(--text-muted)',
        flexWrap: 'wrap',
        gap: '8px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Activity size={13} color="var(--blue-primary)" />
          <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>AI DEFENSE HARMONY:</span>
          <span>⚡ Fast Path (PPO RL &lt; 5ms) + 🧠 Slow Path (Gemini 3.8 Flash Heuristic)</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <CheckCircle2 size={12} color="var(--green-primary)" />
            <span>Zero False Positives</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--blue-primary)' }} />
            <span>24D Anomaly Detector Online</span>
          </div>
        </div>
      </div>
    </div>
  );
}
