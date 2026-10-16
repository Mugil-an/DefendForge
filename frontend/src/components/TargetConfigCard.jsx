import React, { useState } from 'react';
import { Crosshair, Play, Square, RotateCcw, Globe, FolderCode } from 'lucide-react';

export default function TargetConfigCard({
  targetUrl,
  setTargetUrl,
  targetPath,
  setTargetPath,
  onLaunch,
  onStop,
  onReset,
  isRunning,
}) {
  const [useLLM] = useState(true);

  const isConfigValid = Boolean(targetUrl && targetUrl.trim() && targetPath && targetPath.trim());

  const handleButtonClick = () => {
    if (isRunning) {
      if (onStop) onStop();
    } else {
      if (!isConfigValid) return;
      onLaunch({
        targetUrl: targetUrl.trim(),
        targetPath: targetPath.trim(),
        useLLM,
      });
    }
  };

  const handleResetClick = () => {
    if (onReset) onReset();
  };

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '20px' }}>
      {/* Header: ONLY TARGET APPLICATION CONTROL */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
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
          <Crosshair size={18} color="var(--red-primary)" />
        </div>
        <h2 style={{ fontSize: '1.05rem', fontWeight: 800, fontFamily: 'var(--font-heading)', color: 'var(--text-main)' }}>
          TARGET APPLICATION CONTROL
        </h2>
      </div>

      {/* Main Inputs Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(240px, 1fr) minmax(240px, 1fr) auto',
        gap: '14px',
        alignItems: 'end',
      }}>
        {/* 1. Target URL */}
        <div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px' }}>
            <Globe size={13} color="var(--blue-primary)" />
            TARGET CONTAINER URL / ENDPOINT *
          </label>
          <input
            type="text"
            className="cyber-input"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="e.g. http://127.0.0.1:8080 or http://target-app:5000"
            disabled={isRunning}
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
          />
        </div>

        {/* 2. Target Path */}
        <div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '6px' }}>
            <FolderCode size={13} color="var(--green-primary)" />
            TARGET APP SOURCE CODE PATH *
          </label>
          <input
            type="text"
            className="cyber-input"
            value={targetPath}
            onChange={(e) => setTargetPath(e.target.value)}
            placeholder="e.g. ./target_app or /var/www/target_app"
            disabled={isRunning}
            style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
          />
        </div>

        {/* 3. Action Buttons (START / STOP + RESET) */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            className="btn-primary"
            onClick={handleButtonClick}
            disabled={!isRunning && !isConfigValid}
            title={!isConfigValid && !isRunning ? 'Please enter both Target URL and Source Code Path' : ''}
            style={{
              height: '42px',
              padding: '0 24px',
              whiteSpace: 'nowrap',
              fontWeight: 800,
              fontSize: '0.88rem',
              letterSpacing: '0.04em',
              opacity: !isRunning && !isConfigValid ? 0.45 : 1,
              cursor: !isRunning && !isConfigValid ? 'not-allowed' : 'pointer',
              background: isRunning
                ? 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)'
                : 'linear-gradient(135deg, #06b6d4 0%, #0284c7 100%)',
              boxShadow: isRunning
                ? '0 0 24px rgba(239, 68, 68, 0.6)'
                : isConfigValid
                  ? '0 0 24px rgba(6, 182, 212, 0.5)'
                  : 'none',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            {isRunning ? (
              <>
                <div style={{
                  width: '16px',
                  height: '16px',
                  borderRadius: '50%',
                  border: '2px solid white',
                  borderTopColor: 'transparent',
                  animation: 'spin 0.8s linear infinite',
                }} />
                <Square size={14} fill="white" />
                <span>STOP ⏹️</span>
              </>
            ) : (
              <>
                <Play size={16} fill="white" />
                <span>START ⚔️</span>
              </>
            )}
          </button>

          <button
            className="btn-secondary"
            onClick={handleResetClick}
            disabled={isRunning}
            title="Reset Telemetry & Memory"
            style={{ height: '42px', padding: '0 12px' }}
          >
            <RotateCcw size={16} />
          </button>
        </div>
      </div>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
