import React, { useState, useEffect } from 'react';
import {
  Shield,
  Maximize2,
  Minimize2,
  Clock,
  Wifi,
} from 'lucide-react';

export default function Header({ isConnected, isRunning }) {
  const [time, setTime] = useState('');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [latency, setLatency] = useState(14);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTime(now.toISOString().split('T')[1].split('.')[0] + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const pingTimer = setInterval(() => {
      if (isConnected) {
        setLatency(Math.floor(12 + Math.random() * 8));
      }
    }, 4000);
    return () => clearInterval(pingTimer);
  }, [isConnected]);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => setIsFullscreen(true)).catch(() => {});
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false)).catch(() => {});
    }
  };

  return (
    <header className="glass-panel" style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 24px',
      marginBottom: '20px',
      borderLeft: '4px solid var(--blue-primary)',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Top subtle neon scan line */}
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '1px',
        background: 'linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.6), transparent)',
      }} />

      {/* Brand Title: DefendForge */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '42px',
          height: '42px',
          borderRadius: '10px',
          background: 'linear-gradient(135deg, rgba(6, 182, 212, 0.25), rgba(168, 85, 247, 0.25))',
          border: '1px solid rgba(56, 189, 248, 0.45)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 20px rgba(6, 182, 212, 0.35)',
        }}>
          <Shield size={24} color="#38bdf8" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <h1 style={{
            fontSize: '1.45rem',
            fontWeight: 800,
            fontFamily: 'var(--font-heading)',
            letterSpacing: '-0.02em',
            background: 'linear-gradient(to right, #ffffff, #94a3b8)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>
            DefendForge
          </h1>
          {isRunning && (
            <span className="badge badge-amber pulse" style={{ fontSize: '0.65rem' }}>
              ACTIVE
            </span>
          )}
        </div>
      </div>

      {/* Right Controls: Fullscreen, Ping, Clock */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Fullscreen Button */}
        <button
          onClick={toggleFullscreen}
          title={isFullscreen ? 'Exit Fullscreen' : 'Enter Fullscreen'}
          style={{
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '8px',
            padding: '6px 9px',
            cursor: 'pointer',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            transition: 'all 0.2s ease',
          }}
        >
          {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
        </button>

        {/* Telemetry Ping */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          background: 'rgba(0, 0, 0, 0.35)',
          padding: '5px 10px',
          borderRadius: '6px',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          fontSize: '0.75rem',
          fontFamily: 'var(--font-mono)',
        }}>
          <Wifi size={12} color={isConnected ? 'var(--green-primary)' : 'var(--red-primary)'} />
          <span style={{ color: isConnected ? '#86efac' : 'var(--red-primary)' }}>
            {isConnected ? `${latency}ms` : 'OFFLINE'}
          </span>
        </div>

        {/* UTC Clock */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
          background: 'rgba(0, 0, 0, 0.35)',
          padding: '5px 10px',
          borderRadius: '6px',
          border: '1px solid rgba(255, 255, 255, 0.06)',
        }}>
          <Clock size={12} color="var(--blue-primary)" />
          <span>{time}</span>
        </div>
      </div>
    </header>
  );
}
