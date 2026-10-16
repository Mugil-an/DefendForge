import React, { useState, useMemo } from 'react';
import {
  Activity,
  ShieldAlert,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Terminal,
  Search,
  Copy,
  Check,
  Download,
  Trash2,
  Filter,
} from 'lucide-react';

export default function LiveEventFeed({ events }) {
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      // 1. Tab category filter
      if (filter === 'attacks' && !e.is_attack) return false;
      if (filter === 'blocked' && !['blocked', 'block_ip', 'block_source_ip', 'rate_limit', 'update_security_rule', 'apply_known_patch'].includes(e.action)) return false;
      if (filter === 'benign' && e.is_attack) return false;

      // 2. Search keyword filter
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchEndpoint = (e.endpoint || e.path || '').toLowerCase().includes(term);
        const matchType = (e.attack_type || '').toLowerCase().includes(term);
        const matchMethod = (e.method || '').toLowerCase().includes(term);
        const matchPayload = (e.payload || e.rationale || '').toLowerCase().includes(term);
        const matchSource = (e.source_ip || e.source || '').toLowerCase().includes(term);
        return matchEndpoint || matchType || matchMethod || matchPayload || matchSource;
      }

      return true;
    });
  }, [events, filter, searchTerm]);

  const handleCopyPayload = (evt, e) => {
    e.stopPropagation();
    const textToCopy = evt.payload || evt.body || evt.rationale || `${evt.method} ${evt.endpoint}`;
    navigator.clipboard.writeText(textToCopy).then(() => {
      setCopiedId(evt.event_id || evt.timestamp);
      setTimeout(() => setCopiedId(null), 2000);
    });
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `defendforge_telemetry_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="glass-panel" style={{ padding: '20px' }}>
      {/* Header & Controls Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '16px',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
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
            <Activity size={18} color="var(--blue-primary)" />
          </div>
          <div>
            <h2 style={{ fontSize: '1.05rem', fontWeight: 800, fontFamily: 'var(--font-heading)', color: 'var(--text-main)' }}>
              LIVE ATTACK & DEFENSE TELEMETRY FEED
            </h2>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>
              Showing {filteredEvents.length} of {events.length} captured events
            </span>
          </div>
        </div>

        {/* Right action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {events.length > 0 && (
            <button
              className="btn-secondary"
              onClick={handleExportJson}
              title="Export raw telemetry as JSON"
              style={{ fontSize: '0.75rem', padding: '5px 10px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Download size={13} />
              <span>Export JSON</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '14px',
        gap: '10px',
        flexWrap: 'wrap',
      }}>
        {/* Category Tabs */}
        <div style={{ display: 'flex', gap: '6px' }}>
          {[
            { id: 'all', label: 'All Telemetry' },
            { id: 'attacks', label: 'Attacks Detected' },
            { id: 'blocked', label: 'Blocked Only' },
            { id: 'benign', label: 'Benign Traffic' },
          ].map((tab) => (
            <button
              key={tab.id}
              className={`btn-secondary ${filter === tab.id ? 'active' : ''}`}
              style={{
                fontSize: '0.75rem',
                padding: '5px 12px',
                background: filter === tab.id ? 'rgba(6, 182, 212, 0.2)' : undefined,
                borderColor: filter === tab.id ? 'var(--blue-primary)' : undefined,
                color: filter === tab.id ? '#ffffff' : undefined,
                fontWeight: filter === tab.id ? 700 : 500,
              }}
              onClick={() => setFilter(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search input */}
        <div style={{ position: 'relative', minWidth: '220px', flex: '1', maxWidth: '320px' }}>
          <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          <input
            type="text"
            className="cyber-input"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search endpoint, type, IP..."
            style={{ paddingLeft: '32px', fontSize: '0.78rem', height: '32px' }}
          />
        </div>
      </div>

      {/* Events List */}
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        maxHeight: '400px',
        overflowY: 'auto',
        paddingRight: '4px',
      }}>
        {filteredEvents.length === 0 ? (
          <div style={{
            textAlign: 'center',
            padding: '40px 20px',
            color: 'var(--text-dim)',
            fontSize: '0.85rem',
            background: 'rgba(0,0,0,0.2)',
            borderRadius: '8px',
            border: '1px dashed rgba(255, 255, 255, 0.08)',
          }}>
            No events match the selected criteria. Launch an arena campaign or fire a test attack to generate live traffic!
          </div>
        ) : (
          filteredEvents.map((evt, idx) => {
            const isAttack = evt.is_attack || evt.attack_type;
            const isBlocked = ['blocked', 'block_ip', 'block_source_ip', 'rate_limit', 'update_security_rule'].includes(evt.action);
            const evtKey = evt.event_id || evt.request_id || idx;
            const isExpanded = expandedId === evtKey;
            const isCopied = copiedId === (evt.event_id || evt.timestamp);

            return (
              <div
                key={evtKey}
                style={{
                  background: isAttack
                    ? 'linear-gradient(90deg, rgba(244, 63, 94, 0.06), rgba(15, 23, 42, 0.6))'
                    : 'rgba(255, 255, 255, 0.02)',
                  border: `1px solid ${isAttack ? 'rgba(244, 63, 94, 0.25)' : 'var(--border-subtle)'}`,
                  borderRadius: '8px',
                  padding: '10px 14px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
                onClick={() => setExpandedId(isExpanded ? null : evtKey)}
              >
                {/* Summary Row */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0, flexWrap: 'wrap' }}>
                    {isExpanded ? <ChevronDown size={14} color="var(--text-dim)" /> : <ChevronRight size={14} color="var(--text-dim)" />}

                    {/* Timestamp */}
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.72rem',
                      color: 'var(--text-dim)',
                      minWidth: '55px',
                    }}>
                      {evt.timestamp
                        ? new Date(typeof evt.timestamp === 'number' ? evt.timestamp * 1000 : evt.timestamp).toLocaleTimeString()
                        : 'NOW'}
                    </span>

                    {/* Method Badge */}
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '4px',
                      background: evt.method === 'POST'
                        ? 'rgba(56, 189, 248, 0.15)'
                        : evt.method === 'DELETE'
                          ? 'rgba(239, 68, 68, 0.15)'
                          : 'rgba(148, 163, 184, 0.15)',
                      color: evt.method === 'POST'
                        ? 'var(--blue-primary)'
                        : evt.method === 'DELETE'
                          ? 'var(--red-primary)'
                          : '#cbd5e1',
                    }}>
                      {evt.method || 'GET'}
                    </span>

                    {/* Endpoint */}
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.8rem',
                      color: 'var(--text-main)',
                      fontWeight: 600,
                    }}>
                      {evt.endpoint || evt.path || '/'}
                    </span>

                    {/* Attack / Benign Badge */}
                    {isAttack ? (
                      <span className="badge badge-red" style={{ fontSize: '0.7rem' }}>
                        {evt.attack_type || 'Malicious Exploit'}
                      </span>
                    ) : (
                      <span className="badge badge-green" style={{ fontSize: '0.7rem' }}>
                        Benign Traffic
                      </span>
                    )}
                  </div>

                  {/* Right Status Tags */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {/* Copy Payload Button */}
                    {isAttack && (
                      <button
                        onClick={(e) => handleCopyPayload(evt, e)}
                        title="Copy attack payload string"
                        style={{
                          background: 'rgba(255, 255, 255, 0.05)',
                          border: '1px solid rgba(255, 255, 255, 0.1)',
                          borderRadius: '4px',
                          padding: '3px 6px',
                          color: isCopied ? 'var(--green-primary)' : 'var(--text-dim)',
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          fontSize: '0.68rem',
                        }}
                      >
                        {isCopied ? <Check size={11} /> : <Copy size={11} />}
                        <span>{isCopied ? 'Copied' : 'Copy'}</span>
                      </button>
                    )}

                    {isBlocked ? (
                      <span className="badge badge-green" style={{ fontSize: '0.7rem' }}>
                        🛡️ BLOCKED
                      </span>
                    ) : (
                      <span className="badge badge-amber" style={{ fontSize: '0.7rem' }}>
                        ALLOWED
                      </span>
                    )}

                    {evt.severity && isAttack && (
                      <span className={`badge ${evt.severity === 'critical' ? 'badge-red' : 'badge-amber'}`} style={{ fontSize: '0.65rem' }}>
                        {evt.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div style={{
                    marginTop: '10px',
                    paddingTop: '10px',
                    borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                    fontSize: '0.78rem',
                  }}>
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
                      gap: '8px',
                      marginBottom: '8px',
                    }}>
                      <div><strong style={{ color: 'var(--text-dim)' }}>Source IP:</strong> {evt.source_ip || evt.source || '127.0.0.1'}</div>
                      <div><strong style={{ color: 'var(--text-dim)' }}>Defense Action:</strong> {evt.action || 'allowed'}</div>
                      <div><strong style={{ color: 'var(--text-dim)' }}>Anomaly Score:</strong> {evt.confidence || evt.anomaly_score || '0.85'}</div>
                      <div><strong style={{ color: 'var(--text-dim)' }}>Status Code:</strong> {evt.response_code || 200}</div>
                      {evt.mitre_technique && (
                        <div><strong style={{ color: 'var(--text-dim)' }}>MITRE ATT&CK:</strong> {evt.mitre_technique}</div>
                      )}
                    </div>

                    {/* Payload Viewer */}
                    {(evt.payload || evt.body) && (
                      <div style={{ marginBottom: '8px' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginBottom: '4px' }}>
                          PAYLOAD INSPECTOR:
                        </div>
                        <div style={{
                          background: 'rgba(0, 0, 0, 0.65)',
                          padding: '8px 10px',
                          borderRadius: '6px',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          color: '#fda4af',
                          wordBreak: 'break-all',
                        }}>
                          {evt.payload || evt.body}
                        </div>
                      </div>
                    )}

                    {evt.rationale && (
                      <div style={{
                        background: 'rgba(0, 0, 0, 0.45)',
                        padding: '8px 10px',
                        borderRadius: '6px',
                        color: 'var(--text-muted)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.74rem',
                      }}>
                        <strong style={{ color: 'var(--blue-primary)' }}>Defense Analysis & Hardening: </strong>
                        {evt.rationale}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
