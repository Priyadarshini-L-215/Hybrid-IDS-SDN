import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Power, PauseCircle, Trash2, 
  Terminal, Shield, Scan, Zap, AlertTriangle, ChevronDown, Loader,
  Target, Play, X, Copy, CheckCheck, Percent, Filter,
  ArrowUpDown, ArrowUp, ArrowDown, ChevronRight, Clock, Globe,
  Eye, EyeOff, Wifi, Server, Radio
} from 'lucide-react';
import { 
  ComposedChart, Area, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, ReferenceLine, Cell
} from 'recharts';
import './App.css';

// ─────────────────────────────────────────────────────────────────
//  Severity Helpers
// ─────────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  1: { label: 'Critical', color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.3)' },
  2: { label: 'High',     color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.3)' },
  3: { label: 'Medium',   color: '#eab308', bg: 'rgba(234,179,8,0.12)',  border: 'rgba(234,179,8,0.3)' },
  4: { label: 'Low',      color: '#64748b', bg: 'rgba(100,116,139,0.12)', border: 'rgba(100,116,139,0.3)' },
  0: { label: '—',        color: '#475569', bg: 'rgba(71,85,105,0.08)',  border: 'rgba(71,85,105,0.2)' },
};

function getSeverity(level) {
  return SEVERITY_CONFIG[level] || SEVERITY_CONFIG[0];
}

function formatTimestamp(ts) {
  if (!ts || ts === 'Unknown') return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts.split('T')[1]?.substring(0, 8) || ts;
  }
}

function SortDirectionIcon({ field, sortField, sortDir }) {
  if (sortField !== field) return <ArrowUpDown size={11} style={{ opacity: 0.3 }} />;
  return sortDir === 'desc' ? <ArrowDown size={11} /> : <ArrowUp size={11} />;
}

function ThreatChartTooltip({ active, payload, label }) {
  if (!(active && payload && payload.length)) {
    return null;
  }

  const d = payload[0].payload;
  const isAttack = d.attackConfidence > 0;
  const sev = getSeverity(d.severityRaw);

  return (
    <div className={`glass-panel tooltip-panel ${isAttack ? 'attack' : 'normal'}`}>
      <div className="tooltip-header">
        <span className="tooltip-time">{label}</span>
        {isAttack && (
          <span className="tooltip-sev-badge" style={{ background: sev.bg, color: sev.color, borderColor: sev.border }}>
            {sev.label}
          </span>
        )}
      </div>
      {isAttack && (
        <div className="tooltip-body">
          <p className="threat-sig"><AlertTriangle size={14} className="inline mr-1" /> {d.signature}</p>
          <div className="tooltip-metric">
            <span className="ml-label">ML CONFIDENCE:</span>
            <span className="ml-value">{d.attackConfidence}%</span>
          </div>
          <p className="detail-meta">SRC: {d.ip}</p>
        </div>
      )}
      {!isAttack && (
        <div className="tooltip-body">
          <p className="threat-sig safe"><ShieldCheck size={14} className="inline mr-1" /> VERIFIED FLOW</p>
          <div className="tooltip-metric">
            <span className="ml-label">STABILITY:</span>
            <span className="ml-value">{d.normalConfidence}%</span>
          </div>
          <p className="detail-meta">SRC: {d.ip}</p>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
//  Nmap Attack Lab Component
// ─────────────────────────────────────────────────────────────────
function AttackLab({ alerts = [] }) {
  const [profiles, setProfiles]       = useState([]);
  const [nmapCheck, setNmapCheck]     = useState(null); // {available, version, install_url}
  const [target, setTarget]           = useState("127.0.0.1");
  const [profile, setProfile]         = useState("quick");
  const [extraFlags, setExtraFlags]   = useState("");
  const [scanning, setScanning]       = useState(false);
  const [result, setResult]           = useState(null);
  const [copied, setCopied]           = useState(false);
  const outputRef                     = useRef(null);

  // Load profiles + nmap availability check
  useEffect(() => {
    fetch('/api/nmap/profiles')
      .then(r => r.json())
      .then(d => setProfiles(d.profiles || []))
      .catch(() => {});
    fetch('/api/nmap/check')
      .then(r => r.json())
      .then(d => setNmapCheck(d))
      .catch(() => setNmapCheck({ available: false, version: '', install_url: 'https://nmap.org/download.html' }));
  }, []);

  // Auto-scroll output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [result]);

  const selectedProfile = profiles.find(p => p.id === profile);
  const dangerColor = {
    low:    '#00f9ff',
    medium: '#f39c12',
    high:   '#ff006e',
    custom: '#a855f7',
  }[selectedProfile?.danger || 'low'];

  const runScan = async () => {
    if (!target.trim()) return;
    setScanning(true);
    setResult(null);

    try {
      const res = await fetch('/api/nmap/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, profile, extra_flags: extraFlags }),
      });
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setResult({ success: false, error: String(e), raw_output: "" });
    } finally {
      setScanning(false);
    }
  };

  const copyOutput = () => {
    if (result?.raw_output) {
      navigator.clipboard.writeText(result.raw_output).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  // Recent alerts for the IDS activity feed (last 10, newest first)
  const recentAlerts = useMemo(() => {
    return [...alerts].reverse().slice(0, 10);
  }, [alerts]);

  return (
    <div className="attack-lab glass-panel">
      {/* Header */}
      <div className="section-title lab-header">
        <div style={{display:'flex', alignItems:'center', gap:'0.75rem'}}>
          <Target size={16} style={{color: '#ff006e'}} />
          <h3>Attack Lab <span className="lab-badge">Nmap Scanner</span></h3>
        </div>
        {result && (
          <span className={`scan-status ${result.success ? 'ok' : 'fail'}`}>
            {result.success ? <><ShieldCheck size={12}/> Scan Complete ({result.duration_sec}s)</> 
                            : <><AlertTriangle size={12}/> Scan Failed</>}
          </span>
        )}
      </div>

      {/* Nmap install warning */}
      {nmapCheck && !nmapCheck.available && (
        <div className="nmap-warn">
          <AlertTriangle size={15} style={{color:'#f39c12', flexShrink:0}}/>
          <span>
            <strong>nmap not found</strong> — Install it to run scans.&nbsp;
            <a href={nmapCheck.install_url} target="_blank" rel="noreferrer" className="warn-link">
              Download from nmap.org ↗
            </a>
            &nbsp;then restart the backend.
          </span>
        </div>
      )}
      {nmapCheck?.available && (
        <div className="nmap-ok">
          <ShieldCheck size={13} style={{color:'#00f9ff'}}/>
          <span>{nmapCheck.version}</span>
        </div>
      )}

      {/* Config Row */}
      <div className="lab-config">
        {/* Target */}
        <div className="lab-field">
          <label className="lab-label"><Target size={11}/> Target</label>
          <input
            id="nmap-target"
            className="lab-input"
            type="text"
            placeholder="IP, hostname, or CIDR (e.g. 192.168.1.0/24)"
            value={target}
            onChange={e => setTarget(e.target.value)}
            disabled={scanning}
          />
        </div>

        {/* Profile selector */}
        <div className="lab-field lab-field-sm">
          <label className="lab-label"><Zap size={11}/> Scan Profile</label>
          <div className="lab-select-wrap" style={{borderColor: dangerColor}}>
            <select
              id="nmap-profile"
              className="lab-select"
              value={profile}
              onChange={e => setProfile(e.target.value)}
              disabled={scanning}
            >
              {profiles.map(p => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
            <ChevronDown size={14} className="select-arrow" />
          </div>
          {selectedProfile && (
            <span className="danger-badge" style={{background: dangerColor + '22', color: dangerColor, borderColor: dangerColor}}>
              {selectedProfile.danger.toUpperCase()} RISK
            </span>
          )}
        </div>

        {/* Custom flags (only shown for custom profile) */}
        {profile === 'custom' && (
          <div className="lab-field">
            <label className="lab-label"><Terminal size={11}/> Custom Nmap Flags</label>
            <input
              id="nmap-custom-flags"
              className="lab-input"
              type="text"
              placeholder="-sV -T4 -p80,443,8080"
              value={extraFlags}
              onChange={e => setExtraFlags(e.target.value)}
              disabled={scanning}
            />
          </div>
        )}

        {/* Action buttons */}
        <div className="lab-actions">
          <button
            id="nmap-run-btn"
            className={`lab-btn run-btn ${scanning ? 'loading' : ''}`}
            onClick={runScan}
            disabled={scanning || !target.trim()}
          >
            {scanning
              ? <><Loader size={16} className="spin"/> Scanning...</>
              : <><Play size={16}/> Run Scan</>}
          </button>
        </div>
      </div>

      {/* Flags preview */}
      {selectedProfile && (
        <div className="flags-preview">
          <span className="flags-label">CMD ›</span>
          <code>nmap {[...selectedProfile.flags, ...(profile === 'custom' ? extraFlags.split(' ').filter(Boolean) : [])].join(' ')} {target}</code>
        </div>
      )}

      {/* Output Area */}
      {(result || scanning) && (
        <div className="lab-output-wrap">
          {/* Tab bar */}
          <div className="output-tabs">
            <button className="output-tab active">
              <Terminal size={12}/> Scan Output
            </button>
            <button className="copy-btn" onClick={copyOutput} title="Copy to clipboard">
              {copied ? <CheckCheck size={13} style={{color:'#00f9ff'}}/> : <Copy size={13}/>}
            </button>
          </div>

          {/* Output content */}
          <div className="lab-output" ref={outputRef}>
            {scanning 
              ? <div className="scan-progress"><Loader size={18} className="spin"/><span>Running nmap…</span></div>
              : result?.raw_output
                ? <pre className="nmap-pre">{result.raw_output}</pre>
                : result?.error
                  ? <p className="output-err"><X size={14}/> {result.error}</p>
                  : null
            }
          </div>
        </div>
      )}

      {/* ───── Live IDS Activity Feed ───── */}
      <div className="lab-ids-feed glass-panel">
        <div className="section-title ids-feed-header">
          <div style={{display:'flex', alignItems:'center', gap:'0.5rem'}}>
            <Radio size={13} className={alerts.length > 0 ? 'pulse-icon' : ''} style={{color: alerts.length > 0 ? '#38bdf8' : 'rgba(255,255,255,0.3)'}} />
            <h3>Live IDS Activity</h3>
            <span className="alert-count-badge">{alerts.length}</span>
          </div>
          <span className="feed-hint">Network events detected by Suricata + ML Engine</span>
        </div>
        <div className="ids-feed-scroll">
          {recentAlerts.length === 0 ? (
            <div className="feed-empty">
              <Shield size={20} style={{opacity: 0.15}} />
              <span>No network events yet — Run a scan and check if Suricata is capturing traffic</span>
            </div>
          ) : (
            recentAlerts.map((alert, idx) => {
              const isAttack = alert.prediction === 'Attack';
              const sev = getSeverity(alert.severity);
              return (
                <div key={idx} className={`feed-item ${isAttack ? 'feed-attack' : 'feed-normal'}`}>
                  <div className="feed-time">
                    <Clock size={10} style={{opacity:0.4}} />
                    {formatTimestamp(alert.timestamp)}
                  </div>
                  <div className="feed-source mono">{alert.src_ip} → {alert.dest_ip}:{alert.dest_port}</div>
                  <div className="feed-sig">{alert.alert_sig}</div>
                  <span className={`pred-badge-sm ${isAttack ? 'pred-attack' : 'pred-normal'}`}>
                    {isAttack ? 'ATTACK' : 'NORMAL'}
                  </span>
                  <span className="conf-text-sm">{alert.confidence}%</span>
                  {alert.severity > 0 && (
                    <span className="sev-badge-sm" style={{color: sev.color, background: sev.bg, borderColor: sev.border}}>{sev.label}</span>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────
//  Very lightweight markdown renderer (no dependency)
// ─────────────────────────────────────────────────────────────────
function MarkdownLite({ src = "" }) {
  const html = useMemo(() => {
    let text = src
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    // Headers
    text = text.replace(/^### (.+)$/gm, '<h4 class="md-h4">$1</h4>');
    text = text.replace(/^## (.+)$/gm,  '<h3 class="md-h3">$1</h3>');
    text = text.replace(/^# (.+)$/gm,   '<h2 class="md-h2">$1</h2>');
    // Bold
    text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Inline code
    text = text.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');
    // Bullet list
    text = text.replace(/^\s*[-*]\s+(.+)$/gm, '<li>$1</li>');
    text = text.replace(/(<li>.*<\/li>)/gs, '<ul class="md-ul">$1</ul>');
    // Numbered list
    text = text.replace(/^\s*\d+\.\s+(.+)$/gm, '<li>$1</li>');
    // Horizontal rule
    text = text.replace(/^---$/gm, '<hr class="md-hr"/>');
    // Paragraphs (double newlines → <p>)
    text = text.split(/\n{2,}/).map(b => {
      if (b.match(/^<(h[2-4]|ul|li|hr)/)) return b;
      return `<p class="md-p">${b.replace(/\n/g, '<br/>')}</p>`;
    }).join('\n');

    return text;
  }, [src]);

  return <div className="md-render" dangerouslySetInnerHTML={{ __html: html }} />;
}


// ─────────────────────────────────────────────────────────────────
//  Expanded Alert Detail Row
// ─────────────────────────────────────────────────────────────────
function AlertDetailRow({ alert }) {
  const sev = getSeverity(alert.severity);

  return (
    <tr className="alert-detail-row">
      <td colSpan="8">
        <div className="alert-detail-content">
          <div className="detail-grid">
            <div className="detail-item">
              <span className="detail-key"><Globe size={11}/> Source</span>
              <span className="detail-val">{alert.src_ip}:{alert.src_port || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-key"><Server size={11}/> Destination</span>
              <span className="detail-val">{alert.dest_ip}:{alert.dest_port}</span>
            </div>
            <div className="detail-item">
              <span className="detail-key"><Wifi size={11}/> Protocol</span>
              <span className="detail-val">{alert.protocol || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-key"><Shield size={11}/> Event Type</span>
              <span className="detail-val">{alert.event_type || '—'}</span>
            </div>
            <div className="detail-item">
              <span className="detail-key"><AlertTriangle size={11}/> Severity</span>
              <span className="detail-val" style={{color: sev.color}}>{sev.label} (Level {alert.severity})</span>
            </div>
            <div className="detail-item">
              <span className="detail-key"><Clock size={11}/> Timestamp</span>
              <span className="detail-val">{alert.timestamp}</span>
            </div>
            {alert.category && (
              <div className="detail-item detail-item-wide">
                <span className="detail-key"><Target size={11}/> Category</span>
                <span className="detail-val">{alert.category}</span>
              </div>
            )}
            {alert.flow_id && (
              <div className="detail-item">
                <span className="detail-key"><Activity size={11}/> Flow ID</span>
                <span className="detail-val mono">{alert.flow_id}</span>
              </div>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}


// ─────────────────────────────────────────────────────────────────
//  Live Alerts Table Component
// ─────────────────────────────────────────────────────────────────
function AlertsTable({ alerts }) {
  const [filter, setFilter]       = useState('all'); // 'all' | 'attack' | 'normal'
  const [sortField, setSortField] = useState(null);  // 'confidence' | 'severity' | 'time'
  const [sortDir, setSortDir]     = useState('desc');
  const [expandedId, setExpandedId] = useState(null);

  const toggleSort = useCallback((field) => {
    if (sortField === field) {
      setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  }, [sortField]);

  const processed = useMemo(() => {
    let list = [...alerts].reverse();

    // Filter
    // Filter: Rely exclusively on the final ML prediction label
    if (filter === 'attack') {
      list = list.filter(a => a.prediction?.toLowerCase() === 'attack');
    }
    if (filter === 'normal') {
      list = list.filter(a => a.prediction?.toLowerCase() === 'normal');
    }

    // Sort
    if (sortField === 'confidence') {
      list.sort((a, b) => sortDir === 'desc' ? b.confidence - a.confidence : a.confidence - b.confidence);
    } else if (sortField === 'severity') {
      list.sort((a, b) => sortDir === 'desc' ? (a.severity || 99) - (b.severity || 99) : (b.severity || 99) - (a.severity || 99));
    }

    return list;
  }, [alerts, filter, sortField, sortDir]);

  return (
    <div className="alerts-table-section glass-panel">
      {/* Table Header */}
      <div className="section-title table-header">
        <div style={{display:'flex', alignItems:'center', gap:'0.75rem'}}>
          <Activity size={14} style={{color:'#38bdf8'}} />
          <h3>Live Alert Feed</h3>
          <span className="alert-count-badge">{processed.length}</span>
        </div>
        <div className="table-controls">
          {/* Filter buttons */}
          <div className="filter-group">
            <button
              className={`filter-btn ${filter === 'all' ? 'active' : ''}`}
              onClick={() => setFilter('all')}
            >
              <Eye size={11}/> All
            </button>
            <button
              className={`filter-btn filter-attack ${filter === 'attack' ? 'active' : ''}`}
              onClick={() => setFilter('attack')}
            >
              <ShieldAlert size={11}/> Attacks
            </button>
            <button
              className={`filter-btn filter-normal ${filter === 'normal' ? 'active' : ''}`}
              onClick={() => setFilter('normal')}
            >
              <ShieldCheck size={11}/> Normal
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="table-scroll-area">
        <table className="alerts-table" id="alerts-table">
          <thead>
            <tr>
              <th className="th-time">Time</th>
              <th className="th-src">Source IP</th>
              <th className="th-port">Port</th>
              <th className="th-dest">Dest IP</th>
              <th className="th-sig">Alert Signature</th>
              <th className="th-pred">ML Prediction</th>
              <th 
                className="th-conf sortable" 
                onClick={() => toggleSort('confidence')}
              >
                Confidence <SortDirectionIcon field="confidence" sortField={sortField} sortDir={sortDir} />
              </th>
              <th 
                className="th-sev sortable"
                onClick={() => toggleSort('severity')}
              >
                Severity <SortDirectionIcon field="severity" sortField={sortField} sortDir={sortDir} />
              </th>
            </tr>
          </thead>
          <tbody>
            {processed.length === 0 ? (
              <tr className="empty-row">
                <td colSpan="8">
                  <div className="empty-state">
                    <Shield size={24} style={{opacity: 0.2}} />
                    <span>
                      {filter !== 'all' 
                        ? `No ${filter} alerts detected`
                        : 'Waiting for network events… Start Suricata or generate traffic'}
                    </span>
                  </div>
                </td>
              </tr>
            ) : (
              processed.map((alert, idx) => {
                const isAttack = alert.prediction === 'Attack';
                const sev = getSeverity(alert.severity);
                const isExpanded = expandedId === idx;
                
                return (
                  <React.Fragment key={idx}>
                    <tr 
                      className={`alert-row ${isAttack ? 'row-attack' : 'row-normal'} ${isExpanded ? 'expanded' : ''}`}
                      onClick={() => setExpandedId(isExpanded ? null : idx)}
                    >
                      <td className="cell-time">
                        <Clock size={11} style={{opacity: 0.4}} />
                        {formatTimestamp(alert.timestamp)}
                      </td>
                      <td className="cell-ip mono">{alert.src_ip}</td>
                      <td className="cell-port mono">{alert.dest_port}</td>
                      <td className="cell-ip mono">{alert.dest_ip}</td>
                      <td className="cell-sig">
                        <span className="sig-text">{alert.alert_sig}</span>
                      </td>
                      <td className="cell-pred">
                        <span className={`pred-badge ${isAttack ? 'pred-attack' : 'pred-normal'}`}>
                          {isAttack 
                            ? <><ShieldAlert size={12}/> ATTACK</> 
                            : <><ShieldCheck size={12}/> NORMAL</>}
                        </span>
                      </td>
                      <td className="cell-conf">
                        <div className="conf-bar-wrap">
                          <div 
                            className={`conf-bar-fill ${isAttack ? 'bar-attack' : 'bar-normal'}`} 
                            style={{width: `${alert.confidence}%`}}
                          />
                        </div>
                        <span className="conf-text">{alert.confidence}%</span>
                      </td>
                      <td className="cell-sev">
                        <span 
                          className="sev-badge" 
                          style={{
                            background: sev.bg, 
                            color: sev.color, 
                            borderColor: sev.border
                          }}
                        >
                          {sev.label}
                        </span>
                        <ChevronRight 
                          size={12} 
                          className={`expand-arrow ${isExpanded ? 'rotated' : ''}`} 
                        />
                      </td>
                    </tr>
                    {isExpanded && <AlertDetailRow alert={alert} />}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────
//  Main Dashboard
// ─────────────────────────────────────────────────────────────────
function App() {
  const [data, setData]             = useState({ alerts: [], last_updated: null });
  const [loading, setLoading]       = useState(true);
  const [systemState, setSystemState] = useState('ACTIVE');
  const [terminalOutput, setTerminalOutput] = useState("System Active. Awaiting commands...");
  const [activeView, setActiveView] = useState('ids'); // 'ids' | 'lab'

  useEffect(() => {
    let interval;
    const fetchData = async () => {
      if (systemState === 'PAUSED') return;
      try {
        const response = await fetch('/api/alerts');
        if (!response.ok) throw new Error('Network response was not ok');
        const json = await response.json();
        setData(json);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching alerts:", error);
      }
    };
    fetchData();
    if (systemState === 'ACTIVE') {
      interval = setInterval(fetchData, 1000);
    }
    return () => clearInterval(interval);
  }, [systemState]);

  const stats = useMemo(() => {
    const total   = data.alerts.length;
    const attacks = data.alerts.filter(a => a.prediction?.toLowerCase() === 'attack').length;
    const normal  = total - attacks;
    const attackPct = total > 0 ? ((attacks / total) * 100).toFixed(1) : '0.0';
    return { total, attacks, normal, attackPct };
  }, [data.alerts]);

  const chartData = useMemo(() => {
    return [...data.alerts].reverse().map((alert, index) => {
      const timeStr = alert.timestamp ? alert.timestamp.split('T')[1]?.substring(0, 8) : `T-${index}`;
      // Map severity: 1(Critical)->95, 2(High)->65, 3(Med)->35, 4(Low)->15
      const sevScore = alert.severity === 1 ? 95 : (alert.severity === 2 ? 65 : (alert.severity === 3 ? 35 : (alert.severity === 4 ? 15 : 0)));
      return {
        time: timeStr || `T-${index}`,
        attackConfidence: alert.prediction?.toLowerCase() === 'attack' ? alert.confidence : 0,
        normalConfidence: alert.prediction?.toLowerCase() === 'normal' ? alert.confidence : 0,
        severityScore: (alert.prediction?.toLowerCase() === 'attack') ? sevScore : 0,
        severityRaw: alert.severity,
        signature: alert.alert_sig,
        ip: alert.src_ip,
      };
    });
  }, [data.alerts]);

  const handleAction = (action) => {
    switch(action) {
      case 'START':
        setSystemState('ACTIVE');
        setTerminalOutput("> INITIATING IDS ENGINES... [OK]");
        break;
      case 'STOP':
        setSystemState('PAUSED');
        setTerminalOutput("> SYSTEM PAUSED. TRAFFIC LOGGING SUSPENDED.");
        break;
      case 'CLEAR':
        fetch('/api/alerts/clear', { method: 'POST' }).catch(console.error);
        setData({ alerts: [], last_updated: data.last_updated });
        setTerminalOutput("> DATABANKS PURGED. (Logs Truncated)");
        break;
      case 'DIAGNOSE':
        setTerminalOutput("> RUNNING SYSTEM DIAGNOSTICS...\n> SURICATA SENSORS: ONLINE\n> ML MODULE: ACTIVE (Features: 57)\n> QUEUE: NOMINAL");
        break;
    }
  };

  return (
    <>
      <div className="app-background"></div>

      <div className="dashboard-container simplified-layout">

        {/* HEADER */}
        <header className="header-section">
          <div className="title-group">
            <h2>Network Telemetry View</h2>
            <h1>Advanced Threat Defense</h1>
          </div>

          {/* Nav tabs */}
          <div className="nav-tabs">
            <button
              id="nav-ids"
              className={`nav-tab ${activeView === 'ids' ? 'active' : ''}`}
              onClick={() => setActiveView('ids')}
            >
              <Shield size={14}/> IDS Monitor
            </button>
            <button
              id="nav-lab"
              className={`nav-tab ${activeView === 'lab' ? 'active' : ''}`}
              onClick={() => setActiveView('lab')}
            >
              <Scan size={14}/> Attack Lab
            </button>
          </div>

          <div className="status-indicator">
            <span className={`status-dot ${stats.attacks > 0 ? 'error' : (systemState==='PAUSED' ? 'paused' : '')}`}></span>
            {systemState === 'PAUSED' ? 'System Paused' : (stats.attacks > 0 ? 'Threat Engaging' : 'System Nominal')}
            <span style={{ fontSize: '0.7rem', opacity: 0.6, marginLeft: '1rem' }}>
              SYNC: {data.last_updated || '00:00:00'}
            </span>
          </div>
        </header>

        {/* METRICS ROW (always visible) — now 4 cards */}
        <section className="stats-row">
          <div className="stat-box glass-panel attack">
            <span className="stat-title"><ShieldAlert size={14} className="inline mr-2" /> Hostile Signatures</span>
            <span className="stat-value">{stats.attacks}</span>
          </div>
          <div className="stat-box glass-panel normal">
            <span className="stat-title"><ShieldCheck size={14} className="inline mr-2" /> Verified Traffic</span>
            <span className="stat-value">{stats.normal}</span>
          </div>
          <div className="stat-box glass-panel total">
            <span className="stat-title"><Activity size={14} className="inline mr-2" /> Total Processed</span>
            <span className="stat-value">{stats.total}</span>
          </div>
          <div className={`stat-box glass-panel pct ${parseFloat(stats.attackPct) > 25 ? 'pct-high' : ''}`}>
            <span className="stat-title"><Percent size={14} className="inline mr-2" /> Attack Rate</span>
            <span className="stat-value">{stats.attackPct}<small>%</small></span>
          </div>
        </section>

        {/* IDS VIEW */}
        {activeView === 'ids' && (
          <div className="ids-main-layout">
            {/* Top Row: Graph + Controls */}
            <div className="main-content-grid">

              {/* Graph */}
              <section className="graph-section glass-panel">
                <div className="section-title">
                  <h3>Telemetry Timeline Vector</h3>
                </div>
                <div className="graph-container">
                  {loading ? (
                    <div className="loading-overlay">
                      <div className="spinner"></div>
                      <p className="control-label">Connecting to server...</p>
                    </div>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <ComposedChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorAttack" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%"  stopColor="#ff006e" stopOpacity={0.8}/>
                            <stop offset="95%" stopColor="#ff006e" stopOpacity={0}/>
                          </linearGradient>
                          <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%"  stopColor="#00f9ff" stopOpacity={0.5}/>
                            <stop offset="95%" stopColor="#00f9ff" stopOpacity={0}/>
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false}/>
                        <XAxis dataKey="time" stroke="#8b9bb4" tick={{fill:'#8b9bb4', fontSize:12, fontFamily:'Fira Code'}} tickMargin={10}/>
                        <YAxis stroke="#8b9bb4" tick={{fill:'#8b9bb4', fontSize:12, fontFamily:'Fira Code'}} domain={[0,100]} tickFormatter={v=>`${v}%`}/>
                        <Tooltip content={<ThreatChartTooltip/>}/>
                        <ReferenceLine y={90} label={{position:'top', value:'High Threat Threshold', fill:'rgba(255,0,110,0.5)', fontSize:10}} stroke="rgba(255,0,110,0.3)" strokeDasharray="3 3"/>
                        <Area type="monotone" dataKey="normalConfidence" stroke="#00f9ff" strokeWidth={2} fillOpacity={1} fill="url(#colorNormal)" animationDuration={1000}/>
                        <Area type="monotone" dataKey="attackConfidence" stroke="#ff006e" strokeWidth={3} fillOpacity={1} fill="url(#colorAttack)" animationDuration={1000} activeDot={{r:8, fill:'#ff006e', stroke:'#fff', strokeWidth:2}}/>
                        <Bar dataKey="severityScore" barSize={8} animationDuration={1500}>
                          {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={getSeverity(entry.severityRaw).color} fillOpacity={0.6} />
                          ))}
                        </Bar>
                      </ComposedChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </section>

              {/* Controls */}
              <section className="control-panel glass-panel">
                <div className="section-title">
                  <h3>System Controls</h3>
                </div>
                <div className="command-grid">
                  <button className={`command-btn start ${systemState === 'ACTIVE' ? 'active' : ''}`} onClick={() => handleAction('START')}>
                    <Power size={20}/><span>Engage Scanners</span>
                  </button>
                  <button className={`command-btn pause ${systemState === 'PAUSED' ? 'active' : ''}`} onClick={() => handleAction('STOP')}>
                    <PauseCircle size={20}/><span>Halt Scanners</span>
                  </button>
                  <button className="command-btn clear" onClick={() => handleAction('CLEAR')}>
                    <Trash2 size={20}/><span>Purge Data</span>
                  </button>
                  <button className="command-btn diagnose" onClick={() => handleAction('DIAGNOSE')}>
                    <Terminal size={20}/><span>Diagnostics</span>
                  </button>
                </div>
                <div className="terminal-display glass-panel">
                  <div className="terminal-header">System Log Output</div>
                  <pre className="terminal-content">{terminalOutput}</pre>
                </div>
              </section>
            </div>

            {/* Bottom: Alerts Table */}
            <AlertsTable alerts={data.alerts} />
          </div>
        )}

        {/* ATTACK LAB VIEW */}
        {activeView === 'lab' && (
          <div className="lab-view">
            <AttackLab alerts={data.alerts} />
          </div>
        )}

      </div>
    </>
  );
}

export default App;
