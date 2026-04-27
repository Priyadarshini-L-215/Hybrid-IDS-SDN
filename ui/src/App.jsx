import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  ShieldAlert, ShieldCheck, Activity,
  Target, Loader, Search,
  Clock, Cpu, Zap, BarChart3
} from 'lucide-react';
import {
  ComposedChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import './App.css';

// ─────────────────────────────────────────────────────────────────
//  Constants & Helpers
// ─────────────────────────────────────────────────────────────────
const SEVERITY_MAP = {
  1: { label: 'Critical', class: 'badge-danger' },
  2: { label: 'High', class: 'badge-danger' },
  3: { label: 'Medium', class: 'badge-primary' },
  4: { label: 'Low', class: 'badge-primary' },
  0: { label: 'Unknown', class: 'badge-primary' },
};

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch {
    return ts;
  }
}

// ─────────────────────────────────────────────────────────────────
//  Components
// ─────────────────────────────────────────────────────────────────

const StatCard = ({ title, value, icon: Icon, type, trend }) => (
  <div className={`stat-card glass glass-interactive fade-in ${type}`}>
    <div className="stat-header">
      <div className="stat-icon">
        <Icon size={20} />
      </div>
      {trend && <span className="stat-trend badge badge-primary">{trend}</span>}
    </div>
    <div className="stat-title">{title}</div>
    <div className="stat-value">{value}</div>
  </div>
);

const AlertRow = React.memo(({ alert }) => {
  const isAttack = alert.prediction?.toLowerCase() === 'attack';
  const rowKey = alert.event_id || alert.id || `${alert.timestamp}-${alert.src_ip}-${alert.dest_ip}-${alert.src_port || ''}-${alert.dest_port || ''}`;
  
  return (
    <tr key={rowKey} className={`alert-row ${isAttack ? 'critical' : 'normal'}`}>
      <td>
        <div className="cell-time">
          <Clock size={12} /> {formatTimestamp(alert.timestamp)}
        </div>
      </td>
      <td className="mono">{alert.src_ip}</td>
      <td className="mono">{alert.dest_ip}</td>
      <td className="sig-text">{alert.alert_sig}</td>
      <td>
        <span className={`badge ${isAttack ? 'badge-danger' : 'badge-primary'}`}>
          {alert.prediction?.toUpperCase()}
        </span>
      </td>
      <td>
        <div className="mono" style={{ color: isAttack ? 'var(--danger)' : 'var(--primary)' }}>
          {alert.confidence}%
        </div>
      </td>
    </tr>
  );
});

const AlertsTable = ({ alerts, filter, onFilterChange }) => {
  const filteredAlerts = useMemo(() => {
    let list = [...alerts].reverse();
    if (filter === 'attack') list = list.filter(a => a.prediction?.toLowerCase() === 'attack');
    if (filter === 'normal') list = list.filter(a => a.prediction?.toLowerCase() === 'normal');
    return list;
  }, [alerts, filter]);

  return (
    <div className="alerts-table-section glass fade-in">
      <div className="table-header">
        <div className="table-title">
          <Activity size={18} className="text-primary" />
          <h3>Real-time Event Stream</h3>
          <span className="table-badge">{filteredAlerts.length} Active</span>
        </div>
        <div className="filter-group">
          <button className={`filter-btn ${filter === 'all' ? 'active' : ''}`} onClick={() => onFilterChange('all')}>All</button>
          <button className={`filter-btn ${filter === 'attack' ? 'active' : ''}`} onClick={() => onFilterChange('attack')}>Threats</button>
          <button className={`filter-btn ${filter === 'normal' ? 'active' : ''}`} onClick={() => onFilterChange('normal')}>Safe</button>
        </div>
      </div>
      <div className="table-scroll">
        <table className="alerts-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Origin</th>
              <th>Target</th>
              <th>Signature</th>
              <th>Analysis</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr><td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>Waiting for network events...</td></tr>
            ) : (
              filteredAlerts.map((alert, idx) => (
                <AlertRow key={alert.event_id || alert.id || `${alert.timestamp}-${alert.src_ip}-${alert.dest_ip}-${idx}`} alert={alert} />
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const AttackLab = ({ alerts }) => {
  const [target, setTarget] = useState("172.25.24.205");
  const [profile, setProfile] = useState("quick");
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [profiles, setProfiles] = useState([
    { id: 'quick', label: 'Quick Identification' },
    { id: 'stealth_syn', label: 'Stealth SYN Scan' },
    { id: 'aggressive', label: 'Full Aggressive Scan' },
    { id: 'vuln', label: 'Vulnerability Audit' },
  ]);

  // Fetch profiles from backend for accurate sync
  useEffect(() => {
    fetch('/api/nmap/profiles')
      .then(r => r.json())
      .then(data => {
        if (data.profiles && data.profiles.length) {
          setProfiles(data.profiles);
        }
      })
      .catch(() => { }); // Keep defaults on failure
  }, []);

  const runScan = async () => {
    setScanning(true);
    setResult(null);
    try {
      const res = await fetch('/api/nmap/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, profile }),
      });
      const data = await res.json();
      setResult(data);
    } catch (e) {
      setResult({ success: false, error: String(e) });
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="attack-lab fade-in">
      <div className="lab-grid">
        <div className="lab-card glass">
          <div className="table-title" style={{ marginBottom: '1.5rem' }}>
            <Target size={18} className="text-danger" />
            <h3>Attack Simulation Module</h3>
          </div>
          <div className="form-group">
            <label className="form-label">Target Network/IP</label>
            <input className="form-input" value={target} onChange={e => setTarget(e.target.value)} placeholder="192.168.1.1" />
          </div>
          <div className="form-group">
            <label className="form-label">Scan Profile</label>
            <select className="form-select" value={profile} onChange={e => setProfile(e.target.value)}>
              {profiles.map(p => (
                <option key={p.id} value={p.id}>{p.label}</option>
              ))}
            </select>
          </div>
          <button className="btn-primary" onClick={runScan} disabled={scanning}>
            {scanning ? <><Loader size={16} className="spin" style={{ marginRight: '8px' }} /> Initializing...</> : 'Execute Attack Simulation'}
          </button>
        </div>
        <div className="lab-card glass">
          <div className="table-title" style={{ marginBottom: '1.5rem' }}>
            <Search size={18} className="text-primary" />
            <h3>Scanner Raw Output</h3>
          </div>
          <div className="output-window">
            {result ? result.raw_output || result.error : 'Awaiting simulation initialization...'}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────────
//  Main App
// ─────────────────────────────────────────────────────────────────
function App() {
  const [data, setData] = useState({
    alerts: [],
    chart_points: [],
    total_processed: 0,
    attack_total: 0,
    normal_total: 0,
    last_updated: null
  });
  const [activeView, setActiveView] = useState('ids');
  const [filter, setFilter] = useState('all');
  const [connectionState, setConnectionState] = useState('connecting');
  const wsRef = useRef(null);
  const pendingAlertsRef = useRef([]); // Batching queue for high-frequency events

  // Data Pipeline: WebSocket logic
  useEffect(() => {
    let retryCount = 0;
    let ws = null;
    let retryTimeout = null;
    let shouldReconnect = true;
    const retryDelays = [2000, 5000, 10000];

    // Batch processor: updates state every 250ms to prevent UI lockup during bursts
    const flushInterval = setInterval(() => {
      if (pendingAlertsRef.current.length === 0) return;

      const batch = [...pendingAlertsRef.current];
      pendingAlertsRef.current = [];

      setData(prev => {
        let nextAlerts = [...prev.alerts];
        let nextAttacks = prev.attack_total;
        let nextNormal = prev.normal_total;

        batch.forEach(alert => {
          // Avoid duplicate log entries using unique event_id or id
          const isDuplicate = nextAlerts.some(a => 
            (a.event_id && alert.event_id && a.event_id === alert.event_id) ||
            (a.id && alert.id && a.id === alert.id) ||
            (!a.event_id && !a.id && a.timestamp === alert.timestamp && a.src_ip === alert.src_ip && a.dest_ip === alert.dest_ip)
          );
          if (isDuplicate) return;

          const isAttack = alert.prediction?.toLowerCase() === 'attack';
          nextAlerts.push(alert);
          if (isAttack) nextAttacks++; else nextNormal++;
        });

        const nextPoints = [...prev.chart_points, ...batch.map(a => ({
          time: formatTimestamp(a.timestamp),
          threat: a.prediction?.toLowerCase() === 'attack' ? a.confidence : 0,
          safe: a.prediction?.toLowerCase() === 'normal' ? a.confidence : 0,
        }))].slice(-100);

        return {
          ...prev,
          alerts: nextAlerts.slice(-100),
          chart_points: nextPoints,
          total_processed: prev.total_processed + batch.length,
          attack_total: nextAttacks,
          normal_total: nextNormal,
          last_updated: new Date().toLocaleTimeString('en-GB')
        };
      });
    }, 250);

    const getWebSocketUrl = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${proto}//${window.location.host}/ws/alerts`;
    };

    const connectWS = () => {
      const wsUrl = getWebSocketUrl();
      setConnectionState(retryCount === 0 ? 'connecting' : 'retrying');
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        retryCount = 0; // Reset backoff on success
        setConnectionState('connected');
      };

      ws.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          
          // --- TRACER: Pipeline latency measurement ---
          if (alert._tracer && alert._tracer_inject_ts) {
            const T6 = Date.now() / 1000;
            const T0 = alert._tracer_inject_ts;
            const T1 = alert._watcher_read_ts;
            const T4 = alert._ws_send_ts;
            const T5b = alert._relay_fwd_ts;
            const ms = (a, b) => a && b ? ((b - a) * 1000).toFixed(1) : '-';
            const cum = (t) => t ? ((t - T0) * 1000).toFixed(1) : '-';
            
            console.log(
              `%c[PIPELINE] Latency: ${((T6-T0)*1000).toFixed(1)}ms | Read: +${ms(T0,T1)}ms | Relay: +${ms(T4,T5b)}ms | Net: +${ms(T5b,T6)}ms`,
              'color: #00e676; font-family: monospace;'
            );
          }

          // Queue for batching instead of immediate state update
          pendingAlertsRef.current.push(alert);
        } catch (e) {
          console.error('[Pipeline] WebSocket parse error:', e);
        }
      };

      ws.onclose = () => {
        if (!shouldReconnect) {
          return;
        }
        const delay = retryDelays[Math.min(retryCount, retryDelays.length - 1)];
        setConnectionState('retrying');
        retryCount++;
        retryTimeout = setTimeout(connectWS, delay);
      };

      ws.onerror = (err) => {
        setConnectionState('error');
        console.error('[Pipeline] WebSocket error:', err);
      };
    };

    connectWS();
    return () => {
      shouldReconnect = false;
      clearTimeout(retryTimeout);
      clearInterval(flushInterval);
      ws?.close();
    };
  }, []);

  // Data Pipeline: Initial Seeding
  useEffect(() => {
    const seedData = async () => {
      try {
        console.log("[Pipeline] Fetching historical state...");
        const response = await fetch('/api/alerts');
        const json = await response.json();

        setData(prev => {
          // Create a merged list of unique alerts
          const existingIds = new Set(prev.alerts.map(a => a.event_id || a.id || `${a.timestamp}-${a.src_ip}-${a.dest_ip}`));
          const newHistorical = json.alerts.filter(a => !existingIds.has(a.event_id || a.id || `${a.timestamp}-${a.src_ip}-${a.dest_ip}`));

          const allAlerts = [...newHistorical, ...prev.alerts].slice(-100);
          return {
            ...json,
            alerts: allAlerts,
            chart_points: allAlerts.map(a => ({
              time: formatTimestamp(a.timestamp),
              threat: a.prediction?.toLowerCase() === 'attack' ? a.confidence : 0,
              safe: a.prediction?.toLowerCase() === 'normal' ? a.confidence : 0,
            })),
            total_processed: Math.max(json.total_processed, prev.total_processed),
            attack_total: Math.max(json.attack_total, prev.attack_total),
            normal_total: Math.max(json.normal_total, prev.normal_total)
          };
        });
      } catch (error) {
        console.error("[Pipeline] Seeding error:", error);
      }
    };
    seedData();
  }, []);

  const chartData = data.chart_points;

  return (
    <div className="dashboard-container">
      <div className="app-bg-glow" />

      <header className="header-section fade-in">
        <div className="title-group">
          <h1>Sentinel Core</h1>
          <p>Next-Gen Hybrid Machine Learning Network Defense</p>
        </div>

        <div className="nav-tabs">
          <button className={`nav-tab ${activeView === 'ids' ? 'active' : ''}`} onClick={() => setActiveView('ids')}>
            <Activity size={16} /> Monitoring
          </button>
          <button className={`nav-tab ${activeView === 'lab' ? 'active' : ''}`} onClick={() => setActiveView('lab')}>
            <Target size={16} /> Attack Lab
          </button>
        </div>

        <div className="status-indicator">
          <div
            className="status-dot"
            style={{
              backgroundColor:
                connectionState === 'connected'
                  ? (data.attack_total > 0 ? 'var(--danger)' : 'var(--primary)')
                  : connectionState === 'error'
                    ? 'var(--danger)'
                    : 'var(--warning)',
            }}
          />
          <span>
            {connectionState === 'connected'
              ? (data.last_updated ? `LIVE: ${data.last_updated}` : 'CONNECTED')
              : connectionState === 'error'
                ? 'CONNECTION ERROR'
                : connectionState === 'reconnecting'
                  ? 'RECONNECTING...'
                  : 'CONNECTING...'}
          </span>
        </div>
      </header>

      <section className="stats-row">
        <StatCard title="Active Threats" value={data.attack_total} icon={ShieldAlert} type="attack" trend={data.attack_total > 0 ? "+CRITICAL" : "STABLE"} />
        <StatCard title="Safe Traffic" value={data.normal_total} icon={ShieldCheck} type="success" trend="VERIFIED" />
        <StatCard title="Processed Flows" value={data.total_processed} icon={Cpu} />
        <StatCard title="Detection Rate" value={`${data.total_processed > 0 ? ((data.attack_total / data.total_processed) * 100).toFixed(1) : 0}%`} icon={Zap} />
      </section>

      {activeView === 'ids' ? (
        <div className="ids-main-layout">
          <div className="viz-card glass fade-in">
            <div className="table-title" style={{ marginBottom: '1.5rem' }}>
              <BarChart3 size={18} className="text-secondary" />
              <h3>Traffic Analysis Baseline</h3>
            </div>
            <ResponsiveContainer width="100%" height={240}>
              <ComposedChart data={chartData}>
                <defs>
                  <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--danger)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--danger)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}
                  itemStyle={{ fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="safe" stroke="var(--primary)" fillOpacity={1} fill="url(#colorSafe)" />
                <Area type="monotone" dataKey="threat" stroke="var(--danger)" fillOpacity={1} fill="url(#colorThreat)" />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <AlertsTable alerts={data.alerts} filter={filter} onFilterChange={setFilter} />
        </div>
      ) : (
        <AttackLab alerts={data.alerts} />
      )}
    </div>
  );
}

export default App;
