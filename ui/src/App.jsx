import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Activity, Zap, Database, Terminal, Settings, 
  AlertTriangle, CheckCircle2, Server, Globe, Lock, Unlock, Home,
  Cpu, RefreshCcw, Search, Filter, ArrowRight, Play, StopCircle, 
  Clock, ExternalLink, Info, ChevronDown, FileText, Upload, 
  Link, BarChart3, Network, Share2, Eye, Trash2, Bug, 
  HardDrive, Target, Flame, ShieldCheck, Radio, Layers, 
  Fingerprint, RotateCcw, Save, Key, X, MapPin, History, Download
} from 'lucide-react';
import { 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';
import { ComposableMap, Geographies, Geography, Marker } from "react-simple-maps";
import ForceGraph2D from 'react-force-graph-2d';
import './App.css';

const geoUrl = "https://raw.githubusercontent.com/lotusms/world-map-data/master/world-110m.json";

// --- UTILS ---
const formatTimestamp = (ts) => {
  if (!ts) return "--:--:--";
  try {
    const date = new Date(ts);
    if (isNaN(date.getTime())) return ts;
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  } catch (e) { return ts; }
};

const COLORS = ['#38bdf8', '#f43f5e', '#10b981', '#f59e0b', '#8b5cf6'];

// --- UI COMPONENTS ---
const Badge = ({ children, variant = 'info' }) => (
  <span className={`badge badge-${variant}`}>
    <span className="badge-dot" style={{ backgroundColor: 'currentColor' }} />
    {children}
  </span>
);

const GlassCard = ({ children, title, subtitle, icon: Icon, actions, className = '', style = {} }) => (
  <motion.div 
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={`glass-card ${className}`}
    style={style}
  >
    {title && (
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
        <div className="panel-title-group">
          <div className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {Icon && <Icon size={18} className="text-primary" />}
            <span className="gradient-text" style={{ fontSize: '1rem', fontWeight: 800 }}>{title}</span>
          </div>
          {subtitle && <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '4px' }}>{subtitle}</p>}
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </div>
    )}
    {children}
  </motion.div>
);

const StatCard = ({ label, value, icon: Icon, color = 'var(--primary)' }) => (
  <GlassCard className="stat-card">
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
      <div className="stat-label">{label}</div>
      <div style={{ padding: '8px', borderRadius: '10px', background: `${color}15`, color, border: `1px solid ${color}20` }}>
        <Icon size={18} />
      </div>
    </div>
    <div className="stat-value-large">{value}</div>
  </GlassCard>
);

const CompactIP = ({ ip, onClick }) => {
  if (!ip || ip === '---') return <span>---</span>;
  
  const isLocal = ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('172.');
  const displayIp = ip.length > 18 ? `${ip.substring(0, 10)}...${ip.substring(ip.length - 4)}` : ip;
  
  return (
    <div 
      className="compact-ip-badge" 
      onClick={onClick}
      title={ip}
      style={{ 
        display: 'inline-flex', 
        alignItems: 'center', 
        gap: '6px', 
        cursor: onClick ? 'pointer' : 'default',
        padding: '4px 8px',
        background: isLocal ? 'rgba(16, 185, 129, 0.08)' : 'rgba(56, 189, 248, 0.08)',
        borderRadius: '8px',
        border: `1px solid ${isLocal ? 'rgba(16, 185, 129, 0.15)' : 'rgba(56, 189, 248, 0.15)'}`,
        transition: 'all 0.2s'
      }}
    >
      {isLocal ? <Home size={10} className="text-success" /> : <Globe size={10} className="text-primary" />}
      <span style={{ 
        fontFamily: 'var(--font-mono)', 
        fontSize: '0.75rem', 
        fontWeight: 700,
        color: isLocal ? 'var(--success)' : 'var(--primary)'
      }}>
        {displayIp}
      </span>
    </div>
  );
};

// --- MAIN APPLICATION ---
function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ processed_total: 0, attacks: 0, normal: 0 });
  const [chartData, setChartData] = useState(
    Array.from({ length: 30 }, (_, i) => {
      const d = new Date(Date.now() - (29 - i) * 2000);
      return { time: d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }), normal: 0, attacks: 0 };
    })
  );
  const [latency, setLatency] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);

  // Configuration
  const [config, setConfig] = useState(null);
  const [saveStatus, setSaveStatus] = useState(null);

  // Simulation
  const [scanTarget, setScanTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('quick');
  const [simulating, setSimulating] = useState(false);
  const [simOutput, setSimOutput] = useState('');

  // Evaluation
  const [modelList, setModelList] = useState({ models: [], scalers: [], active_model: '', active_scaler: '' });
  const [evaluating, setEvaluating] = useState(false);
  const [evalResult, setEvalResult] = useState(null);

  // Model Control (Settings)
  const [models, setModels] = useState([]);
  const [scalers, setScalers] = useState([]);
  const [activeModel, setActiveModel] = useState('');
  const [activeScaler, setActiveScaler] = useState('');
  const [swapping, setSwapping] = useState(false);

  // Node Intel
  const [selectedIp, setSelectedIp] = useState(null);
  const [nodeIntel, setNodeIntel] = useState(null);
  const [loadingIntel, setLoadingIntel] = useState(false);

  // Search & Filtering
  const [filterQuery, setFilterQuery] = useState('');
  const [filterLevel, setFilterLevel] = useState('ALL');

  // Operational Monitoring
  const [systemLogs, setSystemLogs] = useState([{ ts: new Date().toISOString(), msg: 'Sentinel Core UI Initialized' }]);
  
  const addLog = (msg) => {
    setSystemLogs(prev => [{ ts: new Date().toISOString(), msg }, ...prev].slice(0, 50));
  };

  const ws = useRef(null);
  const statsRef = useRef({ processed_total: 0, attacks: 0, normal: 0 });

  // --- DERIVED DATA ---
  const graphData = useMemo(() => {
    const nodes = new Map();
    const links = [];
    
    // Internal node center
    nodes.set('INTERNAL', { id: 'INTERNAL', name: 'Sentinel Node', group: 'core', val: 25 });

    // Process recent alerts for graph
    alerts.slice(0, 30).forEach(alert => {
      const src = alert.src_ip;
      const isAttack = alert.prediction?.toLowerCase().includes('attack');
      
      if (!nodes.has(src)) {
        nodes.set(src, { 
          id: src, 
          name: src,
          group: isAttack ? 'attacker' : 'neutral',
          val: isAttack ? 15 : 10
        });
      }
      links.push({ source: src, target: 'INTERNAL', value: isAttack ? 2 : 1 });
    });

    return { nodes: Array.from(nodes.values()), links };
  }, [alerts]);

  const mapMarkers = useMemo(() => {
    return alerts
      .filter(a => a.enrichment?.lat && a.enrichment?.lon)
      .map((a, i) => ({
        id: a.event_id || i,
        name: a.enrichment.location,
        coordinates: [a.enrichment.lon, a.enrichment.lat],
        isAttack: a.prediction?.toLowerCase().includes('attack')
      }))
      .slice(0, 15);
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const prediction = (a.prediction || '').toLowerCase();
      const matchesQuery = !filterQuery || 
        a.src_ip.includes(filterQuery) || 
        prediction.includes(filterQuery.toLowerCase()) ||
        a.protocol?.toLowerCase().includes(filterQuery.toLowerCase());
      
      const matchesLevel = filterLevel === 'ALL' || 
        (filterLevel === 'ATTACKS' && (prediction.includes('attack') || prediction.includes('anomaly'))) ||
        (filterLevel === 'SUSPICIOUS' && prediction.includes('suspicious')) ||
        (filterLevel === 'NORMAL' && prediction.includes('normal'));
        
      return matchesQuery && matchesLevel;
    });
  }, [alerts, filterQuery, filterLevel]);

  const protocolStats = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const p = a.protocol?.toUpperCase() || 'OTHER';
      counts[p] = (counts[p] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value);
  }, [alerts]);

  const lastStatsRef = useRef({ processed: 0, attacks: 0 });

  // --- API CALLS ---
  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/pipeline/status');
      const data = await res.json();
      setHealth(data);
      if (data.stats) {
        setStats(data.stats);
        statsRef.current = data.stats;
      }
    } catch (e) { console.error("Status fetch failed", e); }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts');
      const data = await res.json();
      if (data.alerts) {
        setAlerts(data.alerts);
        setStats({ processed_total: data.total_processed, attacks: data.attack_total, normal: data.normal_total });
        statsRef.current = { processed_total: data.total_processed, attacks: data.attack_total, normal: data.normal_total };
        lastStatsRef.current = { processed: data.total_processed, attacks: data.attack_total };
        addLog(`Alerts: Synchronized ${data.alerts.length} events from database`);
      }
    } catch (e) { console.error("Alerts fetch failed", e); }
  };

  const fetchNodeIntel = async (ip) => {
    if (!ip || ip === '---') return;
    setSelectedIp(ip);
    setLoadingIntel(true);
    setNodeIntel(null);
    try {
      const res = await fetch(`/api/intelligence/node/${ip}`);
      const data = await res.json();
      setNodeIntel(data);
      addLog(`Intelligence: Analyzed node ${ip} (Risk: ${data.reputation_score}%)`);
    } catch (e) { 
      console.error("Intel fetch failed", e); 
      addLog(`Error: Failed to fetch intelligence for ${ip}`);
    } finally { setLoadingIntel(false); }
  };

  const runSimulation = async (type, payload = {}) => {
    setSimulating(true);
    setSimOutput(`> Starting ${type.toUpperCase()} simulation...\n`);
    try {
      const endpoint = type === 'nmap' ? '/api/simulation/nmap/scan' : '/api/simulation/attack/ddos';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget, ...payload })
      });
      const data = await res.json();
      setSimOutput(prev => prev + (data.raw_output || data.message || data.error || 'Done.'));
    } catch (e) { setSimOutput(prev => prev + `[ERROR] ${e.message}`); } finally { setSimulating(false); }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setEvaluating(true);
    setEvalResult(null);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('label_column', 'Label'); // Default
    try {
      const res = await fetch('/api/evaluate/dataset', { method: 'POST', body: formData });
      setEvalResult(await res.json());
    } catch (e) { console.error("Eval failed", e); } finally { setEvaluating(false); }
  };

  const blockAction = async (ip, action) => {
    try {
      await fetch(`/api/mitigation/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      fetchStatus();
      if (selectedIp === ip) fetchNodeIntel(ip);
    } catch (e) { console.error("Mitigation failed", e); }
  };

  const fetchModels = async () => {
    try {
      const res = await fetch('/api/models');
      const data = await res.json();
      setModels(data.models || []);
      setScalers(data.scalers || []);
      setActiveModel(data.active_model || '');
      setActiveScaler(data.active_scaler || '');
    } catch (e) { console.error("Failed to fetch models", e); }
  };

  const swapModel = async () => {
    setSwapping(true);
    try {
      const res = await fetch('/api/models/active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_file: activeModel, scaler_file: activeScaler })
      });
      const data = await res.json();
      if (data.success) {
        setSaveStatus({ type: 'success', msg: 'Engine updated successfully' });
      } else {
        setSaveStatus({ type: 'error', msg: data.error || 'Update failed' });
      }
    } catch (e) { 
      setSaveStatus({ type: 'error', msg: e.message });
    } finally { 
      setSwapping(false);
      setTimeout(() => setSaveStatus(null), 3000);
    }
  };

  const downloadPcap = (eventId) => {
    window.open(`/api/pcap/download/${eventId || 'latest'}`, '_blank');
  };

  // --- LIFECYCLE ---
  useEffect(() => {
    fetchStatus(); fetchAlerts(); fetchModels();
    const timer = setInterval(fetchStatus, 3000);
    return () => clearInterval(timer);
  }, []);

  const alertBuffer = useRef([]);

  useEffect(() => {
    const connect = () => {
      const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/alerts`;
      ws.current = new WebSocket(WS_URL);
      ws.current.onopen = () => setConnected(true);
      ws.current.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          alertBuffer.current.push(alert);
        } catch (e) {}
      };
      ws.current.onclose = () => { setConnected(false); setTimeout(connect, 3000); };
    };
    connect();

    // Throttled UI flush loop (60fps max)
    let animationFrame;
    const flushBuffer = () => {
      if (alertBuffer.current.length > 0) {
        const batch = [...alertBuffer.current];
        alertBuffer.current = [];
        
        setAlerts(prev => {
          const next = [...batch, ...prev].slice(0, 100);
          return next;
        });

        // Update stats once per batch
        const batchStats = batch.reduce((acc, a) => {
          const prediction = a.prediction?.toLowerCase() || '';
          const isAttack = prediction.includes('attack') || prediction.includes('suspicious') || prediction.includes('anomaly');
          acc.processed += 1;
          if (isAttack) acc.attacks += 1;
          else acc.normal += 1;
          return acc;
        }, { processed: 0, attacks: 0, normal: 0 });

        setStats(prev => {
          const next = {
            processed_total: prev.processed_total + batchStats.processed,
            attacks: prev.attacks + batchStats.attacks,
            normal: prev.normal + batchStats.normal
          };
          // Sync with ref for the chart interval
          statsRef.current = next;
          return next;
        });

        if (batch[0].processing_time_ms) setLatency(batch[0].processing_time_ms);
      }
      animationFrame = requestAnimationFrame(flushBuffer);
    };
    animationFrame = requestAnimationFrame(flushBuffer);

    return () => {
      ws.current?.close();
      cancelAnimationFrame(animationFrame);
    };
  }, []);

  // Chart data sync
  useEffect(() => {
    const timer = setInterval(() => {
      const current = statsRef.current;
      const last = lastStatsRef.current;
      const deltaTotal = current.processed_total - last.processed;
      const deltaAttacks = current.attacks - last.attacks;
      setChartData(prev => {
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
        return [...prev, { time: now, normal: Math.max(0, deltaTotal - deltaAttacks), attacks: deltaAttacks }].slice(-30);
      });
      lastStatsRef.current = { processed: current.processed_total, attacks: current.attacks };
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="dashboard-container">
      <div className="bg-blobs">
        <div className="blob blob-1" /><div className="blob blob-2" /><div className="blob blob-3" />
      </div>

      {/* --- SIDEBAR --- */}
      <aside className="sidebar glass-panel">
        <div className="sidebar-logo">
          <Shield className="text-primary pulse" size={28} />
          <span className="gradient-text" style={{ fontWeight: 900, fontSize: '1.2rem', letterSpacing: '-0.02em' }}>SENTINEL</span>
        </div>

        <nav className="sidebar-nav">
          {[
            { id: 'overview', label: 'Command Hub', icon: Activity },
            { id: 'visual', label: 'Visual Intel', icon: Network },
            { id: 'mitigation', label: 'Policies', icon: ShieldCheck },
            { id: 'lab', label: 'Simulation', icon: Target },
            { id: 'eval', label: 'Evaluation', icon: Fingerprint },
            { id: 'settings', label: 'Engine Config', icon: Settings }
          ].map(tab => (
            <div 
              key={tab.id} 
              className={`nav-item ${activeTab === tab.id ? 'active' : ''}`} 
              onClick={() => {
                setActiveTab(tab.id);
                addLog(`Navigation: Switched to ${tab.label} module`);
              }}
            >
              <tab.icon size={18} />
              <span>{tab.label}</span>
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <div className={`badge-dot ${connected ? 'bg-success' : 'bg-danger'}`} style={{ width: '8px', height: '8px', background: connected ? 'var(--success)' : 'var(--danger)' }} />
            <span>CORE {connected ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
          <div style={{ opacity: 0.5 }}>v3.1.2-STABLE</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="header-section glass-panel">
          <div className="title-group">
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ color: 'var(--text-muted)', fontWeight: 800, fontSize: '0.65rem', letterSpacing: '0.2em', textTransform: 'uppercase' }}>Current Operations</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 900 }}>{activeTab.charAt(0).toUpperCase() + activeTab.slice(1).replace(/_/g, ' ')}</h2>
            </div>
          </div>

          <div className="engine-metrics">
            <div className="metric-item">
              <span className="metric-label">Inference Latency</span>
              <span className="metric-value">{latency.toFixed(2)}ms</span>
            </div>
            <div className="metric-item">
              <span className="metric-label">Queue Depth</span>
              <span className="metric-value">{health?.queue_depth || 0}</span>
            </div>
            <div className="status-hover-wrapper" style={{ cursor: 'pointer' }}>
              <Badge variant={connected ? 'success' : 'danger'}>{connected ? 'SYSTEM READY' : 'OFFLINE'}</Badge>
              <div className="engine-tooltip glass">
                <div style={{ marginBottom: '1rem', fontWeight: 900, fontSize: '0.65rem', color: 'var(--primary)', letterSpacing: '0.1em' }}>ENGINE INTEGRITY</div>
                {[
                  { label: 'Neural Engine', status: health?.checks?.consumer_running, val: health?.checks?.consumer_running ? 'ACTIVE' : 'STOPPED' },
                  { label: 'Redis Stream', status: health?.checks?.redis_ok, val: health?.checks?.redis_ok ? 'SYNCED' : 'ERROR' },
                  { label: 'IPS Backend', status: true, val: health?.ipset?.backend?.toUpperCase() || 'READY' }
                ].map(item => (
                  <div key={item.label} className="health-item">
                     <span className="health-label">{item.label}</span>
                     <span style={{ color: item.status ? 'var(--success)' : 'var(--danger)', fontWeight: 800, fontSize: '0.7rem' }}>{item.val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </header>

        <AnimatePresence mode="wait">
          {activeTab === 'overview' && (
            <motion.div key="overview" className="content-stack" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
              <div className="stats-grid">
                <StatCard label="Total Ingress" value={stats.processed_total?.toLocaleString()} icon={Database} />
                <StatCard label="Threat Vectors" value={stats.attacks?.toLocaleString()} icon={Flame} color="var(--danger)" />
                <StatCard label="Active Policies" value={health?.ipset?.permanent || 0} icon={Shield} color="var(--success)" />
                <StatCard label="Normal Flows" value={stats.normal?.toLocaleString()} icon={CheckCircle2} color="var(--success)" />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
                <div className="table-container glass">
                  <div className="table-header">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <Terminal size={18} className="text-primary" />
                        <span className="gradient-text" style={{ fontWeight: 800 }}>LIVE THREAT STREAM</span>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button className="btn btn-secondary btn-sm" onClick={() => setFilterLevel('ALL')} style={{ opacity: filterLevel === 'ALL' ? 1 : 0.5 }}>ALL</button>
                        <button className="btn btn-danger btn-sm" onClick={() => setFilterLevel('ATTACKS')} style={{ opacity: filterLevel === 'ATTACKS' ? 1 : 0.5 }}>THREATS</button>
                        <button className="btn btn-secondary btn-sm" title="Export CSV" onClick={() => addLog('Export: CSV generation started')}><Download size={12} /></button>
                        <button className="btn btn-secondary btn-sm" onClick={fetchAlerts}><RotateCcw size={12} /></button>
                      </div>
                    </div>
                    <div className="filter-bar">
                      <Search size={14} className="text-muted" />
                      <input 
                        type="text" 
                        className="filter-input" 
                        placeholder="Filter by Source IP, Classification, or Protocol..." 
                        value={filterQuery}
                        onChange={(e) => setFilterQuery(e.target.value)}
                      />
                      {filterQuery && <X size={14} className="text-muted cursor-pointer" onClick={() => setFilterQuery('')} />}
                    </div>
                  </div>
                  <div className="table-scroller" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                    <table className="alerts-table">
                      <thead><tr><th>Timestamp</th><th>Source Node</th><th>Classification</th><th>Score</th><th>Mitigation</th></tr></thead>
                      <tbody>
                        {filteredAlerts.map((alert, i) => {
                          const prediction = (alert.prediction || 'Unknown').toLowerCase();
                          const isAttack = prediction.includes('attack') || prediction.includes('anomaly');
                          const isSuspicious = prediction.includes('suspicious');
                          const confidence = typeof alert.confidence === 'number' ? alert.confidence : 0;
                          
                          return (
                            <React.Fragment key={alert.event_id || i}>
                              <tr 
                                onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                                className={`alert-row ${isAttack ? 'alert-row-danger' : isSuspicious ? 'alert-row-warning' : ''}`}
                              >
                                <td className="text-muted" style={{ fontSize: '0.65rem', fontWeight: 800 }}>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                                <td>
                                  <CompactIP ip={alert.src_ip} onClick={(e) => { e.stopPropagation(); fetchNodeIntel(alert.src_ip); }} />
                                </td>
                                <td>
                                  <Badge variant={isAttack ? 'danger' : isSuspicious ? 'warning' : 'success'}>
                                    {alert.prediction}
                                  </Badge>
                                </td>
                                <td>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                     <div style={{ width: '40px', height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                                        <div style={{ width: `${confidence}%`, height: '100%', background: confidence > 80 ? 'var(--danger)' : confidence > 50 ? 'var(--warning)' : 'var(--success)', transition: 'width 0.5s ease' }} />
                                     </div>
                                     <span style={{ fontWeight: 800, fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>{confidence.toFixed(1)}%</span>
                                  </div>
                                </td>
                                <td>
                                   <Badge variant={alert.mitigation ? 'info' : 'muted'}>
                                     {alert.mitigation || 'LOGGED'}
                                   </Badge>
                                </td>
                              </tr>
                              {expandedRow === i && (
                                <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                                  <td colSpan="5" style={{ padding: '1.5rem' }}>
                                     <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.5rem' }}>
                                        <div>
                                          <h4 style={{ fontSize: '0.6rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Decision Matrix</h4>
                                          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}><span className="text-muted">Signature</span><span>{alert.forensics?.stage_scores?.signature ? 'DETECTED' : 'CLEAN'}</span></div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}><span className="text-muted">Neural</span><span>{(alert.forensics?.stage_scores?.ml * 100).toFixed(1)}%</span></div>
                                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}><span className="text-muted">Anomaly</span><span>{(alert.forensics?.stage_scores?.anomaly * 100).toFixed(1)}%</span></div>
                                          </div>
                                        </div>
                                        <div>
                                          <h4 style={{ fontSize: '0.6rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Enrichment</h4>
                                          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.7rem' }}>
                                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Globe size={12} className="text-muted" /> {alert.enrichment?.location || 'Unknown'}</div>
                                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Network size={12} className="text-muted" /> {alert.enrichment?.asn || 'Internal'}</div>
                                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><FileText size={12} className="text-muted" /> {alert.protocol?.toUpperCase()} / {alert.dst_port || '0'}</div>
                                          </div>
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                          <button className="btn btn-primary btn-sm" onClick={(e) => { e.stopPropagation(); downloadPcap(alert.id || alert.event_id); }}><FileText size={14} /> PCAP</button>
                                           <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); fetchNodeIntel(alert.src_ip); }}><Fingerprint size={14} /> DEEP FORENSICS</button>
                                          {alert.is_mitigated ? (
                                            <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); blockAction(alert.src_ip, 'unblock'); }}>WHITELIST</button>
                                          ) : (
                                            <button className="btn btn-danger btn-sm" onClick={(e) => { e.stopPropagation(); blockAction(alert.src_ip, 'block'); }}>BLOCK IP</button>
                                          )}
                                        </div>
                                     </div>
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="content-stack">
                  <GlassCard title="Real-time Traffic Velocity" icon={Activity} subtitle="Events per second (Ingress vs Threats)">
                    <div style={{ height: '180px', width: '100%' }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={chartData}>
                          <defs>
                            <linearGradient id="cNormal" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--success)" stopOpacity={0.2}/><stop offset="95%" stopColor="var(--success)" stopOpacity={0}/></linearGradient>
                            <linearGradient id="cAttack" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--danger)" stopOpacity={0.2}/><stop offset="95%" stopColor="var(--danger)" stopOpacity={0}/></linearGradient>
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                          <XAxis dataKey="time" stroke="rgba(255,255,255,0.1)" fontSize={10} tick={{fill: 'rgba(255,255,255,0.5)'}} minTickGap={20} />
                          <YAxis stroke="rgba(255,255,255,0.1)" fontSize={10} axisLine={false} tickLine={false} />
                          <Tooltip contentStyle={{ background: 'rgba(2, 6, 23, 0.95)', border: '1px solid var(--border)', borderRadius: '8px' }} />
                          <Area type="monotone" dataKey="normal" stroke="var(--success)" fill="url(#cNormal)" strokeWidth={2} isAnimationActive={false} />
                          <Area type="monotone" dataKey="attacks" stroke="var(--danger)" fill="url(#cAttack)" strokeWidth={2} isAnimationActive={false} />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  </GlassCard>

                  <GlassCard title="Protocol Distribution" icon={Layers} subtitle="Frequency of observed protocols">
                     <div style={{ height: '180px', width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={protocolStats.slice(0, 5)}>
                            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                            <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} axisLine={false} tickLine={false} />
                            <YAxis stroke="var(--text-muted)" fontSize={10} axisLine={false} tickLine={false} />
                            <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)', borderRadius: '8px' }} />
                            <Bar dataKey="value" fill="var(--primary)" radius={[4, 4, 0, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                     </div>
                  </GlassCard>

                  <GlassCard title="Active Policies" icon={ShieldCheck} subtitle="Top Reputation Violations">
                     <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                        {Object.entries(health?.ipset_detailed?.reputation || {})
                          .sort(([, a], [, b]) => b - a)
                          .slice(0, 3)
                          .map(([ip, score]) => (
                            <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                               <CompactIP ip={ip} onClick={() => fetchNodeIntel(ip)} />
                               <span style={{ fontWeight: 900, color: score > 50 ? 'var(--danger)' : 'var(--text-secondary)', fontSize: '0.8rem' }}>{score.toFixed(1)}</span>
                            </div>
                          ))
                        }
                        <button className="btn btn-secondary btn-sm" style={{ marginTop: '0.5rem' }} onClick={() => setActiveTab('mitigation')}>VIEW ALL POLICIES</button>
                     </div>
                  </GlassCard>
                </div>
              </div>

              <GlassCard 
                title="Operational Log" 
                icon={Terminal} 
                subtitle="Real-time system events and UI state transitions"
                actions={<button className="btn-icon" title="Clear Logs" onClick={() => setSystemLogs([{ ts: new Date().toISOString(), msg: 'Logs cleared by operator' }])}><Trash2 size={14} /></button>}
              >
                 <div className="system-log-mini">
                    {systemLogs.map((log, i) => (
                      <div key={i} className="log-entry">
                        <span className="log-ts">[{formatTimestamp(log.ts)}]</span>
                        <span className="log-msg">{log.msg}</span>
                      </div>
                    ))}
                 </div>
              </GlassCard>
            </motion.div>
          )}
          
          {activeTab === 'visual' && (
            <motion.div key="visual" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
               <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem' }}>
                  <GlassCard title="Global Threat Vector Map" icon={Globe} subtitle="Geographic distribution of detected sources">
                    <div style={{ height: '500px', background: 'rgba(0,0,0,0.2)', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                      <ComposableMap projectionConfig={{ scale: 140 }}>
                        <Geographies geography={geoUrl}>
                          {({ geographies }) =>
                            geographies.map((geo) => (
                              <Geography
                                key={geo.rsmKey}
                                geography={geo}
                                fill="rgba(255,255,255,0.03)"
                                stroke="rgba(255,255,255,0.1)"
                                strokeWidth={0.5}
                                style={{
                                  default: { outline: "none" },
                                  hover: { fill: "rgba(56, 189, 248, 0.1)", outline: "none" },
                                  pressed: { outline: "none" },
                                }}
                              />
                            ))
                          }
                        </Geographies>
                        {mapMarkers.map(({ id, name, coordinates, isAttack }) => (
                          <Marker key={id} coordinates={coordinates}>
                            <motion.circle
                              initial={{ r: 0, opacity: 1 }}
                              animate={{ r: [4, 10, 4], opacity: [1, 0.4, 1] }}
                              transition={{ repeat: Infinity, duration: 2 }}
                              fill={isAttack ? "var(--danger)" : "var(--primary)"}
                              stroke="#fff"
                              strokeWidth={1}
                            />
                          </Marker>
                        ))}
                      </ComposableMap>
                    </div>
                  </GlassCard>

                  <GlassCard title="Network Topology" icon={Network} subtitle="Real-time flow relationship graph">
                    <div className="topology-wrapper">
                       <ForceGraph2D
                          graphData={graphData}
                          width={600}
                          height={500}
                          backgroundColor="rgba(0,0,0,0)"
                          nodeLabel="name"
                          nodeColor={n => {
                            if (n.group === 'core') return '#38bdf8';
                            if (n.group === 'attacker') return '#f43f5e';
                            return '#10b981';
                          }}
                          nodeRelSize={6}
                          linkColor={() => 'rgba(255,255,255,0.05)'}
                          linkWidth={1}
                          linkDirectionalParticles={2}
                          linkDirectionalParticleSpeed={d => d.value * 0.01}
                       />
                    </div>
                  </GlassCard>
               </div>
            </motion.div>
          )}

          {activeTab === 'mitigation' && (
            <motion.div key="mitigation" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <GlassCard title="Active Blocklist" icon={ShieldCheck} subtitle="Nodes currently restricted by IPS">
                   <div style={{ maxHeight: '500px', overflowY: 'auto' }}>
                      <div className="content-stack">
                        <div>
                          <div className="stat-label" style={{ marginBottom: '1rem', color: 'var(--danger)' }}>Permanent Blocks ({health?.ipset_detailed?.permanent_ips?.length || 0})</div>
                          {health?.ipset_detailed?.permanent_ips?.map(ip => (
                            <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.8rem 1rem', background: 'rgba(244, 63, 94, 0.05)', borderRadius: '12px', marginBottom: '8px', border: '1px solid rgba(244, 63, 94, 0.1)' }}>
                               <CompactIP ip={ip} onClick={() => fetchNodeIntel(ip)} />
                               <button className="btn-icon text-danger" onClick={() => blockAction(ip, 'unblock')}><Unlock size={14} /></button>
                            </div>
                          ))}
                        </div>
                        <div>
                          <div className="stat-label" style={{ marginBottom: '1rem', color: 'var(--warning)' }}>Temporary Blocks ({health?.ipset_detailed?.temporary_ips?.length || 0})</div>
                          {health?.ipset_detailed?.temporary_ips?.map(ip => (
                            <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.8rem 1rem', background: 'rgba(245, 158, 11, 0.05)', borderRadius: '12px', marginBottom: '8px', border: '1px solid rgba(245, 158, 11, 0.1)' }}>
                               <CompactIP ip={ip} onClick={() => fetchNodeIntel(ip)} />
                               <button className="btn-icon text-muted" onClick={() => blockAction(ip, 'unblock')}><Unlock size={14} /></button>
                            </div>
                          ))}
                        </div>
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Global Reputation Scores" icon={BarChart3} subtitle="Probabilistic threat weights by node">
                   <div className="table-container" style={{ border: 'none', background: 'transparent' }}>
                      <table className="alerts-table">
                        <thead><tr><th>Node Identity</th><th>Security Index</th><th>Weight</th></tr></thead>
                        <tbody>
                          {Object.entries(health?.ipset_detailed?.reputation || {})
                            .sort(([, a], [, b]) => b - a)
                            .map(([ip, score]) => (
                              <tr key={ip}>
                                <td><CompactIP ip={ip} onClick={() => fetchNodeIntel(ip)} /></td>
                                <td><Badge variant={score > 60 ? 'danger' : score > 30 ? 'warning' : 'success'}>{score > 60 ? 'MALICIOUS' : score > 30 ? 'SUSPICIOUS' : 'TRUSTED'}</Badge></td>
                                <td style={{ width: '150px' }}>
                                   <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                      <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                                        <div style={{ height: '100%', width: `${score}%`, background: score > 60 ? 'var(--danger)' : 'var(--primary)' }} />
                                      </div>
                                      <span style={{ fontWeight: 900, fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{score.toFixed(1)}</span>
                                   </div>
                                </td>
                              </tr>
                            ))
                          }
                        </tbody>
                      </table>
                   </div>
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'lab' && (
            <motion.div key="lab" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '1.5rem' }}>
                <GlassCard title="Simulation Lab" icon={Flame} subtitle="Traffic Generation & Vulnerability Scanning">
                   <div className="content-stack">
                      <div><label className="stat-label">Target IPv4 Address</label><input type="text" className="input-field" value={scanTarget} onChange={e => setScanTarget(e.target.value)} /></div>
                      <div>
                         <label className="stat-label">Scan Profiles</label>
                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '8px' }}>
                            {['quick', 'ping', 'service', 'os_detect', 'aggressive', 'vuln'].map(p => (
                              <button key={p} className={`btn btn-secondary btn-sm ${scanProfile === p ? 'btn-primary' : ''}`} onClick={() => setScanProfile(p)}>{p.toUpperCase()}</button>
                            ))}
                         </div>
                         <button className="btn btn-primary" style={{ width: '100%', marginTop: '1rem' }} onClick={() => runSimulation('nmap', { profile: scanProfile })} disabled={simulating}>
                            {simulating ? <RefreshCcw className="animate-spin" size={16} /> : <Search size={16} />} RUN SCAN
                         </button>
                      </div>
                      <div style={{ paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                         <label className="stat-label">Threat Simulations</label>
                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '8px' }}>
                            <button className="btn btn-danger btn-sm" onClick={() => runSimulation('ddos')}>UDP FLOOD</button>
                            <button className="btn btn-danger btn-sm" onClick={() => runSimulation('ddos', { type: 'slowloris' })}>HTTP EXHAUST</button>
                         </div>
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Execution Console" icon={Terminal} subtitle="Tool standard output (STDOUT/STDERR)">
                   <pre className="terminal-output" style={{ height: '400px' }}>{simOutput || 'Awaiting simulation initialization...'}</pre>
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'eval' && (
            <motion.div key="eval" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '1.5rem' }}>
                <GlassCard title="Model Evaluation" icon={Fingerprint} subtitle="Offline dataset validation">
                   <div className="content-stack">
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Upload forensic CSV data to validate model performance against historical labels.</p>
                      <div style={{ border: '2px dashed var(--border)', borderRadius: '20px', padding: '3rem', textAlign: 'center', background: 'rgba(255,255,255,0.01)' }}>
                        <Upload size={32} className="text-muted" style={{ margin: '0 auto 1.5rem' }} />
                        <label className="btn btn-primary" style={{ display: 'inline-flex', margin: '0 auto' }}>
                          CHOOSE CSV DATASET
                          <input type="file" hidden onChange={handleFileUpload} accept=".csv" />
                        </label>
                        {evaluating && <p style={{ marginTop: '1rem', fontSize: '0.7rem', color: 'var(--primary)' }} className="pulse-fast">ANALYZING FEATURES...</p>}
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Validation Metrics" icon={BarChart3} subtitle="F1-Score, Accuracy, and Confusion Matrix">
                   {evalResult ? (
                     <div className="content-stack">
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '16px', textAlign: 'center' }}>
                            <div className="stat-label">Engine Accuracy</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 900, color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>{(evalResult.summary?.accuracy * 100).toFixed(1)}%</div>
                          </div>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '16px', textAlign: 'center' }}>
                            <div className="stat-label">Samples</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 900, fontFamily: 'var(--font-mono)' }}>{evalResult.summary?.total_samples}</div>
                          </div>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '16px', textAlign: 'center' }}>
                            <div className="stat-label">Model Hash</div>
                            <div style={{ fontSize: '0.7rem', fontWeight: 800, marginTop: '8px', opacity: 0.5 }}>{evalResult.summary?.model_version || 'SHA-256-UNK'}</div>
                          </div>
                        </div>
                        <div style={{ height: '250px' }}>
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={Object.entries(evalResult.metrics || {}).filter(([k]) => ['attack', 'normal', 'suspicious'].includes(k)).map(([name, m]) => ({ name, f1: m.f1_score || m['f1-score'] }))}>
                              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                              <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} />
                              <YAxis stroke="var(--text-muted)" fontSize={10} />
                              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)', borderRadius: '8px' }} />
                              <Bar dataKey="f1" fill="var(--primary)" radius={[6, 6, 0, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                     </div>
                   ) : (
                     <div style={{ height: '350px', display: 'flex', alignItems: 'center', justifyContent: 'center', opacity: 0.1 }}>
                        <BarChart3 size={64} />
                     </div>
                   )}
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'settings' && (
            <motion.div key="settings" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <GlassCard title="Neural Engine Control" icon={Cpu} subtitle="Hot-swappable inference models and scalers">
                   <div className="content-stack">
                      <div>
                        <label className="stat-label">Active Neural Model (.onnx)</label>
                        <select className="input-field" value={activeModel} onChange={e => setActiveModel(e.target.value)}>
                          {models.map(m => <option key={m} value={m}>{m}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="stat-label">Feature Scaler (.pkl)</label>
                        <select className="input-field" value={activeScaler} onChange={e => setActiveScaler(e.target.value)}>
                          {scalers.map(s => <option key={s} value={s}>{s}</option>)}
                        </select>
                      </div>
                      <div style={{ marginTop: '1rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border)' }}>
                        <button className="btn btn-primary" style={{ width: '100%' }} onClick={swapModel} disabled={swapping}>
                          {swapping ? <RefreshCcw className="animate-spin" size={16} /> : <Save size={16} />} APPLY ENGINE CONFIG
                        </button>
                        {saveStatus && (
                          <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '12px', background: saveStatus.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)', color: saveStatus.type === 'success' ? 'var(--success)' : 'var(--danger)', fontSize: '0.75rem', fontWeight: 800, textAlign: 'center' }}>
                            {saveStatus.msg}
                          </div>
                        )}
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Forensic Retention" icon={HardDrive} subtitle="Storage limits and PCAP logging policy">
                   <div className="content-stack">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <span className="stat-label">PCAP Recording</span>
                        <Badge variant={health?.pcap?.enabled ? 'success' : 'muted'}>{health?.pcap?.enabled ? 'ACTIVE' : 'INACTIVE'}</Badge>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <span className="stat-label">Forensic Storage</span>
                        <span style={{ fontWeight: 900, fontFamily: 'var(--font-mono)', color: 'var(--primary)' }}>{health?.pcap?.storage_used_mb?.toFixed(2) || 0} MB</span>
                      </div>
                      <div style={{ padding: '1rem', borderRadius: '12px', background: 'rgba(56, 189, 248, 0.05)', border: '1px solid var(--primary-glow)' }}>
                        <div style={{ display: 'flex', gap: '8px', color: 'var(--primary)', marginBottom: '8px' }}><Info size={14} /> <span style={{ fontSize: '0.65rem', fontWeight: 900 }}>RETENTION POLICY</span></div>
                        <p style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>Forensic buffers are pruned when storage exceeds 2.0GB or records exceed 168 hours of age. Emergency purging is active.</p>
                      </div>
                   </div>
                </GlassCard>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <footer style={{ marginTop: '4rem', padding: '1.5rem 0', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', opacity: 0.3, fontSize: '0.65rem', fontWeight: 800 }}>
          <span>SENTINEL CORE v3.1.2-STABLE // BUILD_ID: 2026.05.03</span>
          <span>© 2026 SENTINEL DEFENSE SYSTEMS</span>
        </footer>
      </main>

      {/* --- Node Intelligence Side Panel --- */}
      <AnimatePresence>
        {selectedIp && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedIp(null)} className="overlay-blur" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', zIndex: 1000 }} />
            <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', damping: 25, stiffness: 200 }} className="side-panel glass" style={{ position: 'fixed', top: 0, right: 0, width: '500px', height: '100vh', zIndex: 1001, padding: '2.5rem', overflowY: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3rem' }}>
                 <div>
                   <span style={{ fontSize: '0.6rem', fontWeight: 800, color: 'var(--text-muted)', letterSpacing: '0.2em', textTransform: 'uppercase' }}>Intelligence Report</span>
                   <h2 className="gradient-text" style={{ fontSize: '1.75rem', fontWeight: 900, marginBottom: '8px' }}>Node Analysis</h2>
                   <CompactIP ip={selectedIp} />
                 </div>
                 <button onClick={() => setSelectedIp(null)} className="btn-icon"><X size={24} /></button>
              </div>

              {loadingIntel ? (
                <div style={{ height: '400px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><RefreshCcw className="animate-spin text-primary" size={48} /></div>
              ) : nodeIntel ? (
                <div className="content-stack">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1.5rem', borderRadius: '20px', border: '1px solid var(--border)' }}>
                      <div className="stat-label" style={{ marginBottom: '8px' }}>Risk Score</div>
                      <div style={{ fontSize: '2rem', fontWeight: 900, color: (nodeIntel.reputation_score || 0) > 60 ? 'var(--danger)' : 'var(--success)', fontFamily: 'var(--font-mono)' }}>{nodeIntel.reputation_score || 0}%</div>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1.5rem', borderRadius: '20px', border: '1px solid var(--border)' }}>
                      <div className="stat-label" style={{ marginBottom: '8px' }}>Observations</div>
                      <div style={{ fontSize: '2rem', fontWeight: 900, fontFamily: 'var(--font-mono)' }}>{nodeIntel.alert_count || 0}</div>
                    </div>
                  </div>

                  <div style={{ height: '220px', background: 'rgba(0,0,0,0.2)', borderRadius: '20px', padding: '1.5rem', border: '1px solid var(--border)' }}>
                    <div className="stat-label" style={{ marginBottom: '1.5rem' }}>Verdict Distribution</div>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={Object.entries(nodeIntel.predictions || {}).map(([name, value]) => ({ name, value }))} cx="50%" cy="50%" innerRadius={45} outerRadius={65} paddingAngle={8} dataKey="value">
                          {Object.entries(nodeIntel.predictions || {}).map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)', borderRadius: '12px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <GlassCard title="Lateral Movement Risk" icon={Share2} subtitle="Nodes with similar behavioral signatures">
                    <div className="content-stack">
                      {nodeIntel.lateral_movement_risk?.length > 0 ? (
                        nodeIntel.lateral_movement_risk.map((node, idx) => (
                          <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(56, 189, 248, 0.05)', borderRadius: '12px', border: '1px solid rgba(56, 189, 248, 0.1)' }}>
                            <CompactIP ip={node.src_ip} onClick={() => fetchNodeIntel(node.src_ip)} />
                            <div style={{ display: 'flex', gap: '10px', fontSize: '0.7rem', fontWeight: 800 }}>
                              <span className="text-primary" title="Shared Signatures">{node.shared_sigs} SIGS</span>
                              <span className="text-muted">{node.total_alerts} ALERTS</span>
                            </div>
                          </div>
                        ))
                      ) : (
                        <p style={{ opacity: 0.5, fontSize: '0.7rem', textAlign: 'center' }}>No similar behavior detected.</p>
                      )}
                    </div>
                  </GlassCard>

                  <GlassCard title="Forensic Timeline" icon={History}>
                     <div className="timeline-mini" style={{ maxHeight: '300px', overflowY: 'auto', paddingRight: '5px' }}>
                        {nodeIntel.recent_activity?.map((entry, idx) => (
                          <div key={idx} className="timeline-item" style={{ borderLeft: '2px solid var(--border)', paddingLeft: '1.5rem', paddingBottom: '1.5rem', position: 'relative' }}>
                             <div style={{ position: 'absolute', left: '-5px', top: '0', width: '8px', height: '8px', borderRadius: '50%', background: entry.prediction === 'attack' ? 'var(--danger)' : 'var(--primary)', border: '2px solid var(--bg-dark)' }} />
                             <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontWeight: 800, marginBottom: '4px' }}>{new Date(entry.timestamp).toLocaleString()}</div>
                             <div style={{ fontSize: '0.75rem', fontWeight: 800, display: 'flex', justifyContent: 'space-between' }}>
                               <span>{entry.alert_sig || 'General Traffic'}</span>
                               <span style={{ color: entry.prediction === 'attack' ? 'var(--danger)' : 'var(--success)' }}>{entry.prediction.toUpperCase()}</span>
                             </div>
                             {entry.mitigation && <div style={{ fontSize: '0.65rem', marginTop: '4px', opacity: 0.7 }}>Action: <span className="text-primary">{entry.mitigation}</span></div>}
                          </div>
                        ))}
                     </div>
                  </GlassCard>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1rem' }}>
                    {nodeIntel.is_mitigated ? (
                      <button className="btn btn-secondary" style={{ width: '100%' }} onClick={() => blockAction(selectedIp, 'unblock')}><Unlock size={16} /> WHITELIST</button>
                    ) : (
                      <button className="btn btn-danger" style={{ width: '100%' }} onClick={() => blockAction(selectedIp, 'block')}><Shield size={16} /> BLOCK HOST</button>
                    )}
                    <button className="btn btn-primary" style={{ width: '100%' }} onClick={() => downloadPcap(nodeIntel.alert_id || 'latest')}><Download size={16} /> PCAP SNIPPET</button>
                  </div>
                </div>
              ) : <div style={{ textAlign: 'center', padding: '3rem', opacity: 0.5 }}><History size={48} style={{ margin: '0 auto 1rem' }} /><p>Error retrieving forensic data.</p></div>}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}

export default App;
