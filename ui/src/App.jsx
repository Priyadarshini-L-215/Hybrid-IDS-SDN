import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Activity, Zap, Database, Terminal, Settings, 
  AlertTriangle, CheckCircle2, Server, Globe, Lock, Unlock,
  Cpu, RefreshCcw, Search, Filter, ArrowRight, Play, StopCircle, 
  Clock, ExternalLink, Info, ChevronDown, FileText, Upload, 
  Link, BarChart3, Network, Share2, Eye, Trash2, Bug, 
  HardDrive, Target, Flame, ShieldCheck, Radio, Layers, 
  Fingerprint, RotateCcw, Save, Key, X, MapPin, History
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

const GlassCard = ({ children, className = '', title, icon: Icon, actions, subtitle }) => (
  <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className={`glass-card ${className}`}>
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

// --- MAIN APPLICATION ---
function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [connected, setConnected] = useState(false);
  const [health, setHealth] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ processed_total: 0, attacks: 0, normal: 0 });
  const [chartData, setChartData] = useState([]);
  const [latency, setLatency] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);

  // Configuration
  const [config, setConfig] = useState(null);
  const [saveStatus, setSaveStatus] = useState(null);

  // Simulation
  const [scanTarget, setScanTarget] = useState('127.0.0.1');
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

  const ws = useRef(null);
  const statsRef = useRef({ processed_total: 0, attacks: 0, normal: 0 });

  // --- DERIVED DATA ---
  const graphData = useMemo(() => {
    const nodes = new Map();
    const links = [];
    const maxNodes = 40;

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
  const lastStatsRef = useRef({ processed: 0, attacks: 0 });

  // --- API CALLS ---
  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/pipeline/status');
      setHealth(await res.json());
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
      setNodeIntel(await res.json());
    } catch (e) { console.error("Intel fetch failed", e); } finally { setLoadingIntel(false); }
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
          const isAttack = a.prediction?.toLowerCase().includes('attack');
          acc.processed += 1;
          if (isAttack) acc.attacks += 1;
          else acc.normal += 1;
          return acc;
        }, { processed: 0, attacks: 0, normal: 0 });

        setStats(prev => ({
          processed_total: prev.processed_total + batchStats.processed,
          attacks: prev.attacks + batchStats.attacks,
          normal: prev.normal + batchStats.normal
        }));

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

      <header className="header-section">
        <div className="title-group">
          <h1>
            <Shield className="text-primary pulse" size={32} />
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span className="gradient-text">SENTINEL</span>
              <span style={{ color: 'var(--text-muted)', fontWeight: 800, fontSize: '0.65rem', letterSpacing: '0.3em' }}>HYBRID IDS/IPS OS</span>
            </div>
          </h1>
        </div>

        <nav className="tabs-navigation">
          {[
            { id: 'overview', label: 'Overview', icon: Activity },
            { id: 'visual', label: 'Visual Intelligence', icon: Network },
            { id: 'mitigation', label: 'Policy & Mitigation', icon: ShieldCheck },
            { id: 'lab', label: 'Simulation', icon: Target },
            { id: 'eval', label: 'Evaluation', icon: Fingerprint },
            { id: 'settings', label: 'Settings', icon: Settings }
          ].map(tab => (
            <button key={tab.id} className={`tab-button ${activeTab === tab.id ? 'active' : ''}`} onClick={() => setActiveTab(tab.id)}>
              <tab.icon size={16} /> {tab.label}
            </button>
          ))}
        </nav>

        <div className="status-container">
          <div className="status-hover-wrapper" style={{ cursor: 'pointer' }}>
            <Badge variant={connected ? 'success' : 'danger'}>{connected ? 'CORE ONLINE' : 'OFFLINE'}</Badge>
            <div className="engine-tooltip glass">
              <div style={{ marginBottom: '1rem', fontWeight: 900, fontSize: '0.65rem', color: 'var(--primary)', letterSpacing: '0.1em' }}>SYSTEM INTEGRITY</div>
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
              <div style={{ marginTop: '1rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border)', fontSize: '0.6rem', color: 'var(--text-muted)' }}>
                Queue Depth: {health?.queue_depth || 0} events
              </div>
            </div>
          </div>
        </div>
      </header>

      <div className="stats-grid">
        <StatCard label="Ingested Events" value={stats.processed_total?.toLocaleString()} icon={Database} />
        <StatCard label="Threats Detected" value={stats.attacks?.toLocaleString()} icon={Flame} color="var(--danger)" />
        <StatCard label="Inference Latency" value={`${latency.toFixed(2)}ms`} icon={Zap} color="var(--primary)" />
        <StatCard label="Mitigated Hosts" value={health?.ipset?.permanent || 0} icon={Shield} color="var(--success)" />
      </div>

      <main className="main-layout">
        <AnimatePresence mode="wait">
          {activeTab === 'overview' && (
            <motion.div key="overview" className="content-stack" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
              <GlassCard title="Network Behavior Analytics" icon={Activity} subtitle="Live threat vector analysis">
                <div style={{ height: '220px', width: '100%' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={chartData}>
                      <defs>
                        <linearGradient id="cNormal" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--success)" stopOpacity={0.2}/><stop offset="95%" stopColor="var(--success)" stopOpacity={0}/></linearGradient>
                        <linearGradient id="cAttack" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="var(--danger)" stopOpacity={0.2}/><stop offset="95%" stopColor="var(--danger)" stopOpacity={0}/></linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                      <XAxis dataKey="time" hide />
                      <YAxis stroke="rgba(255,255,255,0.1)" fontSize={10} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ background: 'rgba(2, 6, 23, 0.95)', border: '1px solid var(--border)', borderRadius: '8px' }} />
                      <Area type="monotone" dataKey="normal" stroke="var(--success)" fill="url(#cNormal)" strokeWidth={2} isAnimationActive={false} />
                      <Area type="monotone" dataKey="attacks" stroke="var(--danger)" fill="url(#cAttack)" strokeWidth={2} isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </GlassCard>

              <div className="table-container glass">
                <div className="table-header"><div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}><Terminal size={18} className="text-primary" /><span className="gradient-text" style={{ fontWeight: 800 }}>LIVE INTELLIGENCE STREAM</span></div></div>
                <div className="table-scroller" style={{ maxHeight: '550px', overflowY: 'auto' }}>
                  <table className="alerts-table">
                    <thead><tr><th>Time</th><th>Source Node</th><th>Destination</th><th>Proto</th><th>Classification</th><th>Confidence</th><th>Mitigation</th></tr></thead>
                    <tbody>
                      {alerts.map((alert, i) => {
                        const isAttack = alert.prediction?.toLowerCase().includes('attack');
                        const isSuspicious = alert.prediction?.toLowerCase().includes('suspicious');
                        return (
                          <React.Fragment key={alert.event_id || i}>
                            <tr className={`alert-row ${isAttack ? 'alert-row-danger' : isSuspicious ? 'alert-row-warning' : ''}`} onClick={() => setExpandedRow(expandedRow === i ? null : i)}>
                              <td className="ip-address" style={{ fontSize: '0.7rem', opacity: 0.6 }}>{formatTimestamp(alert.timestamp)}</td>
                              <td className="ip-address" onClick={(e) => { e.stopPropagation(); fetchNodeIntel(alert.src_ip); }}>{alert.src_ip}</td>
                              <td className="ip-address">{alert.dst_ip || '---'}:{alert.dst_port || ''}</td>
                              <td style={{ fontSize: '0.65rem', fontWeight: 900, opacity: 0.8 }}>{alert.protocol?.toUpperCase()}</td>
                              <td>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <Badge variant={isAttack ? 'danger' : isSuspicious ? 'warning' : 'success'}>{alert.prediction}</Badge>
                                    {alert.duplicate_count > 1 && (
                                      <span className="badge-count" style={{ background: 'var(--primary)', color: 'white', padding: '1px 6px', borderRadius: '10px', fontSize: '0.6rem', fontWeight: 900 }}>
                                        ×{alert.duplicate_count}
                                      </span>
                                    )}
                                  </div>
                                  {alert.mitre && (
                                    <div style={{ display: 'flex', gap: '4px' }}>
                                      <span style={{ fontSize: '0.55rem', opacity: 0.7, background: 'rgba(255,255,255,0.05)', padding: '2px 4px', borderRadius: '4px', border: '1px solid var(--border)' }}>{alert.mitre.id}</span>
                                      <span style={{ fontSize: '0.55rem', opacity: 0.7, color: 'var(--primary)' }}>{alert.mitre.tactic}</span>
                                    </div>
                                  )}
                                </div>
                              </td>
                              <td style={{ fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{alert.confidence}%</td>
                              <td><div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>{alert.is_mitigated ? <Lock size={12} className="text-danger" /> : <Unlock size={12} className="text-muted" />}<span style={{ fontSize: '0.65rem', fontWeight: 800 }}>{alert.mitigation || 'PASSIVE'}</span></div></td>
                            </tr>
                            {expandedRow === i && (
                              <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                                <td colSpan="7" style={{ padding: '1.5rem' }}>
                                   <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1fr 1fr', gap: '2rem' }}>
                                      <div>
                                        <h4 style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Decision Matrix</h4>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}><span className="text-muted">Signature Layer</span><span>{alert.forensics?.stage_scores?.signature ? 'DETECTED' : 'CLEAN'}</span></div>
                                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}><span className="text-muted">Neural Confidence</span><span>{(alert.forensics?.stage_scores?.ml * 100).toFixed(1)}%</span></div>
                                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}><span className="text-muted">Anomaly Magnitude</span><span>{(alert.forensics?.stage_scores?.anomaly * 100).toFixed(1)}%</span></div>
                                          <div style={{ height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', marginTop: '4px' }}>
                                            <div style={{ height: '100%', width: `${alert.confidence}%`, background: 'var(--primary)', boxShadow: '0 0 10px var(--primary-glow)' }} />
                                          </div>
                                        </div>
                                      </div>
                                      <div>
                                        <h4 style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Explainability (SHAP)</h4>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                          {alert.shap_top3 && alert.shap_top3.length > 0 ? alert.shap_top3.map((item, idx) => (
                                            <div key={idx} style={{ fontSize: '0.65rem' }}>
                                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                                                <span className="text-muted" style={{ textTransform: 'capitalize' }}>{item.feature.replace(/_/g, ' ')}</span>
                                                <span className="text-primary">{item.impact > 0.1 ? 'High Impact' : 'Medium'}</span>
                                              </div>
                                              <div style={{ height: '3px', background: 'rgba(255,255,255,0.05)', borderRadius: '1.5px' }}>
                                                <div style={{ height: '100%', width: `${Math.min(item.impact * 200, 100)}%`, background: 'var(--primary)' }} />
                                              </div>
                                            </div>
                                          )) : <span className="text-muted" style={{ fontSize: '0.7rem' }}>No explanation data available.</span>}
                                        </div>
                                      </div>
                                      <div>
                                        <h4 style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Enrichment</h4>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', fontSize: '0.75rem' }}>
                                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Globe size={12} className="text-muted" /> {alert.enrichment?.location || 'Unknown'}</div>
                                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Network size={12} className="text-muted" /> {alert.enrichment?.asn || 'Internal'}</div>
                                          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Info size={12} className="text-muted" /> {alert.alert_sig || 'Generic Flow'}</div>
                                        </div>
                                      </div>
                                      <div>
                                        <h4 style={{ fontSize: '0.65rem', textTransform: 'uppercase', color: 'var(--primary)', marginBottom: '0.75rem', letterSpacing: '0.1em' }}>Actions</h4>
                                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                          {alert.is_mitigated ? (
                                            <button className="btn btn-secondary btn-sm" onClick={(e) => { e.stopPropagation(); blockAction(alert.src_ip, 'unblock'); }}>WHITELIST NODE</button>
                                          ) : (
                                            <button className="btn btn-danger btn-sm" onClick={(e) => { e.stopPropagation(); blockAction(alert.src_ip, 'block'); }}>BLOCK IMMEDIATELY</button>
                                          )}
                                          <button className="btn btn-primary btn-sm" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }} onClick={(e) => { e.stopPropagation(); downloadPcap(alert.event_id); }}>
                                            <FileText size={14} /> DOWNLOAD PCAP
                                          </button>
                                        </div>
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
            </motion.div>
          )}
          
          {activeTab === 'visual' && (
            <motion.div key="visual" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
               <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '2rem' }}>
                  <GlassCard title="Global Threat Vector Map" icon={Globe} subtitle="Real-time geographic source of detections">
                    <div style={{ height: '500px', background: 'rgba(0,0,0,0.2)', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                      <ComposableMap projectionConfig={{ scale: 140 }}>
                        <Geographies geography={geoUrl}>
                          {({ geographies }) =>
                            geographies.map((geo) => (
                              <Geography
                                key={geo.rsmKey}
                                geography={geo}
                                fill="var(--bg-card)"
                                stroke="var(--border)"
                                strokeWidth={0.5}
                                style={{
                                  default: { outline: "none" },
                                  hover: { fill: "var(--primary-glow)", outline: "none" },
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
                              animate={{ r: [4, 12, 4], opacity: [1, 0.4, 1] }}
                              transition={{ repeat: Infinity, duration: 2 }}
                              fill={isAttack ? "var(--danger)" : "var(--primary)"}
                              stroke="#fff"
                              strokeWidth={1}
                            />
                            <text
                              textAnchor="middle"
                              y={-15}
                              style={{ fontFamily: "inherit", fill: "var(--text-secondary)", fontSize: "8px", pointerEvents: 'none' }}
                            >
                              {name}
                            </text>
                          </Marker>
                        ))}
                      </ComposableMap>
                    </div>
                  </GlassCard>

                  <GlassCard title="Network Topology" icon={Network} subtitle="Live flow relationship graph">
                    <div style={{ height: '500px', background: 'rgba(0,0,0,0.2)', borderRadius: '12px', overflow: 'hidden', border: '1px solid var(--border)' }}>
                       <ForceGraph2D
                          graphData={graphData}
                          width={450}
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
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                <GlassCard title="Active Blocklist" icon={ShieldCheck} subtitle="Permanently and temporarily blocked IPs">
                   <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      <div style={{ marginBottom: '1.5rem' }}>
                        <div className="stat-label" style={{ marginBottom: '0.5rem', color: 'var(--danger)' }}>Permanent Blocks ({health?.ipset_detailed?.permanent_ips?.length || 0})</div>
                        {health?.ipset_detailed?.permanent_ips?.map(ip => (
                          <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(244, 63, 94, 0.05)', borderRadius: '8px', marginBottom: '8px', border: '1px solid rgba(244, 63, 94, 0.1)' }}>
                             <span className="ip-address" onClick={() => fetchNodeIntel(ip)} style={{ cursor: 'pointer' }}>{ip}</span>
                             <button className="btn-icon text-danger" onClick={() => blockAction(ip, 'unblock')}><Unlock size={14} /></button>
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="stat-label" style={{ marginBottom: '0.5rem', color: 'var(--warning)' }}>Temporary Blocks ({health?.ipset_detailed?.temporary_ips?.length || 0})</div>
                        {health?.ipset_detailed?.temporary_ips?.map(ip => (
                          <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(245, 158, 11, 0.05)', borderRadius: '8px', marginBottom: '8px' }}>
                             <span className="ip-address" onClick={() => fetchNodeIntel(ip)} style={{ cursor: 'pointer' }}>{ip}</span>
                             <button className="btn-icon text-muted" onClick={() => blockAction(ip, 'unblock')}><Unlock size={14} /></button>
                          </div>
                        ))}
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Reputation Leaderboard" icon={BarChart3} subtitle="Highest risk nodes by reputation score">
                   <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                      {Object.entries(health?.ipset_detailed?.reputation || {})
                        .sort(([, a], [, b]) => b - a)
                        .slice(0, 15)
                        .map(([ip, score]) => (
                          <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', marginBottom: '8px' }}>
                             <span className="ip-address" onClick={() => fetchNodeIntel(ip)} style={{ cursor: 'pointer' }}>{ip}</span>
                             <span style={{ fontWeight: 900, color: score > 50 ? 'var(--danger)' : 'var(--text-secondary)' }}>{score.toFixed(1)}</span>
                          </div>
                        ))
                      }
                   </div>
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'lab' && (
            <motion.div key="lab" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '2rem' }}>
                <GlassCard title="Simulation Lab" icon={Flame} subtitle="Nmap Scanning and DDoS Traffic Test">
                   <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                      <div><label className="stat-label">Target IPv4</label><input type="text" className="input-field" value={scanTarget} onChange={e => setScanTarget(e.target.value)} /></div>
                      <div>
                         <label className="stat-label">Nmap Profiles</label>
                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', marginTop: '8px' }}>
                            {['quick', 'ping', 'service', 'os_detect', 'aggressive', 'vuln'].map(p => (
                              <button key={p} className={`btn btn-secondary btn-sm ${scanProfile === p ? 'btn-primary' : ''}`} onClick={() => setScanProfile(p)}>{p.toUpperCase()}</button>
                            ))}
                         </div>
                         <button className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }} onClick={() => runSimulation('nmap', { profile: scanProfile })} disabled={simulating}>RUN NMAP SCAN</button>
                      </div>
                      <div style={{ paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                         <label className="stat-label">Attack Simulations</label>
                         <p style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>Note: These actions generate real malicious traffic packets.</p>
                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                            <button className="btn btn-danger btn-sm" onClick={() => runSimulation('ddos')}>UDP/SYN FLOOD</button>
                            <button className="btn btn-danger btn-sm" onClick={() => runSimulation('ddos', { type: 'slowloris' })}>HTTP EXHAUST</button>
                         </div>
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Execution Output" icon={Terminal} subtitle="Real-time tool logs">
                   <pre className="terminal-output" style={{ height: '350px' }}>{simOutput || 'Awaiting simulation trigger...'}</pre>
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'eval' && (
            <motion.div key="eval" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.5fr', gap: '2rem' }}>
                <GlassCard title="Evaluation Lab" icon={Fingerprint} subtitle="Validate datasets against engine">
                   <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Upload a CSV dataset with standard features to run batch inference and generate performance metrics.</p>
                      <div style={{ border: '2px dashed var(--border)', borderRadius: '16px', padding: '2rem', textAlign: 'center' }}>
                        <Upload size={32} className="text-muted" style={{ margin: '0 auto 1rem' }} />
                        <label className="btn btn-secondary" style={{ display: 'inline-flex', margin: '0 auto' }}>
                          CHOOSE CSV FILE
                          <input type="file" hidden onChange={handleFileUpload} accept=".csv" />
                        </label>
                        {evaluating && <p style={{ marginTop: '1rem', fontSize: '0.7rem' }}>Processing batch inference...</p>}
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Performance Report" icon={BarChart3} subtitle="Model validation results">
                   {evalResult ? (
                     <div className="content-stack">
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '12px', textAlign: 'center' }}>
                            <div className="stat-label">Accuracy</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 900, color: 'var(--primary)' }}>{(evalResult.summary?.accuracy * 100).toFixed(1)}%</div>
                          </div>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '12px', textAlign: 'center' }}>
                            <div className="stat-label">Total Samples</div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 900 }}>{evalResult.summary?.total_samples}</div>
                          </div>
                          <div className="glass" style={{ padding: '1rem', borderRadius: '12px', textAlign: 'center' }}>
                            <div className="stat-label">Version</div>
                            <div style={{ fontSize: '1rem', fontWeight: 900, marginTop: '8px' }}>{evalResult.summary?.model_version}</div>
                          </div>
                        </div>
                        <div style={{ height: '200px' }}>
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={Object.entries(evalResult.metrics || {}).filter(([k]) => ['attack', 'normal', 'suspicious'].includes(k)).map(([name, m]) => ({ name, f1: m.f1_score || m['f1-score'] }))}>
                              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.03)" vertical={false} />
                              <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} />
                              <YAxis stroke="var(--text-muted)" fontSize={10} />
                              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)' }} />
                              <Bar dataKey="f1" fill="var(--primary)" radius={[4, 4, 0, 0]} />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>
                     </div>
                   ) : (
                     <div style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center', opacity: 0.2 }}>
                        <BarChart3 size={48} />
                     </div>
                   )}
                </GlassCard>
              </div>
            </motion.div>
          )}

          {activeTab === 'settings' && (
            <motion.div key="settings" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                <GlassCard title="ML Engine Control" icon={Cpu} subtitle="Neural inference configuration">
                   <div className="content-stack">
                      <div className="input-group">
                        <label className="stat-label">Active Neural Model (.onnx)</label>
                        <select className="input-field" value={activeModel} onChange={e => setActiveModel(e.target.value)}>
                          {models.map(m => <option key={m} value={m}>{m}</option>)}
                        </select>
                      </div>
                      <div className="input-group">
                        <label className="stat-label">Feature Scaler (.pkl)</label>
                        <select className="input-field" value={activeScaler} onChange={e => setActiveScaler(e.target.value)}>
                          {scalers.map(s => <option key={s} value={s}>{s}</option>)}
                        </select>
                      </div>
                      <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
                        <button className="btn btn-primary" style={{ width: '100%' }} onClick={swapModel} disabled={swapping}>
                          {swapping ? <RefreshCcw className="animate-spin" size={16} /> : 'APPLY ENGINE CONFIG'}
                        </button>
                        {saveStatus && (
                          <div style={{ marginTop: '1rem', padding: '0.75rem', borderRadius: '8px', background: saveStatus.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(244, 63, 94, 0.1)', color: saveStatus.type === 'success' ? 'var(--success)' : 'var(--danger)', fontSize: '0.7rem', fontWeight: 800 }}>
                            {saveStatus.msg}
                          </div>
                        )}
                      </div>
                   </div>
                </GlassCard>
                <GlassCard title="Forensic Retention" icon={HardDrive} subtitle="Storage & Logging policy">
                   <div className="content-stack">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="stat-label">PCAP Recording</span>
                        <Badge variant={health?.pcap?.enabled ? 'success' : 'muted'}>{health?.pcap?.enabled ? 'ENABLED' : 'DISABLED'}</Badge>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="stat-label">Storage Used</span>
                        <span style={{ fontWeight: 800 }}>{health?.pcap?.storage_used_mb?.toFixed(2) || 0} MB</span>
                      </div>
                      <p style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>Forensic buffers are automatically pruned when storage exceeds 2GB or records are older than 7 days.</p>
                   </div>
                </GlassCard>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* --- Node Intelligence Side Panel --- */}
      <AnimatePresence>
        {selectedIp && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={() => setSelectedIp(null)} className="overlay-blur" style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)', zIndex: 1000 }} />
            <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={{ type: 'spring', damping: 25, stiffness: 200 }} className="side-panel glass" style={{ position: 'fixed', top: 0, right: 0, width: '480px', height: '100vh', zIndex: 1001, padding: '2.5rem', overflowY: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2.5rem' }}>
                 <div>
                   <h2 className="gradient-text" style={{ fontSize: '1.5rem', fontWeight: 900 }}>Node Intelligence</h2>
                   <p className="ip-address" style={{ fontSize: '1rem', marginTop: '4px' }}>{selectedIp}</p>
                 </div>
                 <button onClick={() => setSelectedIp(null)} className="btn-icon"><X size={24} /></button>
              </div>

              {loadingIntel ? (
                <div style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><RefreshCcw className="animate-spin" size={32} /></div>
              ) : nodeIntel ? (
                <div className="content-stack">
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1.5rem', borderRadius: '16px', border: '1px solid var(--border)' }}>
                      <div className="stat-label">Reputation</div>
                      <div style={{ fontSize: '1.75rem', fontWeight: 900, color: (nodeIntel.reputation_score || 0) > 60 ? 'var(--danger)' : 'var(--success)' }}>{nodeIntel.reputation_score || 0}/100</div>
                    </div>
                    <div style={{ background: 'rgba(255,255,255,0.03)', padding: '1.5rem', borderRadius: '16px', border: '1px solid var(--border)' }}>
                      <div className="stat-label">Alert Count</div>
                      <div style={{ fontSize: '1.75rem', fontWeight: 900 }}>{nodeIntel.alert_count || 0}</div>
                    </div>
                  </div>

                  <div style={{ height: '200px', background: 'rgba(0,0,0,0.2)', borderRadius: '16px', padding: '1rem' }}>
                    <div className="stat-label" style={{ marginBottom: '1rem' }}>Verdict Distribution</div>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={Object.entries(nodeIntel.predictions || {}).map(([name, value]) => ({ name, value }))} cx="50%" cy="50%" innerRadius={40} outerRadius={60} paddingAngle={5} dataKey="value">
                          {Object.entries(nodeIntel.predictions || {}).map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <GlassCard title="Top Signatures" icon={Target}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {nodeIntel.top_signatures?.slice(0, 3).map((sig, idx) => (
                        <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                          <span className="text-muted" style={{ maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sig[0]}</span>
                          <span style={{ fontWeight: 800 }}>{sig[1]}</span>
                        </div>
                      )) || <p style={{ opacity: 0.5, fontSize: '0.7rem' }}>No signatures recorded.</p>}
                    </div>
                  </GlassCard>

                  <div style={{ display: 'flex', gap: '1rem' }}>
                    {nodeIntel.is_mitigated ? (
                      <button className="btn btn-secondary" style={{ flex: 1 }} onClick={() => blockAction(selectedIp, 'unblock')}>WHITELIST NODE</button>
                    ) : (
                      <button className="btn btn-danger" style={{ flex: 1 }} onClick={() => blockAction(selectedIp, 'block')}>BLOCK HOST</button>
                    )}
                  </div>
                </div>
              ) : <p>Error loading intel.</p>}
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <footer style={{ marginTop: '3rem', padding: '1.5rem 0', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', opacity: 0.4, fontSize: '0.7rem' }}>
        <span>SENTINEL CORE HYBRID v3.1.2-STABLE</span><span>© 2026 SENTINEL DEFENSE SYSTEMS</span>
      </footer>
    </div>
  );
}

export default App;
