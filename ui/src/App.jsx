import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Activity, Zap, Database, Terminal, Settings, 
  AlertTriangle, CheckCircle2, Server, Globe, Lock, Unlock, Home,
  Cpu, RefreshCcw, Search, Filter, ArrowRight, Play, StopCircle, 
  Clock, ExternalLink, Info, ChevronDown, FileText, Upload, 
  Link, BarChart3, Network, Share2, Eye, Trash2, Bug, 
  HardDrive, Target, Flame, ShieldCheck, Radio, Layers, 
  Fingerprint, RotateCcw, Save, Key, X, MapPin, History, Download,
  PieChart as PieChartIcon
} from 'lucide-react';
import { 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar
} from 'recharts';

// Custom hooks and utilities
import { useAlertStream } from './hooks/useAlertStream';
import { useHealthStatus } from './hooks/useHealthStatus';
import { useStats } from './hooks/useStats';
import ErrorBoundary from './components/ErrorBoundary';
import ShapPanel from './components/ShapPanel';
import { apiClient } from './utils/apiClient';

import './App.css';

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
const toLowerText = (value) => String(value ?? '').toLowerCase();
const containsText = (value, query) => toLowerText(value).includes(toLowerText(query));
const toUpperText = (value, fallback = '') => (value == null ? fallback : String(value).toUpperCase());

const getFlagEmoji = (countryCode) => {
  if (!countryCode || countryCode === 'Unknown') return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char =>  127397 + char.charCodeAt());
  try {
    return String.fromCodePoint(...codePoints);
  } catch (e) { return '🌐'; }
};

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

const StatCard = ({ label, value, icon: Icon, color = 'var(--primary)', subtitle, isLoading }) => (
  <div className="glass-card stat-card" style={{ '--card-accent': color }}>
    <div className="stat-icon-wrapper" style={{ background: `${color}15` }}>
      <Icon size={20} style={{ color }} />
    </div>
    <div className="stat-content">
      <div className="stat-label">{label}</div>
      <div className="stat-value-large">
        {isLoading ? <span className="stat-loading-pulse">---</span> : (value || "---")}
      </div>
      {subtitle && <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontWeight: 800, marginTop: '4px' }}>{subtitle}</div>}
    </div>
  </div>
);

const CompactIP = ({ ip, onClick, type }) => {
  if (type === 'system_alert') return <span className="text-muted" style={{ fontSize: '0.7rem', letterSpacing: '1px' }}>SYSTEM</span>;
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
  // ===== CUSTOM HOOKS (State Management) =====
  const { alerts, updateAlert, isConnected, bufferSize } = useAlertStream();
  const { health, isHealthy, refresh: refreshHealth } = useHealthStatus();
  const { stats, chartData } = useStats(alerts);

  // ===== UI STATE ONLY =====
  const [activeTab, setActiveTab] = useState(() => localStorage.getItem('sentinel_active_tab') || 'overview');
  
  useEffect(() => {
    localStorage.setItem('sentinel_active_tab', activeTab);
  }, [activeTab]);
  const [latency, setLatency] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);

  /**
   * Toggles alert expansion and lazy-loads full forensic data (raw_event, enrichment)
   * if not already present (e.g., received via trimmed WebSocket broadcast).
   */
  const toggleExpandRow = async (alert) => {
    const eid = alert.event_id;
    const isExpanding = expandedRow !== eid;
    
    setExpandedRow(isExpanding ? eid : null);
    
    if (isExpanding && !alert.raw_event && alert.id) {
      try {
        const fullAlert = await apiClient.get(`/api/alerts/${alert.id}`);
        if (fullAlert) {
          updateAlert(fullAlert);
        }
      } catch (err) {
        console.error("Failed to lazy load alert detail", err);
      }
    }
  };

  // Configuration
  const [saveStatus, setSaveStatus] = useState(null);

  // Simulation
  const [scanTarget, setScanTarget] = useState('');
  const [scanProfile, setScanProfile] = useState('quick');
  const [simulating, setSimulating] = useState(false);
  const [simOutput, setSimOutput] = useState('');
  const simConsoleRef = useRef(null);

  // Auto-scroll simulation console
  useEffect(() => {
    if (simConsoleRef.current) {
      simConsoleRef.current.scrollTop = simConsoleRef.current.scrollHeight;
    }
  }, [simOutput]);



  // Model Control (Settings)
  const [models, setModels] = useState([]);
  const [scalers, setScalers] = useState([]);
  const [activeModel, setActiveModel] = useState('');
  const [activeScaler, setActiveScaler] = useState('');
  const [swapping, setSwapping] = useState(false);
  const [modelsLoading, setModelsLoading] = useState(false);
  const [baselineStatus, setBaselineStatus] = useState(null);

  // Node Intel
  const [selectedIp, setSelectedIp] = useState(null);
  const [nodeIntel, setNodeIntel] = useState(null);
  const [loadingIntel, setLoadingIntel] = useState(false);

  // Manual Mitigation
  const [manualIp, setManualIp] = useState('');

  // Search & Filtering
  const [filterQuery, setFilterQuery] = useState('');
  const [filterLevel, setFilterLevel] = useState('ALL');

  // Operational Monitoring
  const [systemLogs, setSystemLogs] = useState([{ ts: new Date().toISOString(), msg: 'Sentinel Core UI Initialized' }]);
  
  const addLog = (msg) => {
    setSystemLogs(prev => [{ ts: new Date().toISOString(), msg }, ...prev].slice(0, 50));
  };

  // --- DERIVED DATA ---
  
  // 1. SHAP Feature Importance aggregation from last 50 alerts
  const shapAggregated = useMemo(() => {
    const stats = {};
    const attackAlerts = alerts.filter(a => {
      const pred = (a.prediction || "").toLowerCase();
      return pred.includes("attack") || pred.includes("anomaly") || pred.includes("suspicious");
    });

    attackAlerts.slice(0, 50).forEach(a => {
      let tops = a.shap_top3 || [];
      if (typeof tops === 'string') {
        try { tops = JSON.parse(tops); } catch (e) { tops = []; }
      }
      
      if (Array.isArray(tops)) {
        tops.forEach(t => {
          const name = t.feature || (Array.isArray(t) ? t[0] : null);
          const impact = typeof t.impact === 'number' ? t.impact : (typeof t.value === 'number' ? t.value : (Array.isArray(t) ? t[1] : 0));
          if (name) {
            if (!stats[name]) stats[name] = { sum: 0, count: 0 };
            stats[name].sum += Math.abs(impact);
            stats[name].count += 1;
          }
        });
      }
    });
    
    return Object.entries(stats)
      .map(([name, s]) => ({ name, hits: s.count, impact: s.sum / s.count }))
      .sort((a, b) => b.impact - a.impact)
      .slice(0, 8);
  }, [alerts]);

  // 2. Attack Severity Donut
  const severityStats = useMemo(() => {
    const counts = { attack: 0, suspicious: 0, normal: 0 };
    alerts.forEach(a => {
      const p = toLowerText(a.prediction);
      if (p.includes('attack') || p.includes('anomaly')) counts.attack++;
      else if (p.includes('suspicious')) counts.suspicious++;
      else counts.normal++;
    });
    return [
      { name: 'ATTACK', value: counts.attack, color: 'var(--danger)' },
      { name: 'SUSPICIOUS', value: counts.suspicious, color: 'var(--warning)' },
      { name: 'NORMAL', value: counts.normal, color: 'var(--success)' }
    ].filter(d => d.value > 0);
  }, [alerts]);

  // 3. Top Attacker Leaderboard
  const topAttackers = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const p = toLowerText(a.prediction);
      if (p.includes('attack') || p.includes('anomaly')) {
        counts[a.src_ip] = (counts[a.src_ip] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [alerts]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const matchesQuery = !filterQuery || 
        containsText(a.src_ip, filterQuery) || 
        containsText(a.prediction, filterQuery) ||
        containsText(a.protocol, filterQuery);
      
      const matchesLevel = filterLevel === 'ALL' || 
        (filterLevel === 'ATTACKS' && (containsText(a.prediction, 'attack') || containsText(a.prediction, 'anomaly'))) ||
        (filterLevel === 'SUSPICIOUS' && containsText(a.prediction, 'suspicious')) ||
        (filterLevel === 'NORMAL' && containsText(a.prediction, 'normal'));
        
      return matchesQuery && matchesLevel;
    });
  }, [alerts, filterQuery, filterLevel]);

  const lastStatsRef = useRef({ processed: 0, attacks: 0 });

  // --- API CALLS (Simplified with apiClient & hooks) ---
  const fetchNodeIntel = async (ip) => {
    if (!ip || ip === '---') return;
    setSelectedIp(ip);
    setLoadingIntel(true);
    setNodeIntel(null);
    try {
      // Use the new forensics IP endpoint for detailed timeline
      const data = await apiClient.get(`/api/forensics/ip/${ip}`);
      setNodeIntel(data);
      addLog(`Forensics: Reconstructed trail for ${ip} (${data.history?.length || 0} events)`);
    } catch (e) { 
      apiClient.handleError(e, `Failed to fetch forensics for ${ip}`);
      addLog(`Error: Forensic analysis failed for ${ip}`);
    } finally { 
      setLoadingIntel(false); 
    }
  };

  const runSimulation = async (type, payload = {}) => {
    setSimulating(true);
    setSimOutput(`> Starting ${type.toUpperCase()} simulation...\n`);
    try {
      const endpoint = type === 'nmap' ? '/api/simulation/nmap/scan' : '/api/simulation/attack/ddos';
      const data = await apiClient.post(endpoint, { target: scanTarget, ...payload });
      setSimOutput(prev => prev + (data.raw_output || data.message || data.error || 'Done.'));
    } catch (e) { 
      setSimOutput(prev => prev + `[ERROR] ${e.message}`);
    } finally { 
      setSimulating(false); 
    }
  };



  const blockAction = async (ip, action) => {
    try {
      await apiClient.post(`/api/mitigation/${action}`, { ip });
      refreshHealth(); // Refresh health status from hook
      if (selectedIp === ip) fetchNodeIntel(ip);
    } catch (e) { 
      apiClient.handleError(e, `Mitigation action failed`);
    }
  };

  const fetchModels = async () => {
    setModelsLoading(true);
    try {
      const [modelData, baselineData] = await Promise.all([
        apiClient.get('/api/models'),
        apiClient.get('/api/baseline/status')
      ]);
      
      setModels(modelData.models || []);
      setScalers(modelData.scalers || []);
      setActiveModel(modelData.active_model || '');
      setActiveScaler(modelData.active_scaler || '');
      setBaselineStatus(baselineData);
    } catch (e) { 
      apiClient.handleError(e, 'Failed to fetch model metadata');
    } finally {
      setModelsLoading(false);
    }
  };

  const swapModel = async () => {
    setSwapping(true);
    try {
      const data = await apiClient.post('/api/models/active', {
        model_file: activeModel,
        scaler_file: activeScaler
      });
      if (data.success) {
        setSaveStatus({ type: 'success', msg: 'Engine updated successfully' });
        addLog('Engine: Model configuration updated');
      } else {
        setSaveStatus({ type: 'error', msg: data.error || 'Update failed' });
      }
    } catch (e) { 
      setSaveStatus({ type: 'error', msg: e.message });
      apiClient.handleError(e, 'Model swap failed');
    } finally { 
      setSwapping(false);
      setTimeout(() => setSaveStatus(null), 3000);
    }
  };

  const downloadPcap = (eventId) => {
    window.open(`/api/pcap/download/${eventId || 'latest'}`, '_blank');
  };

  const exportAlerts = async () => {
    try {
      const csv = [
        ['Timestamp', 'Source IP', 'Classification', 'Confidence', 'Protocol', 'Port'].join(','),
        ...filteredAlerts.map(a => 
          [
            a.timestamp || '',
            a.src_ip || '',
            a.prediction || '',
            (a.confidence || 0).toFixed(2),
            a.protocol || '',
            a.dst_port || ''
          ].join(',')
        )
      ].join('\n');
      
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `alerts-${new Date().toISOString().slice(0,10)}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      addLog(`Export: CSV downloaded with ${filteredAlerts.length} alerts`);
    } catch (e) {
      console.error('CSV export error:', e);
      addLog(`Error: CSV export failed - ${e.message}`);
    }
  };

  const refreshAlerts = async () => {
    try {
      const data = await apiClient.get('/api/alerts');
      // Note: Alerts are managed by useAlertStream hook
      // This just logs the refresh action and refreshes the health status
      addLog(`Alerts: Refresh requested (${data.alerts?.length || 0} events available)`);
      refreshHealth();
    } catch (e) {
      apiClient.handleError(e, 'Failed to refresh alerts');
      addLog(`Error: Failed to refresh alerts`);
    }
  };

  // --- LIFECYCLE & INITIALIZATION ---
  useEffect(() => {
    // Fetch models on mount
    fetchModels();
  }, []);

  // Update latency from first alert in stream
  useEffect(() => {
    if (alerts.length > 0 && alerts[0].processing_time_ms) {
      setLatency(alerts[0].processing_time_ms);
    }
  }, [alerts]);

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
            { id: 'mitigation', label: 'Policies', icon: ShieldCheck },
            { id: 'lab', label: 'Simulation', icon: Target },
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
            <div className={`badge-dot ${isConnected ? 'bg-success' : 'bg-danger'}`} style={{ width: '8px', height: '8px', background: isConnected ? 'var(--success)' : 'var(--danger)' }} />
            <span>CORE {isConnected ? 'ONLINE' : 'OFFLINE'}</span>
          </div>
          <div style={{ opacity: 0.5 }}>v3.1.2-STABLE</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="header-section glass-panel">
          <div className="title-group">
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ color: 'var(--text-muted)', fontWeight: 800, fontSize: '0.65rem', letterSpacing: '0.2em', textTransform: 'uppercase' }}>Current Operations</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 900 }}>
                {{ overview: 'Command Hub', mitigation: 'Policies', lab: 'Simulation', settings: 'Engine Config' }[activeTab] || 'Dashboard'}
              </h2>
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
              <Badge variant={isConnected ? 'success' : 'danger'}>{isConnected ? 'SYSTEM READY' : 'OFFLINE'}</Badge>
              <div className="engine-tooltip glass">
                <div style={{ marginBottom: '1rem', fontWeight: 900, fontSize: '0.65rem', color: 'var(--primary)', letterSpacing: '0.1em' }}>ENGINE INTEGRITY</div>
                {[
                  { label: 'Neural Engine', status: health?.checks?.consumer_running, val: health === null ? 'LOADING' : (health?.checks?.consumer_running ? 'ACTIVE' : 'STOPPED') },
                  { label: 'Redis Stream', status: health?.checks?.redis_ok, val: health === null ? 'LOADING' : (health?.checks?.redis_ok ? 'SYNCED' : 'ERROR') },
                  { label: 'IPS Backend', status: true, val: health?.ipset?.backend?.toUpperCase() || (health === null ? 'LOADING' : 'READY') }
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
            <ErrorBoundary>
              <motion.div key="overview" className="content-stack" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
              <div className="stats-grid">
                <StatCard label="Total Ingress" value={stats.processed_total?.toLocaleString()} icon={Database} isLoading={!stats.processed_total && !isConnected} />
                <StatCard label="Threat Vectors" value={stats.attacks?.toLocaleString()} icon={Flame} color="var(--danger)" isLoading={!stats.processed_total && !isConnected} />
                <StatCard 
                  label="Blocked Hosts" 
                  value={(health?.ipset_detailed?.permanent_ips?.length || 0) + (health?.ipset_detailed?.temporary_ips?.length || 0)} 
                  icon={Shield} 
                  color="var(--success)" 
                  isLoading={!health}
                />
                <StatCard 
                  label="Detection Model" 
                  value={baselineStatus?.baseline_active ? "VAE + Random Forest" : "RF (Default)"} 
                  icon={Cpu} 
                  color="var(--primary)" 
                  isLoading={!baselineStatus}
                />
                <StatCard 
                  label="Model Accuracy" 
                  value={baselineStatus?.accuracy_pct ? `${baselineStatus.accuracy_pct.toFixed(2)}%` : "99.11%"} 
                  icon={ShieldCheck} 
                  color="var(--success)" 
                  isLoading={!baselineStatus}
                />
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
                        <button className="btn btn-secondary btn-sm" title="Export CSV" onClick={exportAlerts}><Download size={12} /></button>
                        <button className="btn btn-secondary btn-sm" onClick={refreshAlerts} title="Refresh alerts"><RotateCcw size={12} /></button>
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
                        {filteredAlerts.map((alert) => {
                          const prediction = (alert.prediction || 'Unknown').toLowerCase();
                          const isAttack = prediction.includes('attack') || prediction.includes('anomaly');
                          const isSuspicious = prediction.includes('suspicious');
                          const confidence = typeof alert.confidence === 'number' ? alert.confidence : 0;
                          const isExpanded = expandedRow === alert.event_id; // CHANGED: event_id instead of index
                          
                          return (
                            <React.Fragment key={alert.event_id}>
                              <tr 
                                onClick={() => toggleExpandRow(alert)}
                                className={`alert-row ${isAttack ? 'alert-row-danger' : isSuspicious ? 'alert-row-warning' : ''}`}
                              >
                                <td className="text-muted" style={{ fontSize: '0.65rem', fontWeight: 800 }}>{new Date(alert.timestamp).toLocaleTimeString()}</td>
                                <td style={{ minWidth: '180px' }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span style={{ fontSize: '1.2rem' }}>{getFlagEmoji(alert.enrichment?.country_code)}</span>
                                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                                      <CompactIP 
                                        ip={alert.src_ip} 
                                        type={alert.event_type}
                                        onClick={(e) => { e.stopPropagation(); fetchNodeIntel(alert.src_ip); }} 
                                      />
                                      <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>{alert.event_type === 'system_alert' ? 'Sentinel Internal' : (alert.enrichment?.city || 'Internal/Local')}</span>
                                    </div>
                                  </div>
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
                              {isExpanded && (
                                <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                                  <td colSpan="5" style={{ padding: '1.5rem' }}>
                                     <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.5rem' }}>
                                        <div>
                                          <ShapPanel alert={alert} />
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
                                            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}><Network size={12} className="text-muted" /> {alert.enrichment?.asn || 'Internal'} {alert.enrichment?.isp && alert.enrichment.isp !== 'Unknown' ? `(${alert.enrichment.isp})` : ''}</div>
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
                    <div style={{ height: '240px', width: '100%', position: 'relative' }}>
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

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                    <GlassCard title="Classification" icon={PieChartIcon} subtitle="Attack vs Normal">
                       <div style={{ height: '200px', width: '100%', position: 'relative' }}>
                          <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                              <Pie 
                                data={severityStats} 
                                innerRadius={35} 
                                outerRadius={50} 
                                paddingAngle={5} 
                                dataKey="value"
                                isAnimationActive={false}
                              >
                                {severityStats.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                              </Pie>
                              <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid var(--border)', borderRadius: '8px', fontSize: '0.7rem' }} />
                            </PieChart>
                          </ResponsiveContainer>
                       </div>
                    </GlassCard>

                    <GlassCard title="Top Attackers" icon={Flame} subtitle="Most active threats">
                       <div className="content-stack" style={{ gap: '8px' }}>
                          {topAttackers.length > 0 ? topAttackers.map((node, i) => (
                            <div key={node.ip} className="leaderboard-row" style={{ padding: '6px 10px' }} onClick={() => fetchNodeIntel(node.ip)}>
                               <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                 <div className="rank-badge">{i + 1}</div>
                                 <span style={{ fontSize: '0.7rem', fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{node.ip}</span>
                               </div>
                               <span style={{ fontSize: '0.7rem', fontWeight: 900, color: 'var(--danger)' }}>{node.count}</span>
                            </div>
                          )) : <p style={{ opacity: 0.3, fontSize: '0.6rem', textAlign: 'center', marginTop: '1rem' }}>No threats detected</p>}
                       </div>
                    </GlassCard>
                  </div>

                  <GlassCard title="SHAP Feature Importance" icon={Zap} subtitle="Global key drivers for recent detections">
                     <div className="shap-bar-container">
                        {shapAggregated.map(item => {
                          const percentage = (item.impact / shapAggregated[0].impact) * 100;
                          return (
                            <div key={item.name} className="shap-bar-row">
                               <div className="shap-bar-header">
                                  <span>{item.name}</span>
                                  <span className="text-muted">{item.hits} hits</span>
                               </div>
                               <div className="shap-bar-bg">
                                  <div 
                                    className="shap-bar-fill" 
                                    style={{ 
                                      width: `${percentage}%`, 
                                      background: percentage > 70 ? 'var(--danger)' : percentage > 40 ? 'var(--warning)' : 'var(--primary)' 
                                    }} 
                                  />
                               </div>
                            </div>
                          );
                        })}
                        {shapAggregated.length === 0 && <p style={{ opacity: 0.3, fontSize: '0.65rem', textAlign: 'center' }}>Awaiting more detections...</p>}
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
            </ErrorBoundary>
          )}
          
          {activeTab === 'mitigation' && (
            <ErrorBoundary>
            <motion.div key="mitigation" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <GlassCard title="Active Blocklist" icon={ShieldCheck} subtitle="Nodes currently restricted by IPS">
                   <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
                      <div className="content-stack">
                        <div>
                          <div className="stat-label" style={{ marginBottom: '1rem', color: 'var(--danger)' }}>Permanent Blocks ({health?.ipset_detailed?.permanent_ips?.length || 0})</div>
                          {(!health?.ipset_detailed?.permanent_ips || health.ipset_detailed.permanent_ips.length === 0) ? (
                            <div className="empty-state-small">No permanent blocks active.</div>
                          ) : (
                            health.ipset_detailed.permanent_ips.map(ip => (
                              <div key={ip} className="leaderboard-row" style={{ marginBottom: '0.5rem' }}>
                                 <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                    <Lock size={14} className="text-danger" />
                                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{ip}</span>
                                 </div>
                                 <button 
                                    className="btn-glass btn-sm" 
                                    onClick={() => blockAction(ip, 'unblock')}
                                    style={{ color: 'var(--primary)' }}
                                 >
                                    Authorize
                                 </button>
                              </div>
                            ))
                          )}
                        </div>

                        <div style={{ marginTop: '1.5rem' }}>
                          <div className="stat-label" style={{ marginBottom: '1rem', color: 'var(--warning)' }}>Temporary Bans ({health?.ipset_detailed?.temporary_ips?.length || 0})</div>
                          {(!health?.ipset_detailed?.temporary_ips || health.ipset_detailed.temporary_ips.length === 0) ? (
                            <div className="empty-state-small">No temporary bans active.</div>
                          ) : (
                            health.ipset_detailed.temporary_ips.map(ip => (
                              <div key={ip} className="leaderboard-row" style={{ marginBottom: '0.5rem' }}>
                                 <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                    <History size={14} className="text-warning" />
                                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{ip}</span>
                                 </div>
                                 <button 
                                    className="btn-glass btn-sm" 
                                    onClick={() => blockAction(ip, 'unblock')}
                                 >
                                    Lift Ban
                                 </button>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                   </div>
                </GlassCard>

                <div className="content-stack">
                  <GlassCard title="Manual Node Control" icon={Shield} subtitle="Directly restrict or authorize hosts">
                     <div className="content-stack">
                        <div>
                          <label className="stat-label">Host IPv4 Address</label>
                          <input 
                            type="text" 
                            className="input-field" 
                            placeholder="e.g., 192.168.1.50" 
                            value={manualIp}
                            onChange={e => setManualIp(e.target.value)}
                          />
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '0.5rem' }}>
                          <button 
                            className="btn btn-danger" 
                            onClick={() => { blockAction(manualIp, 'block'); setManualIp(''); }}
                            disabled={!manualIp}
                          >
                            <Lock size={16} /> BLOCK HOST
                          </button>
                          <button 
                            className="btn btn-secondary" 
                            onClick={() => { blockAction(manualIp, 'unblock'); setManualIp(''); }}
                            disabled={!manualIp}
                          >
                            <Unlock size={16} /> AUTHORIZE
                          </button>
                        </div>
                     </div>
                  </GlassCard>

                  <GlassCard title="Security Exceptions" icon={CheckCircle2} subtitle="Trusted local infrastructure">
                     <div className="content-stack">
                        <div style={{ padding: '1rem', borderRadius: '12px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.1)' }}>
                           <p style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                             Internal Sentinel nodes and loopback addresses are automatically protected from mitigation policies to prevent self-denial.
                           </p>
                        </div>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                           {['127.0.0.1', '10.0.2.15', '192.168.1.1'].map(ip => (
                             <Badge key={ip} variant="success">{ip}</Badge>
                           ))}
                        </div>
                     </div>
                  </GlassCard>
                </div>
              </div>
            </motion.div>
            </ErrorBoundary>
          )}

          {activeTab === 'lab' && (
            <ErrorBoundary>
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
                   <pre 
                     ref={simConsoleRef} 
                     className="terminal-output" 
                     style={{ height: '400px', overflowY: 'auto' }}
                   >
                     {simOutput || 'Awaiting simulation initialization...'}
                   </pre>
                </GlassCard>
              </div>
            </motion.div>
            </ErrorBoundary>
          )}



          {activeTab === 'settings' && (
            <ErrorBoundary>
            <motion.div key="settings" className="content-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                <GlassCard title="Neural Engine Control" icon={Cpu} subtitle="Hot-swappable inference models and scalers">
                   <div className="content-stack">
                      {modelsLoading && <p style={{ fontSize: '0.75rem', color: 'var(--primary)' }} className="pulse-fast">LOADING MODELS...</p>}
                      <div>
                        <label className="stat-label">Active Neural Model</label>
                        <select className="input-field" value={activeModel} onChange={e => setActiveModel(e.target.value)} disabled={modelsLoading}>
                          {models.map(m => <option key={m} value={m}>{m}</option>)}
                        </select>
                      </div>
                      <div>
                        <label className="stat-label">Feature Scaler (.pkl)</label>
                        <select className="input-field" value={activeScaler} onChange={e => setActiveScaler(e.target.value)} disabled={modelsLoading}>
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
                <GlassCard title="System Observability" icon={Eye} subtitle="Console logging and telemetry status">
                   <div className="content-stack">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <span className="stat-label">Neural Consumer</span>
                        <Badge variant={health?.checks?.consumer_running ? 'success' : 'danger'}>{health?.checks?.consumer_running ? 'RUNNING' : 'STOPPED'}</Badge>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: '12px', border: '1px solid var(--border)' }}>
                        <span className="stat-label">Redis Pipeline</span>
                        <Badge variant={health?.checks?.redis_ok ? 'success' : 'danger'}>{health?.checks?.redis_ok ? 'HEALTHY' : 'ERROR'}</Badge>
                      </div>
                      <div style={{ padding: '1rem', borderRadius: '12px', background: 'rgba(56, 189, 248, 0.05)', border: '1px solid var(--primary-glow)' }}>
                        <div style={{ display: 'flex', gap: '8px', color: 'var(--primary)', marginBottom: '8px' }}><Info size={14} /> <span style={{ fontSize: '0.65rem', fontWeight: 900 }}>SYSTEM STATUS</span></div>
                        <p style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>The Sentinel engine is operating in V4 architecture with 49-feature extraction. Automated drift detection is active.</p>
                      </div>
                   </div>
                </GlassCard>
              </div>
            </motion.div>
            </ErrorBoundary>
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

                  <GlassCard title="Forensic Timeline" icon={History} subtitle="Behavioral activity reconstruction">
                     <div className="timeline-mini" style={{ maxHeight: '400px', overflowY: 'auto', paddingRight: '10px' }}>
                        {nodeIntel.history?.length > 0 ? (
                          nodeIntel.history.map((entry, idx) => (
                            <div key={idx} className="timeline-item">
                               <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', fontWeight: 800, marginBottom: '4px' }}>{new Date(entry.timestamp).toLocaleString()}</div>
                               <div style={{ fontSize: '0.75rem', fontWeight: 800, display: 'flex', justifyContent: 'space-between' }}>
                                 <span style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{entry.alert_sig || 'General Traffic'}</span>
                                 <Badge variant={entry.prediction?.toLowerCase().includes('attack') ? 'danger' : 'success'}>
                                   {entry.prediction}
                                 </Badge>
                               </div>
                               {entry.shap_top3?.length > 0 && (
                                 <div style={{ fontSize: '0.65rem', marginTop: '6px', color: 'var(--text-secondary)', display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                   <Zap size={10} className="text-warning" />
                                   Key Driver: <span className="text-primary">{entry.shap_top3[0][0] || entry.shap_top3[0].feature}</span>
                                 </div>
                               )}
                               {entry.mitigation && (
                                 <div style={{ fontSize: '0.65rem', marginTop: '4px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                                   <Shield size={10} className="text-primary" />
                                   <span style={{ opacity: 0.7 }}>Response: </span>
                                   <span className="text-primary" style={{ fontWeight: 700 }}>{entry.mitigation}</span>
                                 </div>
                               )}
                            </div>
                          ))
                        ) : (
                          <div className="empty-state-small">No historical alerts found for this IP.</div>
                        )}
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
