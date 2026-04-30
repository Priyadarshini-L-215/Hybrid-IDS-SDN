import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Activity, 
  Zap, 
  Database, 
  Terminal, 
  Settings, 
  AlertTriangle, 
  CheckCircle2, 
  Server, 
  Globe, 
  Lock, 
  Unlock,
  Cpu,
  RefreshCcw,
  Search,
  Filter,
  ArrowRight,
  Play,
  StopCircle,
  Clock,
  ExternalLink,
  Info,
  ChevronDown,
  FileText,
  Upload,
  Link,
  BarChart3
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';
import './App.css';

// --- UI COMPONENTS ---

const Badge = ({ children, variant = 'info' }) => (
  <span className={`badge badge-${variant}`}>
    <span className="badge-dot" style={{ backgroundColor: 'currentColor' }} />
    {children}
  </span>
);

const GlassCard = ({ children, className = '', title, icon: Icon, actions }) => (
  <motion.div 
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={`glass-card ${className}`}
  >
    {title && (
      <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div className="panel-title" style={{ marginBottom: 0 }}>
          {Icon && <Icon size={18} className="text-primary" />}
          <span className="gradient-text">{title}</span>
        </div>
        {actions && <div className="panel-actions">{actions}</div>}
      </div>
    )}
    {children}
  </motion.div>
);

const StatCard = ({ label, value, icon: Icon, color = 'var(--primary)', trend }) => (
  <GlassCard className="stat-card">
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
      <div className="stat-label">{label}</div>
      <div style={{ padding: '8px', borderRadius: '10px', background: `${color}15`, color }}>
        <Icon size={20} />
      </div>
    </div>
    <div className="stat-value-large">{value}</div>
  </GlassCard>
);

// --- MAIN APPLICATION ---

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ 
    processed_total: 0, 
    attacks: 0, 
    normal: 0,
    displayed_total: 0 
  });
  const [health, setHealth] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [connected, setConnected] = useState(false);
  
  // Lab State
  const [scanTarget, setScanTarget] = useState('127.0.0.1');
  const [scanProfile, setScanProfile] = useState('quick');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [latency, setLatency] = useState(4);
  
  const [chartData, setChartData] = useState([]);
  const [attackers, setAttackers] = useState({});
  const [driftWarning, setDriftWarning] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [config, setConfig] = useState(null);
  const [saveStatus, setSaveStatus] = useState(null);
  const lastStats = useRef({ processed: 0, attacks: 0 });
  
  // Eval State
  const [modelList, setModelList] = useState({ models: [], scalers: [], active_model: '', active_scaler: '' });
  const [evalPath, setEvalPath] = useState('');
  const [evalFile, setEvalFile] = useState(null);
  const [evalLabel, setEvalLabel] = useState('Label');
  const [evalType, setEvalType] = useState('path'); // 'path' or 'upload'
  const [evaluating, setEvaluating] = useState(false);
  const [evalResult, setEvalResult] = useState(null);
  
  const ws = useRef(null);

  // Fetch status via REST
  const fetchStatus = async () => {
    try {
      const res = await fetch('/api/pipeline/status');
      const data = await res.json();
      setHealth(data);
    } catch (err) {
      console.error("Status fetch failed:", err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await fetch('/api/alerts');
      const data = await res.json();
      if (data.alerts) {
        setAlerts(data.alerts);
        setStats(prev => ({
          ...prev,
          processed_total: data.total_processed,
          attacks: data.attack_total,
          normal: data.normal_total
        }));
      }
    } catch (err) {
      console.error("Alerts fetch failed:", err);
    }
  };

  const fetchConfig = async () => {
    try {
      const res = await fetch('/api/config');
      const data = await res.json();
      setConfig(data);
    } catch (err) {
      console.error("Config fetch failed:", err);
    }
  };

  const saveConfig = async () => {
    setSaveStatus('saving');
    try {
      const res = await fetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      const data = await res.json();
      if (data.success) {
        setSaveStatus('success');
        setTimeout(() => setSaveStatus(null), 3000);
      } else {
        setSaveStatus('error');
      }
    } catch (err) {
      console.error("Config save failed:", err);
      setSaveStatus('error');
    }
  };

  const fetchModels = async () => {
    try {
      const res = await fetch('/api/models');
      const data = await res.json();
      setModelList(data);
    } catch (err) {
      console.error("Models fetch failed:", err);
    }
  };

  const swapModel = async (model, scaler) => {
    try {
      const res = await fetch('/api/models/active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model_file: model, scaler_file: scaler })
      });
      const data = await res.json();
      if (data.success) {
        fetchModels();
      }
    } catch (err) {
      console.error("Model swap failed:", err);
    }
  };

  const runEvaluation = async () => {
    if (evalType === 'path' && !evalPath) return;
    if (evalType === 'upload' && !evalFile) return;

    setEvaluating(true);
    setEvalResult(null);
    try {
      const formData = new FormData();
      if (evalType === 'upload' && evalFile) {
        formData.append('file', evalFile);
      } else {
        formData.append('dataset_path', evalPath);
      }
      formData.append('label_column', evalLabel);

      const res = await fetch('/api/evaluate/dataset', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      setEvalResult(data);
    } catch (err) {
      setEvalResult({ success: false, error: "Evaluation request failed" });
    } finally {
      setEvaluating(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
    fetchConfig();
    fetchModels();
    const timer = setInterval(fetchStatus, 3000);
    return () => clearInterval(timer);
  }, []);

  // WebSocket Connection
  useEffect(() => {
    const connect = () => {
      const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/alerts`;
      
      ws.current = new WebSocket(WS_URL);

      ws.current.onopen = () => {
        setConnected(true);
        console.log("[WS] Connected to Sentinel Relay");
      };

      ws.current.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
          
          if (alert.type === "drift_alert") {
            setDriftWarning(alert.message);
            return;
          }

          setAlerts(prev => [alert, ...prev].slice(0, 100));

          if (alert.processing_time_ms !== undefined) {
            setLatency(alert.processing_time_ms);
          }
          
          const isAttack = alert.prediction?.toLowerCase().includes('attack');
          if (isAttack) {
            setAttackers(prev => {
              const ip = alert.src_ip;
              const existing = prev[ip] || { count: 0, maxConf: 0, lastSig: '', category: '' };
              return {
                ...prev,
                [ip]: {
                  ip,
                  count: existing.count + 1,
                  maxConf: Math.max(existing.maxConf, alert.confidence || 0),
                  lastSig: alert.alert_sig,
                  category: alert.category
                }
              };
            });
          }

          setStats(prev => ({
            ...prev,
            processed_total: prev.processed_total + 1,
            attacks: isAttack ? prev.attacks + 1 : prev.attacks,
            normal: alert.prediction?.toLowerCase().includes('normal') ? prev.normal + 1 : prev.normal
          }));
        } catch (err) {
          console.error("[WS] Message error:", err);
        }
      };

      ws.current.onclose = () => {
        setConnected(false);
        setTimeout(connect, 3000);
      };
    };

    connect();
    return () => ws.current?.close();
  }, []);

  const statsRef = useRef(stats);
  useEffect(() => { statsRef.current = stats; }, [stats]);

  // Update Chart Data (Fixed 2s Interval)
  useEffect(() => {
    const timer = setInterval(() => {
      // Access current stats via ref to avoid useEffect dependency churn
      const currentStats = statsRef.current;
      
      // Don't record deltas until we have initial baseline
      if (currentStats.processed_total === 0 && lastStats.current.processed === 0) return;

      setChartData(prev => {
        const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        
        const deltaTotal = currentStats.processed_total - lastStats.current.processed;
        const deltaAttacks = currentStats.attacks - lastStats.current.attacks;
        const deltaNormal = Math.max(0, deltaTotal - deltaAttacks);
        
        // Sync for next interval
        lastStats.current = { 
          processed: currentStats.processed_total, 
          attacks: currentStats.attacks 
        };

        const newEntry = {
          time: now,
          normal: deltaNormal,
          attacks: deltaAttacks
        };
        
        // Safety: If it's the first data point and it's huge, skip it
        if (prev.length === 0 && deltaTotal > 100) return prev;

        return [...prev, newEntry].slice(-30);
      });
    }, 2000);
    return () => clearInterval(timer);
  }, []); // Run once on mount

  // Initial data seed
  useEffect(() => {
    fetch('/api/alerts')
      .then(r => r.json())
      .then(data => {
        if (data.alerts) {
          setAlerts(data.alerts);
          // Initialize attackers from historical alerts
          const initAttackers = data.alerts.reduce((acc, alert) => {
            if (!alert.prediction?.toLowerCase().includes('attack')) return acc;
            const ip = alert.src_ip;
            if (!acc[ip]) acc[ip] = { ip, count: 0, maxConf: 0, lastSig: '', category: '' };
            acc[ip].count += 1;
            acc[ip].maxConf = Math.max(acc[ip].maxConf, alert.confidence || 0);
            acc[ip].lastSig = alert.alert_sig;
            acc[ip].category = alert.category;
            return acc;
          }, {});
          setAttackers(initAttackers);
        }
        setStats({
          processed_total: data.total_processed,
          attacks: data.attack_total,
          normal: data.normal_total,
          displayed_total: data.displayed_total
        });
        lastStats.current = { 
          processed: data.total_processed, 
          attacks: data.attack_total 
        };
      });
  }, []);

  // Lab Actions
  const runScan = async () => {
    if (!scanTarget) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/nmap/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget, profile: scanProfile })
      });
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      setScanResult({ success: false, error: "Network error triggering scan" });
    } finally {
      setScanning(false);
    }
  };

  const runDDoS = async () => {
    if (!scanTarget) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/attack/ddos', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget })
      });
      const data = await res.json();
      setScanResult({
        success: data.success,
        raw_output: data.message || data.error,
        target: scanTarget,
        duration_sec: 1.0
      });
    } catch (err) {
      setScanResult({ success: false, error: "DDoS simulation failed" });
    } finally {
      setScanning(false);
    }
  };

  const runPayload = async () => {
    if (!scanTarget) return;
    setScanning(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/attack/payload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: scanTarget })
      });
      const data = await res.json();
      setScanResult({
        success: data.success,
        raw_output: data.message || data.error,
        target: scanTarget,
        duration_sec: 0.5
      });
    } catch (err) {
      setScanResult({ success: false, error: "Payload simulation failed" });
    } finally {
      setScanning(false);
    }
  };

  const unblockIp = async (ip) => {
    try {
      const res = await fetch('/api/mitigation/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        fetchStatus(); // Refresh status
      }
    } catch (err) {
      console.error("Failed to unblock IP:", err);
    }
  };

  const blockIp = async (ip) => {
    try {
      const res = await fetch('/api/mitigation/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        fetchStatus(); // Refresh status
      }
    } catch (err) {
      console.error("Failed to block IP:", err);
    }
  };



  return (
    <div className="dashboard-container">
      {/* Background blobs */}
      <div className="bg-blobs">
        <div className="blob blob-1" />
        <div className="blob blob-2" />
        <div className="blob blob-3" />
      </div>

      {/* Header */}
      <header className="header-section animate-fade-in">
        <div className="title-group">
          <h1>
            <Shield className="text-primary pulse" size={32} />
            <span className="gradient-text">SENTINEL</span>
            <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>CORE</span>
          </h1>
        </div>

        <div className="tabs-navigation">
          <button 
            className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity size={16} /> Overview
          </button>
          <button 
            className={`tab-button ${activeTab === 'mitigation' ? 'active' : ''}`}
            onClick={() => setActiveTab('mitigation')}
          >
            <Lock size={16} /> Mitigation
          </button>
          <button 
            className={`tab-button ${activeTab === 'lab' ? 'active' : ''}`}
            onClick={() => setActiveTab('lab')}
          >
            <Cpu size={16} /> Attack Lab
          </button>
          <button 
            className={`tab-button ${activeTab === 'eval' ? 'active' : ''}`}
            onClick={() => setActiveTab('eval')}
          >
            <BarChart3 size={16} /> Evaluation
          </button>
          <button 
            className={`tab-button ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            <Settings size={16} /> Settings
          </button>
        </div>

        <div className="status-container" style={{ position: 'absolute', top: '2.5rem', right: '4rem', zIndex: 100 }}>
          <div className="status-hover-wrapper">
            <Badge variant={connected ? 'success' : 'danger'}>
              {connected ? 'LIVE FEED' : 'OFFLINE'}
            </Badge>
            
            <div className="engine-tooltip glass">
              <div style={{ marginBottom: '1rem', fontWeight: 800, fontSize: '0.8rem', color: 'var(--primary)', letterSpacing: '0.1em' }}>ENGINE INTEGRITY</div>
              {[
                { label: 'ML Model Engine', status: health?.checks?.consumer_running, val: 'ACTIVE' },
                { label: 'Redis Stream', status: health?.checks?.redis_ok, val: 'SYNCED' },
                { label: 'WebSocket Relay', status: health?.checks?.ws_port_open, val: 'LISTENING' },
                { label: 'Ipset Mitigation', status: true, val: 'HARDENED' }
              ].map(item => (
                <div key={item.label} className="health-item" style={{ padding: '0.5rem 0' }}>
                   <span className="health-label" style={{ fontSize: '0.75rem' }}>{item.label}</span>
                   <span style={{ fontWeight: 800, fontSize: '0.75rem', color: item.status ? 'var(--success)' : 'var(--danger)' }}>
                      {item.status ? item.val : 'FAILURE'}
                   </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </header>

      {/* Drift Warning Banner */}
      {driftWarning && (
        <div className="drift-banner animate-fade-in" style={{ 
          background: 'rgba(234, 179, 8, 0.1)', 
          border: '1px solid var(--warning)', 
          color: 'var(--warning)', 
          padding: '1rem', 
          borderRadius: '12px', 
          marginBottom: '1.5rem', 
          display: 'flex', 
          alignItems: 'center', 
          gap: '12px',
          fontWeight: 700,
          fontSize: '0.85rem'
        }}>
          <AlertTriangle size={18} />
          <div style={{ flex: 1 }}>{driftWarning}</div>
          <button 
            onClick={() => setDriftWarning(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontWeight: 800 }}
          >
            DISMISS
          </button>
        </div>
      )}

      {/* Stats Grid */}
      <div className="stats-grid animate-fade-in" style={{ animationDelay: '0.1s' }}>
        <StatCard 
          label="Ingested Events" 
          value={stats.processed_total?.toLocaleString()} 
          icon={Database} 
        />
        <StatCard 
          label="Malicious Attacks" 
          value={stats.attacks?.toLocaleString()} 
          icon={AlertTriangle} 
          color="var(--danger)"
        />
        <StatCard 
          label="Pipeline Latency" 
          value={`${latency.toFixed(1)}ms`} 
          icon={Zap} 
          color="var(--primary)"
        />
        <StatCard 
          label="Mitigated Hosts" 
          value={health?.ipset?.permanent || 0} 
          icon={Shield} 
          color="var(--success)"
        />
      </div>

      <main className="main-layout animate-fade-in" style={{ animationDelay: '0.2s' }}>
        <div className="content-stack">
          <AnimatePresence mode="wait">
            {activeTab === 'overview' && (
              <motion.div key="overview" className="content-stack">
                {/* Real-time Graph */}
                <GlassCard title="Network Activity (Live)" icon={Activity}>
                  <div style={{ height: '240px', width: '100%', paddingRight: '20px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 255, 0, 0.1)" vertical={true} />
                        <XAxis 
                          dataKey="time" 
                          stroke="var(--text-muted)" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false} 
                          hide={true}
                        />
                        <YAxis 
                          stroke="rgba(0, 255, 0, 0.3)" 
                          fontSize={10} 
                          tickLine={false} 
                          axisLine={false} 
                          domain={[0, 'auto']}
                        />
                        <Tooltip 
                          contentStyle={{ background: 'rgba(15, 23, 42, 0.95)', border: '1px solid #10b981', borderRadius: '4px' }}
                          itemStyle={{ fontSize: '0.8rem', color: '#10b981' }}
                          cursor={{ stroke: '#10b981', strokeWidth: 1 }}
                        />
                        <Line 
                          type="monotone" 
                          dataKey="normal" 
                          stroke="#10b981" 
                          strokeWidth={2}
                          dot={false}
                          isAnimationActive={false}
                        />
                        <Line 
                          type="monotone" 
                          dataKey="attacks" 
                          stroke="#ef4444" 
                          strokeWidth={2}
                          dot={false}
                          isAnimationActive={false}
                        />

                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </GlassCard>



                {/* Live Alerts */}
                <div className="table-container glass">
                  <div className="table-header">
                    <div className="panel-title" style={{ marginBottom: 0 }}>
                      <Terminal size={18} className="text-primary" />
                      <span className="gradient-text">Real-time Behavioral Stream</span>
                    </div>
                  </div>

                  
                  <div className="table-scroller">
                    <table className="alerts-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Source (Blocked IP)</th>
                          <th>Destination</th>
                          <th>Risk Level</th>
                          <th>Score</th>
                          <th>Action / Signature</th>
                        </tr>
                      </thead>
                      <tbody>
                        {alerts.map((alert, i) => {
                          const isBlocked = alert.is_mitigated || 
                                           alert.category?.toLowerCase().includes('ips') || 
                                           alert.prediction?.toLowerCase().includes('attack');
                          return (
                            <React.Fragment key={alert.event_id || i}>
                              <tr 
                                className={`alert-row ${isBlocked ? 'alert-row-danger' : ''}`}
                                onClick={() => setExpandedRow(expandedRow === (alert.event_id || i) ? null : (alert.event_id || i))}
                                style={{ cursor: 'pointer', transition: 'background 0.2s' }}
                              >
                                <td style={{ opacity: 0.6 }}>{alert.timestamp?.split('T')[1]?.split('.')[0]}</td>
                                <td className="ip-address">
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    {(isBlocked || alert.is_mitigated) && <Lock size={12} className="text-danger" />}
                                    {alert.src_ip}
                                  </div>
                                </td>
                                <td className="ip-address">{alert.dst_ip || 'Internal'}</td>
                                <td>
                                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                    <Badge variant={
                                      alert.prediction?.toLowerCase().includes('attack') ? 'danger' :
                                      alert.prediction?.toLowerCase().includes('suspicious') ? 'warning' : 'success'
                                    }>
                                      {alert.prediction?.toUpperCase()}
                                    </Badge>
                                    {alert.is_mitigated && alert.mitigation && (
                                      <span style={{ 
                                        fontSize: '0.65rem', 
                                        fontWeight: 800, 
                                        color: 'var(--warning)', 
                                        letterSpacing: '0.05em',
                                        display: 'flex',
                                        alignItems: 'center',
                                        gap: '4px'
                                      }}>
                                        <Zap size={10} /> {alert.mitigation}
                                      </span>
                                    )}
                                  </div>
                                </td>
                                <td style={{ fontWeight: 800 }}>
                                  {alert.confidence > 0 ? `${alert.confidence?.toFixed(1)}%` : '—'}
                                </td>
                                <td style={{ fontSize: '0.8rem' }}>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                    <span>
                                      {alert.category?.startsWith('IPS') ? (
                                        <span className="text-danger" style={{ fontWeight: 700 }}>[{alert.category.split(' - ')[0]}] </span>
                                      ) : null}
                                      {alert.alert_sig}
                                    </span>
                                    <ChevronDown size={14} style={{ opacity: 0.3, transform: expandedRow === (alert.event_id || i) ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }} />
                                  </div>
                                </td>
                              </tr>
                              
                              {expandedRow === (alert.event_id || i) && (
                                <tr className="explain-row" style={{ background: 'rgba(255,255,255,0.02)' }}>
                                   <td colSpan={6} style={{ padding: '1.5rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                                      <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                                         {alert.mitre && (
                                           <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                                              <Shield size={16} className="text-primary" />
                                              <span style={{ fontWeight: 800, fontSize: '0.8rem', color: 'var(--primary)', letterSpacing: '0.05em' }}>
                                                MITRE ATT&CK: {alert.mitre.id} — {alert.mitre.name}
                                              </span>
                                           </div>
                                         )}
                                         
                                         <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '3rem' }}>
                                            <div>
                                               <div style={{ fontSize: '0.7rem', opacity: 0.5, marginBottom: '0.75rem', fontWeight: 800, letterSpacing: '0.05em' }}>BEHAVIORAL EVIDENCE (TOP FEATURES)</div>
                                               {alert.shap_top3?.length > 0 ? (
                                                 <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                                                    {alert.shap_top3.map(f => (
                                                      <div key={f.feature} style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                                                         <span style={{ fontSize: '0.75rem', flex: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', opacity: 0.8 }}>{f.feature}</span>
                                                         <div style={{ flex: 1.5, height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden', position: 'relative' }}>
                                                            <div style={{ 
                                                              width: `${Math.min(Math.abs(f.impact) * 200, 100)}%`, 
                                                              height: '100%', 
                                                              background: f.impact > 0 ? 'var(--danger)' : 'var(--primary)',
                                                              opacity: 0.6
                                                            }} />
                                                         </div>
                                                         <span style={{ fontSize: '0.7rem', fontWeight: 800, width: '50px', textAlign: 'right', fontFamily: 'monospace' }}>{f.value.toFixed(2)}</span>
                                                      </div>
                                                    ))}
                                                 </div>
                                               ) : (
                                                 <div style={{ fontSize: '0.75rem', opacity: 0.4, fontStyle: 'italic' }}>No SHAP evidence available for this event type.</div>
                                               )}
                                            </div>
                                            
                                            <div style={{ borderLeft: '1px solid rgba(255,255,255,0.05)', paddingLeft: '2rem' }}>
                                               <div style={{ fontSize: '0.7rem', opacity: 0.5, marginBottom: '0.75rem', fontWeight: 800, letterSpacing: '0.05em' }}>ANOMALY SCOPE</div>
                                               <div style={{ display: 'flex', alignItems: 'baseline', gap: '10px' }}>
                                                  <span className="gradient-text" style={{ fontSize: (alert.anomaly_score > 0) ? '2.5rem' : '1.5rem', fontWeight: 900 }}>
                                                     {(alert.anomaly_score > 0) ? alert.anomaly_score.toFixed(4) : 'CALIBRATING...'}
                                                  </span>
                                               </div>
                                               <p style={{ fontSize: '0.7rem', opacity: 0.5, marginTop: '0.25rem', lineHeight: 1.4 }}>
                                                  Normalised reconstruction error relative to rolling <b>{alert.protocol}</b> baseline.
                                               </p>
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

            {activeTab === 'mitigation' && (
              <motion.div key="mitigation" className="content-stack">
                <GlassCard title="Active Threat Intelligence" icon={AlertTriangle}>
                  <div className="table-scroller">
                    <table className="alerts-table">
                      <thead>
                        <tr>
                          <th>Attacker IP</th>
                          <th>Total Attacks</th>
                          <th>Peak Risk</th>
                          <th>Action Required</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.values(attackers)
                          .sort((a, b) => b.count - a.count)
                          .map((threat) => {
                            const isBlocked = health?.ipset_detailed?.permanent_ips?.includes(threat.ip) || 
                                             health?.ipset_detailed?.temporary_ips?.includes(threat.ip);
                            return (
                              <tr key={threat.ip} className="alert-row">
                                <td className="ip-address">{threat.ip}</td>
                                <td style={{ fontWeight: 800 }}>{threat.count} events</td>
                                <td>
                                  <Badge variant="danger">{threat.maxConf?.toFixed(1)}% High</Badge>
                                </td>
                                <td>
                                  <div style={{ display: 'flex', gap: '10px' }}>
                                    {isBlocked ? (
                                      <button 
                                        onClick={() => unblockIp(threat.ip)}
                                        className="glass"
                                        style={{ padding: '6px 12px', borderRadius: '8px', fontSize: '0.7rem', color: 'var(--success)', border: '1px solid var(--success)', cursor: 'pointer', fontWeight: 800 }}
                                      >
                                        UNBLOCK
                                      </button>
                                    ) : (
                                      <button 
                                        onClick={() => blockIp(threat.ip)}
                                        className="glass"
                                        style={{ padding: '6px 12px', borderRadius: '8px', fontSize: '0.7rem', color: 'var(--danger)', border: '1px solid var(--danger)', cursor: 'pointer', fontWeight: 800 }}
                                      >
                                        BLOCK IP
                                      </button>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                    {alerts.filter(a => a.prediction?.toLowerCase().includes('attack')).length === 0 && (
                      <div style={{ textAlign: 'center', padding: '2rem', opacity: 0.4 }}>
                        <p>No active threats identified.</p>
                      </div>
                    )}
                  </div>
                </GlassCard>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                  <GlassCard title="Mitigation Policy: ipset" icon={Shield}>
                    <div className="ip-list">
                      {[
                        ...(health?.ipset_detailed?.permanent_ips || []).map(ip => ({ ip, type: 'Permanent' })),
                        ...(health?.ipset_detailed?.temporary_ips || []).map(ip => ({ ip, type: 'Temporary' }))
                      ].length > 0 ? (
                        [
                          ...(health?.ipset_detailed?.permanent_ips || []).map(ip => ({ ip, type: 'Permanent' })),
                          ...(health?.ipset_detailed?.temporary_ips || []).map(ip => ({ ip, type: 'Temporary' }))
                        ].map(({ ip, type }) => (
                          <div key={ip} className="ip-item">
                            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                              <Lock size={16} className={type === 'Permanent' ? "text-danger" : "text-warning"} />
                              <div>
                                <div className="ip-address">{ip}</div>
                                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{type} Restriction</div>
                              </div>
                            </div>
                            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                              <Badge variant={type === 'Permanent' ? "danger" : "warning"}>{type}</Badge>
                              <button 
                                onClick={() => unblockIp(ip)}
                                className="glass"
                                style={{ padding: '6px 12px', borderRadius: '8px', fontSize: '0.7rem', color: 'var(--text-primary)', border: '1px solid var(--border)', cursor: 'pointer' }}
                              >
                                Unblock
                              </button>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div style={{ textAlign: 'center', padding: '3rem', opacity: 0.5 }}>
                          <Unlock size={48} />
                          <p style={{ marginTop: '1rem' }}>No restrictions active.</p>
                        </div>
                      )}
                    </div>
                  </GlassCard>

                  <GlassCard title="Reputation Analysis" icon={Globe}>
                    <div className="ip-list">
                      {Object.entries(health?.ipset_detailed?.reputation || {})
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10)
                        .map(([ip, score]) => (
                          <div key={ip} className="ip-item">
                            <span className="ip-address">{ip}</span>
                            <div style={{ flex: 1, margin: '0 2rem' }}>
                              <div className="meter-bar-bg">
                                <div 
                                  className="meter-bar-fill" 
                                  style={{ 
                                    width: `${Math.min((score/50)*100, 100)}%`, 
                                    background: score > 40 ? 'var(--danger)' : score > 20 ? 'var(--warning)' : 'var(--primary)' 
                                  }} 
                                />
                              </div>
                            </div>
                            <span style={{ fontSize: '0.75rem', fontWeight: 800, minWidth: '30px', textAlign: 'right' }}>{score.toFixed(1)}</span>
                          </div>
                      ))}
                      {Object.keys(health?.ipset_detailed?.reputation || {}).length === 0 && (
                        <div style={{ textAlign: 'center', padding: '2rem', opacity: 0.4, fontSize: '0.9rem' }}>No IPs being tracked.</div>
                      )}
                    </div>
                  </GlassCard>
                </div>
              </motion.div>
            )}

            {activeTab === 'lab' && (
              <motion.div key="lab" className="content-stack">
                <GlassCard title="Attack Simulation Lab" icon={Cpu}>
                  <div style={{ padding: '1rem' }}>
                    <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem' }}>
                      <div className="glass" style={{ flex: 1, padding: '1rem', borderRadius: '12px' }}>
                        <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Target IP / Host</label>
                        <input 
                          type="text" 
                          value={scanTarget}
                          onChange={(e) => setScanTarget(e.target.value)}
                          className="glass"
                          style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px', borderRadius: '8px', fontSize: '1rem' }}
                        />
                      </div>
                      <div className="glass" style={{ flex: 1, padding: '1rem', borderRadius: '12px' }}>
                        <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Scan Profile</label>
                        <select 
                          value={scanProfile}
                          onChange={(e) => setScanProfile(e.target.value)}
                          className="glass"
                          style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px', borderRadius: '8px' }}
                        >
                          <option value="ping">Ping Sweep (Stealth)</option>
                          <option value="quick">Quick Scan (Fast)</option>
                          <option value="service">Service Discovery</option>
                          <option value="os_detect">OS Fingerprinting</option>
                          <option value="aggressive">Aggressive (A-Scan)</option>
                          <option value="vuln">Vulnerability Script</option>
                        </select>
                      </div>
                      <button 
                        onClick={runScan}
                        disabled={scanning}
                        className="glass"
                        style={{ padding: '0 2rem', borderRadius: '12px', background: 'var(--primary)', color: 'white', fontWeight: 800, cursor: scanning ? 'not-allowed' : 'pointer', border: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}
                      >
                        {scanning ? <RefreshCcw size={20} className="spin" /> : <Play size={20} />}
                        {scanning ? 'SCANNING...' : 'START ATTACK'}
                      </button>
                    </div>

                    {scanResult && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass" style={{ padding: '1.5rem', borderRadius: '16px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                          <h3 className="gradient-text">Scan Result</h3>
                          <Badge variant={scanResult.success ? 'success' : 'danger'}>{scanResult.success ? 'COMPLETED' : 'FAILED'}</Badge>
                        </div>
                        <div style={{ maxHeight: '300px', overflowY: 'auto', background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '8px', fontFamily: 'monospace', fontSize: '0.85rem', color: '#a5f3fc', whiteSpace: 'pre-wrap' }}>
                          {scanResult.raw_output || scanResult.error}
                        </div>
                        <div style={{ marginTop: '1rem', display: 'flex', gap: '1rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                          <span>Duration: {scanResult.duration_sec}s</span>
                          <span>Target: {scanResult.target}</span>
                        </div>
                      </motion.div>
                    )}
                  </div>
                </GlassCard>
                
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '1.5rem' }}>
                   <GlassCard title="DDoS Stressor" icon={Zap}>
                     <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>Simulate high-velocity packet floods from a virtual botnet.</p>
                     <button 
                        onClick={runDDoS}
                        disabled={scanning}
                        className="glass"
                        style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--danger)', border: '1px solid var(--danger)', fontWeight: 700, cursor: 'pointer' }}
                     >
                       Launch Flood
                     </button>
                   </GlassCard>
                   <GlassCard title="Payload Injector" icon={Database}>
                     <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1rem' }}>Test regex and behavioral signatures against malicious strings.</p>
                     <button 
                        onClick={runPayload}
                        disabled={scanning}
                        className="glass"
                        style={{ width: '100%', padding: '10px', borderRadius: '8px', background: 'rgba(59, 130, 246, 0.1)', color: 'var(--primary)', border: '1px solid var(--primary)', fontWeight: 700, cursor: 'pointer' }}
                     >
                       Inject Payload
                     </button>
                   </GlassCard>
                </div>
              </motion.div>
            )}

            {activeTab === 'eval' && (
              <motion.div key="eval" className="content-stack">
                <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.2fr', gap: '1.5rem' }}>
                  <div className="content-stack">
                    <GlassCard title="Model Management" icon={Cpu}>
                      <div className="content-stack" style={{ gap: '1rem' }}>
                        <div>
                          <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Active ML Model</label>
                          <select 
                            value={modelList.active_model}
                            onChange={(e) => swapModel(e.target.value, modelList.active_scaler)}
                            className="glass"
                            style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px', borderRadius: '8px' }}
                          >
                            {modelList.models.map(m => <option key={m} value={m}>{m}</option>)}
                          </select>
                        </div>
                        <div>
                          <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Active Scaler</label>
                          <select 
                            value={modelList.active_scaler}
                            onChange={(e) => swapModel(modelList.active_model, e.target.value)}
                            className="glass"
                            style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px', borderRadius: '8px' }}
                          >
                            {modelList.scalers.map(s => <option key={s} value={s}>{s}</option>)}
                          </select>
                        </div>
                        <div style={{ padding: '0.75rem', background: 'rgba(59, 130, 246, 0.05)', borderRadius: '8px', fontSize: '0.75rem', opacity: 0.8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--primary)', fontWeight: 800, marginBottom: '4px' }}>
                            <Info size={14} /> MODEL INFO
                          </div>
                          Model swapping is instantaneous and affects both this lab and real-time detection.
                        </div>
                      </div>
                    </GlassCard>

                    <GlassCard title="Dataset Configuration" icon={Database}>
                      <div className="content-stack" style={{ gap: '1.25rem' }}>
                        <div style={{ display: 'flex', gap: '8px', background: 'rgba(0,0,0,0.2)', padding: '4px', borderRadius: '8px' }}>
                          <button 
                            onClick={() => setEvalType('path')}
                            className={`glass ${evalType === 'path' ? 'active' : ''}`}
                            style={{ flex: 1, padding: '8px', border: 'none', borderRadius: '6px', fontSize: '0.75rem', cursor: 'pointer', background: evalType === 'path' ? 'var(--primary)' : 'transparent', color: 'white', fontWeight: 700 }}
                          >
                            Local Path
                          </button>
                          <button 
                            onClick={() => setEvalType('upload')}
                            className={`glass ${evalType === 'upload' ? 'active' : ''}`}
                            style={{ flex: 1, padding: '8px', border: 'none', borderRadius: '6px', fontSize: '0.75rem', cursor: 'pointer', background: evalType === 'upload' ? 'var(--primary)' : 'transparent', color: 'white', fontWeight: 700 }}
                          >
                            Upload
                          </button>
                        </div>

                        {evalType === 'path' ? (
                          <div>
                            <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Dataset CSV Path</label>
                            <div style={{ position: 'relative' }}>
                              <Link size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', opacity: 0.5 }} />
                              <input 
                                type="text" 
                                placeholder="/home/user/data/test.csv"
                                value={evalPath}
                                onChange={(e) => setEvalPath(e.target.value)}
                                className="glass"
                                style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px 12px 12px 40px', borderRadius: '8px', fontSize: '0.9rem' }}
                              />
                            </div>
                          </div>
                        ) : (
                          <div>
                            <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Upload CSV</label>
                            <label className="glass" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '10px', padding: '1.5rem', border: '2px dashed var(--border)', borderRadius: '12px', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }}>
                              <Upload size={24} className="text-primary" />
                              <span style={{ fontSize: '0.8rem', opacity: 0.7 }}>{evalFile ? evalFile.name : 'Click to select CSV file'}</span>
                              <input 
                                type="file" 
                                accept=".csv"
                                onChange={(e) => setEvalFile(e.target.files[0])}
                                style={{ display: 'none' }}
                              />
                            </label>
                          </div>
                        )}

                        <div>
                          <label className="stat-label" style={{ display: 'block', marginBottom: '8px' }}>Ground Truth Label Column</label>
                          <input 
                            type="text" 
                            value={evalLabel}
                            onChange={(e) => setEvalLabel(e.target.value)}
                            className="glass"
                            style={{ width: '100%', border: '1px solid var(--border)', background: 'rgba(0,0,0,0.2)', color: 'white', padding: '12px', borderRadius: '8px', fontSize: '0.9rem' }}
                          />
                        </div>

                        <button 
                          onClick={runEvaluation}
                          disabled={evaluating}
                          className="glass"
                          style={{ width: '100%', padding: '14px', borderRadius: '12px', background: 'var(--primary)', color: 'white', fontWeight: 800, cursor: evaluating ? 'not-allowed' : 'pointer', border: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}
                        >
                          {evaluating ? <RefreshCcw size={18} className="spin" /> : <Play size={18} />}
                          {evaluating ? 'EVALUATING...' : 'RUN BENCHMARK'}
                        </button>
                      </div>
                    </GlassCard>
                  </div>

                  <div className="content-stack">
                    <GlassCard title="Evaluation Results" icon={BarChart3}>
                      {!evalResult && !evaluating && (
                        <div style={{ textAlign: 'center', padding: '5rem 2rem', opacity: 0.3 }}>
                          <FileText size={48} style={{ margin: '0 auto 1.5rem' }} />
                          <p>Configure a dataset and run the benchmark to see metrics.</p>
                        </div>
                      )}

                      {evaluating && (
                        <div style={{ textAlign: 'center', padding: '5rem 2rem' }}>
                          <RefreshCcw size={48} className="spin text-primary" style={{ margin: '0 auto 1.5rem' }} />
                          <p className="gradient-text" style={{ fontWeight: 800 }}>Analyzing Dataset Structure...</p>
                          <p style={{ fontSize: '0.8rem', opacity: 0.5 }}>This may take a moment for large CSV files.</p>
                        </div>
                      )}

                      {evalResult && !evalResult.success && (
                        <div className="animate-fade-in" style={{ padding: '1.5rem', background: 'rgba(239, 68, 68, 0.05)', border: '1px solid var(--danger)', borderRadius: '12px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: 'var(--danger)', fontWeight: 800, marginBottom: '1rem' }}>
                            <AlertTriangle size={20} /> COMPATIBILITY ERROR
                          </div>
                          <p style={{ fontSize: '0.9rem', marginBottom: '1.5rem' }}>{evalResult.error}</p>
                          
                          {evalResult.incompatibility_details?.missing_features && (
                            <div>
                              <div style={{ fontSize: '0.7rem', opacity: 0.6, fontWeight: 800, marginBottom: '0.5rem', letterSpacing: '0.05em' }}>MISSING FEATURES IN DATASET:</div>
                              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                {evalResult.incompatibility_details.missing_features.map(f => (
                                  <span key={f} style={{ fontSize: '0.65rem', background: 'rgba(239, 68, 68, 0.2)', padding: '2px 8px', borderRadius: '4px' }}>{f}</span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {evalResult && evalResult.success && (
                        <div className="animate-fade-in content-stack">
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
                            <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderRadius: '12px' }}>
                              <div style={{ fontSize: '0.7rem', opacity: 0.5, marginBottom: '4px' }}>SAMPLES</div>
                              <div style={{ fontSize: '1.2rem', fontWeight: 900 }}>{evalResult.summary.total_samples.toLocaleString()}</div>
                            </div>
                            <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderRadius: '12px' }}>
                              <div style={{ fontSize: '0.7rem', opacity: 0.5, marginBottom: '4px' }}>ACCURACY</div>
                              <div className="text-success" style={{ fontSize: '1.2rem', fontWeight: 900 }}>{(evalResult.summary.accuracy * 100).toFixed(1)}%</div>
                            </div>
                            <div className="glass" style={{ padding: '1rem', textAlign: 'center', borderRadius: '12px' }}>
                              <div style={{ fontSize: '0.7rem', opacity: 0.5, marginBottom: '4px' }}>VERSION</div>
                              <div style={{ fontSize: '0.9rem', fontWeight: 900, marginTop: '4px' }}>{evalResult.summary.model_version}</div>
                            </div>
                          </div>

                          <div className="table-container glass" style={{ border: 'none', background: 'transparent' }}>
                            <table className="alerts-table">
                              <thead>
                                <tr>
                                  <th>Class Name</th>
                                  <th>Precision</th>
                                  <th>Recall</th>
                                  <th>F1-Score</th>
                                  <th>Support</th>
                                </tr>
                              </thead>
                              <tbody>
                                {Object.entries(evalResult.metrics)
                                  .filter(([key]) => !['accuracy', 'macro avg', 'weighted avg'].includes(key))
                                  .map(([name, m]) => (
                                    <tr key={name} className="alert-row">
                                      <td style={{ fontWeight: 800 }}>{name}</td>
                                      <td>{(m.precision * 100).toFixed(1)}%</td>
                                      <td>{(m.recall * 100).toFixed(1)}%</td>
                                      <td>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                          <div style={{ flex: 1, height: '4px', background: 'rgba(255,255,255,0.05)', borderRadius: '2px', overflow: 'hidden' }}>
                                            <div style={{ width: `${m['f1-score'] * 100}%`, height: '100%', background: m['f1-score'] > 0.8 ? 'var(--success)' : m['f1-score'] > 0.5 ? 'var(--warning)' : 'var(--danger)' }} />
                                          </div>
                                          {(m['f1-score'] * 100).toFixed(1)}%
                                        </div>
                                      </td>
                                      <td style={{ opacity: 0.6 }}>{m.support}</td>
                                    </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}
                    </GlassCard>
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'settings' && config && (
              <motion.div key="settings" className="content-stack animate-fade-in">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
                  <h2 style={{ margin: 0, fontSize: '1.5rem', fontWeight: 900 }} className="gradient-text">System Configuration</h2>
                  <button 
                    onClick={saveConfig}
                    className="glass"
                    style={{ 
                      padding: '10px 24px', 
                      borderRadius: '12px', 
                      background: saveStatus === 'success' ? 'var(--success)' : 'var(--primary)',
                      color: 'white',
                      fontWeight: 800,
                      cursor: 'pointer',
                      border: 'none',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      transition: 'all 0.3s'
                    }}
                  >
                    {saveStatus === 'saving' ? <RefreshCcw size={16} className="animate-spin" /> : <Database size={16} />}
                    {saveStatus === 'success' ? 'SAVED' : saveStatus === 'error' ? 'FAILED' : 'SAVE CONFIGURATION'}
                  </button>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                  {/* ML Decision Engine Settings */}
                  <GlassCard title="ML Decision Engine" icon={Cpu}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                      <div>
                         <label style={{ fontSize: '0.75rem', opacity: 0.6, display: 'block', marginBottom: '0.5rem' }}>Attack Threshold</label>
                         <input 
                           type="range" min="0" max="1" step="0.01" 
                           value={config.detection?.decision_engine?.thresholds?.attack || 0.85}
                           onChange={(e) => {
                             const newConfig = {...config};
                             newConfig.detection.decision_engine.thresholds.attack = parseFloat(e.target.value);
                             setConfig(newConfig);
                           }}
                           style={{ width: '100%' }}
                         />
                         <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                            <span style={{ fontSize: '0.7rem' }}>Conservative</span>
                            <span style={{ fontSize: '0.8rem', fontWeight: 800, color: 'var(--primary)' }}>{config.detection?.decision_engine?.thresholds?.attack}</span>
                            <span style={{ fontSize: '0.7rem' }}>Aggressive</span>
                         </div>
                      </div>

                      <div>
                         <label style={{ fontSize: '0.75rem', opacity: 0.6, display: 'block', marginBottom: '0.5rem' }}>Suspicious Threshold</label>
                         <input 
                           type="range" min="0" max="1" step="0.01" 
                           value={config.detection?.decision_engine?.thresholds?.suspicious || 0.6}
                           onChange={(e) => {
                             const newConfig = {...config};
                             newConfig.detection.decision_engine.thresholds.suspicious = parseFloat(e.target.value);
                             setConfig(newConfig);
                           }}
                           style={{ width: '100%' }}
                         />
                         <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                            <span style={{ fontSize: '0.7rem' }}>Low Sensitivity</span>
                            <span style={{ fontSize: '0.8rem', fontWeight: 800, color: 'var(--warning)' }}>{config.detection?.decision_engine?.thresholds?.suspicious}</span>
                            <span style={{ fontSize: '0.7rem' }}>High Sensitivity</span>
                         </div>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
                         <div>
                            <label style={{ fontSize: '0.65rem', opacity: 0.5 }}>Sig Weight</label>
                            <input 
                              type="number" step="0.1" className="glass"
                              value={config.detection?.decision_engine?.weights?.signature}
                              onChange={(e) => {
                                const newConfig = {...config};
                                newConfig.detection.decision_engine.weights.signature = parseFloat(e.target.value);
                                setConfig(newConfig);
                              }}
                              style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                            />
                         </div>
                         <div>
                            <label style={{ fontSize: '0.65rem', opacity: 0.5 }}>ML Weight</label>
                            <input 
                              type="number" step="0.1" className="glass"
                              value={config.detection?.decision_engine?.weights?.ml}
                              onChange={(e) => {
                                const newConfig = {...config};
                                newConfig.detection.decision_engine.weights.ml = parseFloat(e.target.value);
                                setConfig(newConfig);
                              }}
                              style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                            />
                         </div>
                         <div>
                            <label style={{ fontSize: '0.65rem', opacity: 0.5 }}>Anomaly Weight</label>
                            <input 
                              type="number" step="0.1" className="glass"
                              value={config.detection?.decision_engine?.weights?.anomaly}
                              onChange={(e) => {
                                const newConfig = {...config};
                                newConfig.detection.decision_engine.weights.anomaly = parseFloat(e.target.value);
                                setConfig(newConfig);
                              }}
                              style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                            />
                         </div>
                      </div>
                    </div>
                  </GlassCard>

                  {/* Mitigation Policies */}
                  <GlassCard title="Mitigation Policy" icon={Shield}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                             <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>Block Duration (TTL)</div>
                             <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>Time in seconds for temporary blocks</div>
                          </div>
                          <input 
                            type="number" className="glass"
                            value={config.mitigation?.block_ttl}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.mitigation.block_ttl = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '80px', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white', textAlign: 'right' }}
                          />
                       </div>

                       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                             <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>Rate Limit</div>
                             <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>Max packets/sec per IP before sampling</div>
                          </div>
                          <input 
                            type="number" className="glass"
                            value={config.mitigation?.rate_limit_per_sec}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.mitigation.rate_limit_per_sec = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '80px', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white', textAlign: 'right' }}
                          />
                       </div>

                       <div style={{ marginTop: '0.5rem', padding: '1rem', background: 'rgba(234, 179, 8, 0.05)', border: '1px solid rgba(234, 179, 8, 0.2)', borderRadius: '10px' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.5rem', color: 'var(--warning)', fontWeight: 800, fontSize: '0.7rem' }}>
                             <AlertTriangle size={14} /> ATTENTION REQUIRED
                          </div>
                          <p style={{ fontSize: '0.7rem', margin: 0, opacity: 0.7, lineHeight: 1.4 }}>
                            Changes to mitigation thresholds will enforce stricter kernel-level packet drops. Ensure your whitelists are current before applying aggressive policies.
                          </p>
                       </div>
                    </div>
                  </GlassCard>

                  {/* System Parameters */}
                  <GlassCard title="Pipeline & Infrastructure" icon={Server}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
                       <div>
                          <label style={{ fontSize: '0.7rem', opacity: 0.5 }}>Log Level</label>
                          <select 
                            className="glass"
                            value={config.system?.log_level}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.system.log_level = e.target.value;
                              setConfig(newConfig);
                            }}
                            style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                          >
                            <option value="DEBUG">DEBUG</option>
                            <option value="INFO">INFO</option>
                            <option value="WARNING">WARNING</option>
                            <option value="ERROR">ERROR</option>
                          </select>
                       </div>
                       <div>
                          <label style={{ fontSize: '0.7rem', opacity: 0.5 }}>Worker Threads</label>
                          <input 
                            type="number" className="glass"
                            value={config.system?.worker_count}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.system.worker_count = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                          />
                       </div>
                       <div>
                          <label style={{ fontSize: '0.7rem', opacity: 0.5 }}>Batch Size</label>
                          <input 
                            type="number" className="glass"
                            value={config.system?.batch_size}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.system.batch_size = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                          />
                       </div>
                       <div>
                          <label style={{ fontSize: '0.7rem', opacity: 0.5 }}>Websocket Port</label>
                          <input 
                            type="number" className="glass"
                            value={config.network?.ws_port}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.network.ws_port = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '100%', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white' }}
                          />
                       </div>
                    </div>
                  </GlassCard>

                  {/* Detection Tuning */}
                  <GlassCard title="Detection Correlation" icon={Activity}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                             <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>Port Scan Threshold</div>
                             <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>Unique ports per window to trigger alert</div>
                          </div>
                          <input 
                            type="number" className="glass"
                            value={config.detection?.port_scan_threshold}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.detection.port_scan_threshold = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '80px', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white', textAlign: 'right' }}
                          />
                       </div>

                       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                             <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>DoS Event Threshold</div>
                             <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>Events per window from single source</div>
                          </div>
                          <input 
                            type="number" className="glass"
                            value={config.detection?.dos_threshold}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.detection.dos_threshold = parseInt(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '80px', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white', textAlign: 'right' }}
                          />
                       </div>

                       <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <div>
                             <div style={{ fontSize: '0.85rem', fontWeight: 700 }}>Correlation Window</div>
                             <div style={{ fontSize: '0.7rem', opacity: 0.5 }}>Time in seconds for flow aggregation</div>
                          </div>
                          <input 
                            type="number" step="1" className="glass"
                            value={config.detection?.correlation_window}
                            onChange={(e) => {
                              const newConfig = {...config};
                              newConfig.detection.correlation_window = parseFloat(e.target.value);
                              setConfig(newConfig);
                            }}
                            style={{ width: '80px', padding: '8px', background: 'rgba(255,255,255,0.05)', border: 'none', borderRadius: '6px', color: 'white', textAlign: 'right' }}
                          />
                       </div>
                    </div>
                  </GlassCard>

                  {/* Adversarial Weaknesses & Model Limits */}
                  <div style={{ gridColumn: '1 / -1' }}>
                    <GlassCard title="Adversarial Weaknesses & Model Limits" icon={Lock}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
                        <div>
                          <div style={{ color: 'var(--danger)', fontWeight: 800, fontSize: '0.75rem', marginBottom: '0.75rem', letterSpacing: '0.05em' }}>EVASION VULNERABILITIES</div>
                          <ul style={{ fontSize: '0.75rem', opacity: 0.7, paddingLeft: '1.25rem', lineHeight: 1.6 }}>
                            <li><b>Feature Manipulation</b>: Attackers may use packet padding or timing delays to bypass ML thresholds.</li>
                            <li><b>Aggregation Blind Spots</b>: Single-packet exploits can be masked by high-volume normal traffic in the flow aggregator.</li>
                            <li><b>SHAP Obfuscation</b>: Spurious benign features can be injected to distract from malicious indicators in forensics.</li>
                          </ul>
                        </div>
                        <div>
                          <div style={{ color: 'var(--warning)', fontWeight: 800, fontSize: '0.75rem', marginBottom: '0.75rem', letterSpacing: '0.05em' }}>OPERATIONAL LIMITS</div>
                          <ul style={{ fontSize: '0.75rem', opacity: 0.7, paddingLeft: '1.25rem', lineHeight: 1.6 }}>
                            <li><b>Low & Slow Drift</b>: Incremental poisoning of the VAE baseline may occur if attacks are distributed over weeks.</li>
                            <li><b>Zero-Day Latency</b>: Novel attacks without prior feature correlation may take N-samples before triggering ADWIN alerts.</li>
                            <li><b>False Positives</b>: High-entropy benign traffic (e.g., encrypted backups) can skew anomaly scores.</li>
                          </ul>
                        </div>
                      </div>
                      <div style={{ marginTop: '1.5rem', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', fontSize: '0.7rem', opacity: 0.5, fontStyle: 'italic', textAlign: 'center' }}>
                        Notice: This system uses a hybrid behavioral/signature approach. Analysts should cross-reference ML alerts with deterministic Suricata signatures for high-confidence mitigation.
                      </div>
                    </GlassCard>
                  </div>
                </div>

                <div style={{ marginTop: '1rem', padding: '1rem', borderTop: '1px solid rgba(255,255,255,0.05)', textAlign: 'center', opacity: 0.4, fontSize: '0.7rem' }}>
                  Sentinel Core v3.0.0 — Hybrid ML/Signature Pipeline — SOC Administrative Console
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <aside className="side-stack">
          {/* Engine Integrity moved to Live Badge Hover */}
        </aside>

      </main>

      <footer style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.75rem', opacity: 0.6 }}>
        Sentinel Core IDS/IPS — Integrated Behavioral Defense System — {new Date().getFullYear()}
      </footer>
    </div>
  );
}

export default App;
