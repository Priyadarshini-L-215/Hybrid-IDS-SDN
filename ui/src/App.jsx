/* eslint-disable no-unused-vars, no-useless-escape */
import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, Activity, Zap, Database, Terminal, 
  AlertTriangle, CheckCircle2, Server, Globe, Lock, Unlock, Home,
  RefreshCcw, Search, Filter, ArrowRight, Play, StopCircle, 
  Clock, ExternalLink, Info, ChevronDown, FileText, 
  Link, Network, Share2, Trash2, Bug, 
  HardDrive, Flame, ShieldCheck, Radio, Layers, 
  Fingerprint, RotateCcw, Key, X, MapPin, History, Download,
  PieChart as PieChartIcon
} from 'lucide-react';
import { 
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  AreaChart, Area, PieChart, Pie, Cell
} from 'recharts';

// Custom hooks and utilities
import { useAlertStream } from './hooks/useAlertStream';
import { useHealthStatus } from './hooks/useHealthStatus';
import { useStats } from './hooks/useStats';
import ErrorBoundary from './components/ErrorBoundary';
import ShapPanel from './components/ShapPanel';
import AttackMap from './components/AttackMap';
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

const HighlightText = ({ text, highlight }) => {
  if (!highlight || !text) {
    return <span>{text}</span>;
  }
  const strText = String(text);
  const parts = strText.split(new RegExp(`(${highlight.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&')})`, 'gi'));
  return (
    <span>
      {parts.map((part, index) => 
        part.toLowerCase() === highlight.toLowerCase() ? (
          <mark key={index} className="match-highlight">{part}</mark>
        ) : (
          part
        )
      )}
    </span>
  );
};

const CompactIP = ({ ip, onClick, type, highlight }) => {
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
        <HighlightText text={displayIp} highlight={highlight} />
      </span>
    </div>
  );
};

// --- premium Cybernetic gauges ---
const RiskGauge = ({ score }) => {
  const percentage = Math.min(Math.max(score || 0, 0), 100);
  const color = percentage > 70 ? 'var(--danger)' : percentage > 35 ? 'var(--warning)' : 'var(--success)';
  const glowColor = percentage > 70 ? 'var(--danger-glow)' : percentage > 35 ? 'var(--warning-glow)' : 'var(--success-glow)';
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', width: '100%' }}>
      <div style={{ position: 'relative', width: '80px', height: '80px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{
          position: 'absolute',
          width: '60px',
          height: '60px',
          borderRadius: '50%',
          boxShadow: `0 0 20px ${glowColor}`,
          opacity: 0.1,
          pointerEvents: 'none'
        }} />
        <svg viewBox="0 0 70 70" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
          <circle cx="35" cy="35" r={radius} fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="3" />
          <circle cx="35" cy="35" r={radius} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" strokeDasharray="3, 3" />
          <motion.circle
            cx="35"
            cy="35"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="4.5"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.2, ease: "easeOut" }}
            strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 4px ${color})` }}
          />
        </svg>
        <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: '1.1rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#fff' }}>
            {percentage}%
          </span>
          <span style={{ fontSize: '0.45rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em', marginTop: '-2px' }}>
            {percentage > 70 ? 'CRITICAL' : percentage > 35 ? 'WARNING' : 'SECURE'}
          </span>
        </div>
      </div>
    </div>
  );
};

const ObservationsDisplay = ({ count }) => {
  const isHigh = count > 50;
  const isMedium = count > 5;
  const color = isHigh ? 'var(--danger)' : isMedium ? 'var(--warning)' : 'var(--success)';
  const glowClass = isHigh ? 'breathing-glow-danger' : '';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: '100%' }}>
      <div 
        className={glowClass}
        style={{ 
          background: 'rgba(255, 255, 255, 0.01)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
          borderRadius: '16px',
          padding: '0.4rem 1.1rem',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '2px',
          minWidth: '100px',
          transition: 'all 0.3s ease',
          boxShadow: isHigh ? '0 0 10px rgba(255, 0, 85, 0.1)' : 'none'
        }}
      >
        <span style={{ fontSize: '1.4rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: color, textShadow: `0 0 8px ${color}30` }}>
          {count}
        </span>
        <span style={{ fontSize: '0.45rem', fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
          Observations
        </span>
      </div>
    </div>
  );
};

// --- MAIN APPLICATION ---
function App() {
  // ===== CUSTOM HOOKS (State Management) =====
  const { alerts, incidents, updateAlert, isConnected, bufferSize } = useAlertStream();
  const { health, setHealth, isHealthy, refresh: refreshHealth } = useHealthStatus();
  const { stats, chartData } = useStats(alerts);

  // ===== UI STATE ONLY =====
  const [activeTab, setActiveTab] = useState(() => {
    const saved = localStorage.getItem('sentinel_active_tab');
    return ['overview', 'mitigation'].includes(saved) ? saved : 'overview';
  });
  const [viewMode, setViewMode] = useState('raw'); // 'raw' or 'incident'
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchResults, setSearchResults] = useState(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchParams, setSearchParams] = useState({ src_ip: '', prediction: '', limit: 50 });
  
  useEffect(() => {
    localStorage.setItem('sentinel_active_tab', activeTab);
  }, [activeTab]);
  const latency = (alerts.length > 0 && alerts[0].processing_time_ms) ? alerts[0].processing_time_ms : 0;
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

  // Node Intel
  const [selectedIp, setSelectedIp] = useState(null);
  const [nodeIntel, setNodeIntel] = useState(null);
  const [loadingIntel, setLoadingIntel] = useState(false);
  const [forensicsTab, setForensicsTab] = useState('timeline');

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



  const blockAction = async (ip, action) => {
    let previousHealth = null;
    if (health) {
      previousHealth = JSON.parse(JSON.stringify(health));
      const ipsetDetailed = health.ipset_detailed || { permanent_ips: [], temporary_ips: [] };
      let newPerm = [...(ipsetDetailed.permanent_ips || [])];
      let newTemp = [...(ipsetDetailed.temporary_ips || [])];

      if (action === 'unblock') {
        newPerm = newPerm.filter(x => x !== ip);
        newTemp = newTemp.filter(x => x !== ip);
        addLog(`System: Initiating manual authorization / lift ban for ${ip}`);
      } else if (action === 'block') {
        if (!newPerm.includes(ip)) {
          newPerm.push(ip);
        }
        addLog(`System: Initiating manual block for ${ip}`);
      }

      setHealth({
        ...health,
        ipset_detailed: {
          ...ipsetDetailed,
          permanent_ips: newPerm,
          temporary_ips: newTemp
        }
      });
    }

    try {
      await apiClient.post(`/api/mitigation/${action}`, { ip });
      refreshHealth(); // Refresh health status from hook
      if (selectedIp === ip) fetchNodeIntel(ip);
    } catch (e) { 
      if (previousHealth) {
        setHealth(previousHealth);
      }
      apiClient.handleError(e, `Mitigation action failed`);
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

  // Latency is derived directly from the alert stream

  return (
    <div className="dashboard-container">
      <div className="bg-blobs">
        <div className="cyber-grid-overlay" />
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
            { id: 'mitigation', label: 'Policies', icon: ShieldCheck }
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
                {{ overview: 'Command Hub', mitigation: 'Policies' }[activeTab] || 'Dashboard'}
              </h2>
            </div>
          </div>

          <div className="global-search-container" style={{ flex: 1, margin: '0 3rem', maxWidth: '500px' }}>
            <div className="filter-bar" style={{ position: 'relative' }}>
              <Search size={16} className="text-primary" />
              <input 
                type="text" 
                className="filter-input" 
                placeholder="Global historical search (IP, CIDR, classification...)" 
                onFocus={() => setSearchOpen(true)}
                value={searchParams.src_ip}
                onChange={(e) => setSearchParams({...searchParams, src_ip: e.target.value})}
                onKeyDown={async (e) => {
                  if (e.key === 'Enter') {
                    setSearchLoading(true);
                    try {
                      const data = await apiClient.get('/api/search', searchParams);
                      setSearchResults(data.results);
                    } catch (err) { console.error(err); }
                    finally { setSearchLoading(false); }
                  }
                }}
              />
              {searchOpen && (
                <div className="glass-panel" style={{ position: 'absolute', top: '120%', left: 0, right: 0, padding: '1rem', borderRadius: '16px', zIndex: 1000, maxHeight: '400px', overflowY: 'auto' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 900 }}>HISTORICAL RESULTS</span>
                    <X size={14} className="cursor-pointer" onClick={() => setSearchOpen(false)} />
                  </div>
                  {searchLoading ? <div className="animate-pulse">Searching forensics database...</div> : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {searchResults?.map(r => (
                        <div key={r.event_id} className="leaderboard-row" style={{ fontSize: '0.7rem' }}>
                          <span>{r.src_ip}</span>
                          <Badge variant={r.prediction.includes('attack') ? 'danger' : 'info'}>{r.prediction}</Badge>
                          <span className="text-muted">{new Date(r.timestamp).toLocaleDateString()}</span>
                        </div>
                      ))}
                      {!searchResults && <div style={{ fontSize: '0.65rem', opacity: 0.5 }}>Press Enter to search historical database</div>}
                    </div>
                  )}
                </div>
              )}
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
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: '1.5rem' }}>
                <div className="table-container glass">
                  <div className="table-header">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <Terminal size={18} className="text-primary" />
                        <span className="gradient-text" style={{ fontWeight: 800 }}>LIVE {viewMode === 'raw' ? 'THREAT STREAM' : 'INCIDENT QUEUE'}</span>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <div style={{ display: 'flex', background: 'rgba(0,0,0,0.3)', padding: '2px', borderRadius: '10px', marginRight: '1rem' }}>
                          <button 
                            className={`btn btn-sm ${viewMode === 'raw' ? 'btn-primary' : ''}`} 
                            style={{ background: viewMode === 'raw' ? 'var(--primary)' : 'transparent', color: viewMode === 'raw' ? '#000' : 'inherit' }}
                            onClick={() => setViewMode('raw')}
                          >RAW</button>
                          <button 
                            className={`btn btn-sm ${viewMode === 'incident' ? 'btn-primary' : ''}`} 
                            style={{ background: viewMode === 'incident' ? 'var(--primary)' : 'transparent', color: viewMode === 'incident' ? '#000' : 'inherit' }}
                            onClick={() => setViewMode('incident')}
                          >INCIDENTS</button>
                        </div>
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
                      {viewMode === 'raw' ? (
                        <table className="alerts-table">
                          <thead><tr><th>Timestamp</th><th>Source Node</th><th>Classification</th><th>Score</th><th>Mitigation</th></tr></thead>
                          <tbody>
                            {filteredAlerts.map((alert) => {
                              const prediction = (alert.prediction || 'Unknown').toLowerCase();
                              const isAttack = prediction.includes('attack') || prediction.includes('anomaly');
                              const isSuspicious = prediction.includes('suspicious');
                              const confidence = typeof alert.confidence === 'number' ? alert.confidence : 0;
                              const isExpanded = expandedRow === alert.event_id;
                              
                              return (
                                <React.Fragment key={alert.event_id}>
                                  <motion.tr 
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    transition={{ duration: 0.3 }}
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
                                            highlight={filterQuery}
                                          />
                                          <span style={{ fontSize: '0.6rem', color: 'var(--text-muted)' }}>{alert.event_type === 'system_alert' ? 'Sentinel Internal' : (alert.enrichment?.city || 'Internal/Local')}</span>
                                        </div>
                                      </div>
                                    </td>
                                    <td>
                                      <Badge variant={isAttack ? 'danger' : isSuspicious ? 'warning' : 'success'}>
                                        <HighlightText text={alert.prediction} highlight={filterQuery} />
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
                                  </motion.tr>
                                  {isExpanded && (
                                    <tr style={{ background: 'rgba(0,0,0,0.3)' }}>
                                      <td colSpan="5" style={{ padding: '1.5rem' }}>
                                         <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1.5rem' }}>
                                            <div>
                                              <ShapPanel alert={alert} />
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
                                              <button className="btn btn-danger btn-sm" onClick={(e) => { e.stopPropagation(); blockAction(alert.src_ip, 'block'); }}>BLOCK IP</button>
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
                      ) : (
                        <table className="alerts-table">
                          <thead><tr><th>Incident ID</th><th>Primary Actor</th><th>Attack Type</th><th>Hits</th><th>Last Activity</th></tr></thead>
                          <tbody>
                            {incidents.map((inc) => (
                              <tr key={inc.id} className="alert-row">
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem' }}>{inc.id.substring(0, 12)}...</td>
                                <td><CompactIP ip={inc.src_ip} onClick={() => fetchNodeIntel(inc.src_ip)} /></td>
                                <td><Badge variant="danger">{inc.prediction}</Badge></td>
                                <td style={{ fontWeight: 900 }}>{inc.count}</td>
                                <td className="text-muted">{new Date(inc.last_seen).toLocaleTimeString()}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </div>
                </div>

                <div className="content-stack">
                  <AttackMap alerts={alerts} />
                  
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
                  {/* Summary Metric Strip */}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', alignItems: 'center' }}>
                    <div style={{ background: 'rgba(10, 16, 30, 0.4)', backdropFilter: 'blur(16px)', padding: '1.25rem', borderRadius: '20px', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', boxShadow: 'inset 0 2px 8px rgba(255,255,255,0.02)' }}>
                      <div className="stat-label" style={{ marginBottom: '4px', letterSpacing: '0.1em' }}>Risk Index</div>
                      <RiskGauge score={nodeIntel.reputation_score || 0} />
                    </div>
                    <div style={{ background: 'rgba(10, 16, 30, 0.4)', backdropFilter: 'blur(16px)', padding: '1.25rem', borderRadius: '20px', border: '1px solid rgba(255,255,255,0.06)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem', justifyContent: 'center', minHeight: '142px', boxShadow: 'inset 0 2px 8px rgba(255,255,255,0.02)' }}>
                      <div className="stat-label" style={{ marginBottom: '4px', letterSpacing: '0.1em' }}>Observations</div>
                      <ObservationsDisplay count={nodeIntel.alert_count || 0} />
                    </div>
                  </div>

                  {/* Forensics Tab Trigger Navigation */}
                  <div className="forensics-tabs">
                    <button
                      className={`forensics-tab-btn ${forensicsTab === 'timeline' ? 'active' : ''}`}
                      onClick={() => setForensicsTab('timeline')}
                    >
                      <History size={14} /> Timeline
                    </button>
                    <button
                      className={`forensics-tab-btn ${forensicsTab === 'insights' ? 'active' : ''}`}
                      onClick={() => setForensicsTab('insights')}
                    >
                      <Share2 size={14} /> Insights & Profile
                    </button>
                  </div>

                  {forensicsTab === 'timeline' && (
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
                  )}

                  {forensicsTab === 'insights' && (
                    <>
                      {/* Node Profile Metadata Card */}
                      <div className="glass-card" style={{ padding: '1.25rem', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.7rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>JA3 FINGERPRINT</span>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--primary)', fontWeight: 700 }}>
                              {nodeIntel.ja3_hash || 'None Captured'}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>GEOGRAPHIC REGION</span>
                            <span style={{ color: '#fff', fontWeight: 700 }}>
                              {nodeIntel.geo?.city || 'Unknown'}, {nodeIntel.geo?.country || 'Unknown'}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>ASN IDENTIFIER</span>
                            <span style={{ color: 'var(--text-secondary)', fontWeight: 700 }}>
                              {nodeIntel.geo?.asn || 'Internal Network'}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>FIRST ACTIVITY</span>
                            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>
                              {nodeIntel.first_seen ? new Date(nodeIntel.first_seen).toLocaleString() : 'N/A'}
                            </span>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontWeight: 800 }}>LAST SEEN TRAIL</span>
                            <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>
                              {nodeIntel.last_seen ? new Date(nodeIntel.last_seen).toLocaleString() : 'N/A'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Verdict Pie Chart */}
                      <div style={{ height: '220px', background: 'rgba(10, 16, 30, 0.4)', backdropFilter: 'blur(16px)', borderRadius: '20px', padding: '1.25rem', border: '1px solid rgba(255,255,255,0.06)', position: 'relative' }}>
                        <div className="stat-label" style={{ marginBottom: '0.75rem', letterSpacing: '0.05em' }}>Verdict Distribution</div>
                        <div style={{ position: 'relative', height: '140px' }}>
                          <ResponsiveContainer width="100%" height="100%">
                            <PieChart>
                              <Pie 
                                data={Object.entries(nodeIntel.predictions || {}).map(([name, value]) => ({ name, value }))} 
                                cx="50%" 
                                cy="50%" 
                                innerRadius={42} 
                                outerRadius={60} 
                                paddingAngle={6} 
                                dataKey="value"
                              >
                                {Object.entries(nodeIntel.predictions || {}).map(([name, value], index) => {
                                  let cellColor = 'var(--primary)';
                                  const nameLower = name.toLowerCase();
                                  if (nameLower.includes('normal') || nameLower.includes('benign')) cellColor = 'var(--success)';
                                  else if (nameLower.includes('attack') || nameLower.includes('malicious') || nameLower.includes('ddos') || nameLower.includes('scan')) cellColor = 'var(--danger)';
                                  else if (nameLower.includes('suspicious') || nameLower.includes('anomaly')) cellColor = 'var(--warning)';
                                  else cellColor = COLORS[index % COLORS.length];
                                  return <Cell key={`cell-${index}`} fill={cellColor} stroke="rgba(255,255,255,0.05)" strokeWidth={1} style={{ filter: `drop-shadow(0 0 3px ${cellColor}40)` }} />;
                                })}
                              </Pie>
                              <Tooltip contentStyle={{ background: 'rgba(15, 23, 42, 0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', fontSize: '0.75rem', color: '#fff' }} />
                            </PieChart>
                          </ResponsiveContainer>
                          {/* Central Label */}
                          <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', pointerEvents: 'none' }}>
                            <span style={{ fontSize: '1.25rem', fontWeight: 900, fontFamily: 'var(--font-mono)', color: '#fff', lineHeight: '1.1' }}>
                              {Object.values(nodeIntel.predictions || {}).reduce((a, b) => a + b, 0)}
                            </span>
                            <span style={{ fontSize: '0.45rem', color: 'var(--text-muted)', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '1px' }}>Events</span>
                          </div>
                        </div>
                      </div>

                      {/* Lateral Movement Similar Nodes */}
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
                    </>
                  )}

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
