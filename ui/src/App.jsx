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
  Info
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
  const lastStats = useRef({ processed: 0, attacks: 0 });
  
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

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
    const timer = setInterval(fetchStatus, 3000);
    return () => clearInterval(timer);
  }, []);

  // WebSocket Connection
  useEffect(() => {
    const connect = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
      
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setConnected(true);
        console.log("[WS] Connected to Sentinel Relay");
      };

      ws.current.onmessage = (event) => {
        try {
          const alert = JSON.parse(event.data);
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
                            <tr key={alert.event_id || i} className={`alert-row ${isBlocked ? 'alert-row-danger' : ''}`}>
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
                                  {alert.is_mitigated && (
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
                              <td style={{ fontWeight: 800 }}>{alert.confidence?.toFixed(1)}%</td>
                              <td style={{ fontSize: '0.8rem' }}>
                                {alert.category?.startsWith('IPS') ? (
                                  <span className="text-danger" style={{ fontWeight: 700 }}>[{alert.category.split(' - ')[0]}] </span>
                                ) : null}
                                {alert.alert_sig}
                              </td>
                            </tr>
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
