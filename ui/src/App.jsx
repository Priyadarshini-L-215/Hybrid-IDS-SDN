import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Power, PauseCircle, Trash2, 
  Terminal, Shield, Scan, Zap, AlertTriangle, ChevronDown, Loader,
  Brain, Target, Play, X, Copy, CheckCheck
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, ReferenceLine
} from 'recharts';
import './App.css';

// ─────────────────────────────────────────────────────────────────
//  Nmap Attack Lab Component
// ─────────────────────────────────────────────────────────────────
function AttackLab() {
  const [profiles, setProfiles]       = useState([]);
  const [nmapCheck, setNmapCheck]     = useState(null); // {available, version, install_url}
  const [target, setTarget]           = useState("127.0.0.1");
  const [profile, setProfile]         = useState("quick");
  const [extraFlags, setExtraFlags]   = useState("");
  const [scanning, setScanning]       = useState(false);
  const [analysing, setAnalysing]     = useState(false);
  const [result, setResult]           = useState(null);
  const [aiAnalysis, setAiAnalysis]   = useState("");
  const [aiError, setAiError]         = useState("");
  const [copied, setCopied]           = useState(false);
  const [tab, setTab]                 = useState("output"); // "output" | "ai"
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
  }, [result, aiAnalysis]);

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
    setAiAnalysis("");
    setAiError("");
    setTab("output");

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

  const runAiAnalysis = async () => {
    if (!result?.raw_output) return;
    setAnalysing(true);
    setAiAnalysis("");
    setAiError("");
    setTab("ai");

    try {
      const res = await fetch('/api/nmap/analyse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nmap_output: result.raw_output, target }),
      });
      const data = await res.json();
      if (data.success) setAiAnalysis(data.analysis);
      else setAiError(data.error || "Unknown error");
    } catch (e) {
      setAiError(String(e));
    } finally {
      setAnalysing(false);
    }
  };

  const copyOutput = () => {
    const text = tab === "ai" ? aiAnalysis : result?.raw_output;
    if (text) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      });
    }
  };

  return (
    <div className="attack-lab glass-panel">
      {/* Header */}
      <div className="section-title lab-header">
        <div style={{display:'flex', alignItems:'center', gap:'0.75rem'}}>
          <Target size={16} style={{color: '#ff006e'}} />
          <h3>Attack Lab <span className="lab-badge">Nmap + Gemini AI</span></h3>
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
          <button
            id="nmap-ai-btn"
            className={`lab-btn ai-btn ${analysing ? 'loading' : ''}`}
            onClick={runAiAnalysis}
            disabled={analysing || !result?.raw_output}
          >
            {analysing
              ? <><Loader size={16} className="spin"/> Analysing...</>
              : <><Brain size={16}/> Gemini AI</>}
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
      {(result || scanning || analysing) && (
        <div className="lab-output-wrap">
          {/* Tab bar */}
          <div className="output-tabs">
            <button
              className={`output-tab ${tab === 'output' ? 'active' : ''}`}
              onClick={() => setTab('output')}
            >
              <Terminal size={12}/> Raw Output
            </button>
            <button
              className={`output-tab ${tab === 'ai' ? 'active' : ''}`}
              onClick={() => setTab('ai')}
              disabled={!aiAnalysis && !aiError && !analysing}
            >
              <Brain size={12}/> AI Analysis
            </button>
            <button className="copy-btn" onClick={copyOutput} title="Copy to clipboard">
              {copied ? <CheckCheck size={13} style={{color:'#00f9ff'}}/> : <Copy size={13}/>}
            </button>
          </div>

          {/* Output content */}
          <div className="lab-output" ref={outputRef}>
            {tab === 'output' && (
              scanning 
                ? <div className="scan-progress"><Loader size={18} className="spin"/><span>Running nmap…</span></div>
                : result?.raw_output
                  ? <pre className="nmap-pre">{result.raw_output}</pre>
                  : result?.error
                    ? <p className="output-err"><X size={14}/> {result.error}</p>
                    : null
            )}
            {tab === 'ai' && (
              analysing
                ? <div className="scan-progress"><Loader size={18} className="spin"/><span>Gemini is thinking…</span></div>
                : aiError
                  ? <p className="output-err"><X size={14}/> {aiError}</p>
                  : <MarkdownLite src={aiAnalysis} />
            )}
          </div>
        </div>
      )}
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
      interval = setInterval(fetchData, 5000);
    }
    return () => clearInterval(interval);
  }, [systemState]);

  const stats = useMemo(() => {
    const total   = data.alerts.length;
    const attacks = data.alerts.filter(a => a.prediction === 'Attack').length;
    return { total, attacks, normal: total - attacks };
  }, [data.alerts]);

  const chartData = useMemo(() => {
    return [...data.alerts].reverse().map((alert, index) => {
      const timeStr = alert.timestamp ? alert.timestamp.split('T')[1].substring(0, 8) : `T-${index}`;
      return {
        time: timeStr,
        attackConfidence: alert.prediction === 'Attack' ? alert.confidence : 0,
        normalConfidence: alert.prediction === 'Normal' ? alert.confidence : 0,
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

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      const isAttack = d.attackConfidence > 0;
      return (
        <div className={`glass-panel tooltip-panel ${isAttack ? 'attack' : 'normal'}`}>
          <p className="detail-label" style={{marginBottom:'5px'}}>{label}</p>
          {isAttack && (
            <>
              <p className="threat-badge attack"><ShieldAlert size={14}/> {d.signature}</p>
              <p className="detail-value">Confidence: {d.attackConfidence}%</p>
              <p className="detail-value" style={{opacity: 0.7}}>Src: {d.ip}</p>
            </>
          )}
          {!isAttack && (
            <>
              <p className="threat-badge normal"><ShieldCheck size={14}/> VERIFIED TRAFFIC</p>
              <p className="detail-value">Confidence: {d.normalConfidence}%</p>
              <p className="detail-value" style={{opacity: 0.7}}>Src: {d.ip}</p>
            </>
          )}
        </div>
      );
    }
    return null;
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

        {/* METRICS ROW (always visible) */}
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
        </section>

        {/* IDS VIEW */}
        {activeView === 'ids' && (
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
                    <AreaChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 0 }}>
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
                      <Tooltip content={<CustomTooltip/>}/>
                      <ReferenceLine y={90} label={{position:'top', value:'High Threat Threshold', fill:'rgba(255,0,110,0.5)', fontSize:10}} stroke="rgba(255,0,110,0.3)" strokeDasharray="3 3"/>
                      <Area type="monotone" dataKey="normalConfidence" stroke="#00f9ff" strokeWidth={2} fillOpacity={1} fill="url(#colorNormal)" animationDuration={1000}/>
                      <Area type="monotone" dataKey="attackConfidence" stroke="#ff006e" strokeWidth={3} fillOpacity={1} fill="url(#colorAttack)" animationDuration={1000} activeDot={{r:8, fill:'#ff006e', stroke:'#fff', strokeWidth:2}}/>
                    </AreaChart>
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
        )}

        {/* ATTACK LAB VIEW */}
        {activeView === 'lab' && (
          <div className="lab-view">
            <AttackLab />
          </div>
        )}

      </div>
    </>
  );
}

export default App;
