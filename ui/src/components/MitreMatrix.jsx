import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Target, X, AlertTriangle, ShieldCheck } from 'lucide-react';
import { apiClient } from '../utils/apiClient';

// Tactic/Technique descriptions for enhanced forensics context
const TECHNIQUE_NAMES = {
  'T1190': 'Exploit Public-Facing Application',
  'T1566': 'Phishing / Social Engineering',
  'T1059': 'Command and Scripting Interpreter',
  'T1078': 'Valid Accounts Abuse',
  'T1133': 'External Remote Services',
  'T1021': 'Remote Services Execution',
  'T1071': 'Application Layer Protocol Command Channel',
  'T1048': 'Exfiltration Over Alternative Protocol',
  'T1499': 'Endpoint Denial of Service',
  'T1567': 'Exfiltration Over Web Service',
  'T1090': 'Proxy Redirection',
  'T1210': 'Exploitation of Remote Services',
  'T1595': 'Active Scanning / Recon'
};

/**
 * MitreMatrix: Visualizes detection coverage across the MITRE ATT&CK framework.
 */
const MitreMatrix = () => {
  const [stats, setStats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTactic, setSelectedTactic] = useState(null);

  const tactics = useMemo(() => [
    { id: 'TA0001', name: 'Initial Access', color: '#38bdf8' },
    { id: 'TA0002', name: 'Execution', color: '#0ea5e9' },
    { id: 'TA0003', name: 'Persistence', color: '#0284c7' },
    { id: 'TA0004', name: 'Privilege Esc.', color: '#0369a1' },
    { id: 'TA0005', name: 'Defense Evasion', color: '#075985' },
    { id: 'TA0006', name: 'Cred. Access', color: '#10b981' },
    { id: 'TA0007', name: 'Discovery', color: '#059669' },
    { id: 'TA0008', name: 'Lateral Mvmnt', color: '#047857' },
    { id: 'TA0009', name: 'Collection', color: '#f59e0b' },
    { id: 'TA0011', name: 'C&C', color: '#d97706' },
    { id: 'TA0010', name: 'Exfiltration', color: '#f43f5e' },
    { id: 'TA0040', name: 'Impact', color: '#e11d48' }
  ], []);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const data = await apiClient.get('/api/stats/mitre');
        if (data && data.stats) setStats(data.stats);
      } catch (e) {
        console.error('MITRE stats fetch failed', e);
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  // Compute stats grouped by tactic ID
  const tacticStatus = useMemo(() => {
    const status = {};
    tactics.forEach(t => {
      const hits = stats.filter(s => {
        const mid = (s.mitre_id || '').toUpperCase();
        return mid === t.id || mid.startsWith(t.id) || mid.includes(t.id);
      });
      const count = hits.reduce((acc, curr) => acc + curr.count, 0);
      status[t.id] = { count, items: hits };
    });
    return status;
  }, [stats, tactics]);

  const activeTacticDetails = useMemo(() => {
    if (!selectedTactic) return null;
    const tactic = tactics.find(t => t.id === selectedTactic);
    const details = tacticStatus[selectedTactic] || { count: 0, items: [] };
    return {
      ...tactic,
      ...details
    };
  }, [selectedTactic, tactics, tacticStatus]);

  const handleTacticClick = (id) => {
    if (selectedTactic === id) {
      setSelectedTactic(null);
    } else {
      setSelectedTactic(id);
    }
  };

  return (
    <div className="glass-card" style={{ padding: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Target size={18} className="text-primary" />
          <span className="gradient-text" style={{ fontWeight: 900, fontSize: '1rem' }}>MITRE ATT&CK KILL-CHAIN</span>
        </div>
        <div className="badge badge-info">LIVE COVERAGE</div>
      </div>

      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fill, minmax(110px, 1fr))', 
        gap: '10px' 
      }}>
        {tactics.map(t => {
          const { count } = tacticStatus[t.id] || { count: 0 };
          const isActive = count > 0;
          const isSelected = selectedTactic === t.id;
          
          return (
            <motion.div
              key={t.id}
              whileHover={{ scale: 1.03, y: -2 }}
              onClick={() => handleTacticClick(t.id)}
              animate={isActive ? {
                borderColor: [
                  isSelected ? t.color : `${t.color}60`,
                  isSelected ? t.color : `${t.color}c0`,
                  isSelected ? t.color : `${t.color}60`
                ],
                boxShadow: [
                  isSelected ? `0 0 15px ${t.color}40` : `0 0 4px ${t.color}10`,
                  isSelected ? `0 0 25px ${t.color}70` : `0 0 14px ${t.color}35`,
                  isSelected ? `0 0 15px ${t.color}40` : `0 0 4px ${t.color}10`
                ]
              } : {}}
              transition={isActive ? {
                borderColor: { repeat: Infinity, duration: 2.5, ease: "easeInOut" },
                boxShadow: { repeat: Infinity, duration: 2.5, ease: "easeInOut" }
              } : {}}
              style={{
                background: isSelected 
                  ? `${t.color}25` 
                  : isActive ? `${t.color}10` : 'rgba(255,255,255,0.01)',
                border: `1px solid ${isSelected 
                  ? t.color 
                  : isActive ? `${t.color}60` : 'var(--glass-border)'}`,
                borderRadius: '14px',
                padding: '12px 10px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                minHeight: '90px',
                cursor: 'pointer',
                transition: 'background 0.3s ease, transform 0.3s ease',
                boxShadow: isSelected ? `0 0 15px ${t.color}40` : 'none'
              }}
            >
              <div style={{ fontSize: '0.55rem', fontWeight: 900, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t.id}</div>
              <div style={{ fontSize: '0.65rem', fontWeight: 800, color: isSelected || isActive ? '#fff' : 'var(--text-secondary)', lineHeight: 1.2 }}>{t.name}</div>
              
              <div style={{ marginTop: 'auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                {isActive ? (
                  <>
                    <div style={{ width: '6px', height: '6px', background: t.color, borderRadius: '50%' }} className="pulse" />
                    <span style={{ fontSize: '0.75rem', fontWeight: 900, color: t.color }}>{count}</span>
                  </>
                ) : (
                  <span style={{ fontSize: '0.55rem', fontWeight: 800, color: 'var(--text-muted)' }}>0 DETECTED</span>
                )}
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Interactive Technique Drawer Panel */}
      <AnimatePresence>
        {activeTacticDetails && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="tactic-details-drawer"
            style={{ overflow: 'hidden' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--glass-border)', paddingBottom: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '8px', height: '8px', background: activeTacticDetails.color, borderRadius: '50%' }} />
                <span style={{ fontWeight: 900, fontSize: '0.8rem', textTransform: 'uppercase', color: '#fff' }}>
                  {activeTacticDetails.name} Coverage Breakdown ({activeTacticDetails.id})
                </span>
              </div>
              <button 
                onClick={() => setSelectedTactic(null)} 
                className="btn-icon" 
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
              >
                <X size={14} />
              </button>
            </div>

            {activeTacticDetails.items.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', padding: '1rem', background: 'rgba(255,255,255,0.01)', borderRadius: '12px', border: '1px dashed var(--glass-border)' }}>
                <ShieldCheck size={16} className="text-success" />
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>No threats matching this tactic have bypassed perimeter defense. System clear.</span>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {activeTacticDetails.items.map((item, idx) => {
                  const parts = (item.mitre_id || '').split('.');
                  const techId = parts[1] || parts[0] || 'Unknown';
                  const name = TECHNIQUE_NAMES[techId] || 'Custom Signature Action';
                  
                  return (
                    <div key={idx} className="technique-badge-item">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="technique-id-label">{techId}</span>
                        <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{name}</span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Events:</span>
                        <span style={{ fontWeight: 900, color: activeTacticDetails.color }}>{item.count}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default MitreMatrix;
