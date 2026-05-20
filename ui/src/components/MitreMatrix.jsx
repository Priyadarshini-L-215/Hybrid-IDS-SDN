import React, { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Shield, Target, Zap, Activity } from 'lucide-react';
import { apiClient } from '../utils/apiClient';

/**
 * MitreMatrix: Visualizes detection coverage across the MITRE ATT&CK framework.
 */
const MitreMatrix = () => {
  const [stats, setStats] = useState([]);
  const [loading, setLoading] = useState(true);

  const tactics = [
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
  ];

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

  const tacticStatus = useMemo(() => {
    const status = {};
    tactics.forEach(t => {
      const hit = stats.find(s => s.mitre_id === t.id || s.mitre_id?.startsWith(t.id));
      status[t.id] = hit ? hit.count : 0;
    });
    return status;
  }, [stats]);

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
        gridTemplateColumns: 'repeat(auto-fill, minmax(100px, 1fr))', 
        gap: '8px' 
      }}>
        {tactics.map(t => {
          const count = tacticStatus[t.id];
          const isActive = count > 0;
          return (
            <motion.div
              key={t.id}
              whileHover={{ scale: 1.05 }}
              style={{
                background: isActive ? `${t.color}15` : 'rgba(255,255,255,0.02)',
                border: `1px solid ${isActive ? t.color : 'var(--glass-border)'}`,
                borderRadius: '12px',
                padding: '10px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
                minHeight: '80px',
                transition: 'all 0.3s'
              }}
            >
              <div style={{ fontSize: '0.55rem', fontWeight: 900, color: 'var(--text-muted)', textTransform: 'uppercase' }}>{t.id}</div>
              <div style={{ fontSize: '0.65rem', fontWeight: 800, color: isActive ? t.color : 'var(--text-secondary)', lineHeight: 1.1 }}>{t.name}</div>
              {isActive && (
                <div style={{ marginTop: 'auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ width: '4px', height: '4px', background: t.color, borderRadius: '50%' }} className="pulse" />
                  <span style={{ fontSize: '0.7rem', fontWeight: 900, color: t.color }}>{count}</span>
                </div>
              )}
            </motion.div>
          );
        })}
      </div>
    </div>
  );
};

export default MitreMatrix;
