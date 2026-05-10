import React from 'react';
import { motion } from 'framer-motion';
import { Info, AlertCircle, BarChart3, Activity } from 'lucide-react';

const ShapPanel = ({ alert }) => {
  if (!alert) return null;

  const shapTop3 = alert.shap_top3 || [];
  const stageScores = alert.forensics?.stage_scores || {};
  const anomalyScore = alert.anomaly_score || 0;

  // Helper to get color based on value
  const getShapColor = (val) => {
    return val > 0 ? 'var(--danger)' : 'var(--success)';
  };

  return (
    <div className="shap-explanation-container" style={{ marginTop: '1.5rem' }}>
      {/* SHAP Features Section */}
      <div className="detail-section-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
        <BarChart3 size={16} className="text-primary" />
        <span style={{ fontSize: '0.9rem', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Feature Contribution (XAI)</span>
      </div>

      {(() => {
        let tops = alert.shap_top3 || [];
        if (typeof tops === 'string') {
          try { tops = JSON.parse(tops); } catch (e) { tops = []; }
        }
        
        if (tops.length > 0) {
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
              {tops.map((item, idx) => {
                const [feature, value] = Array.isArray(item) ? item : [item.feature, item.impact ?? item.value ?? 0];
                const displayValue = typeof value === 'number' ? value : 0;
                const absValue = Math.abs(displayValue);
                const percentage = Math.min(Math.max(absValue * 100, 5), 100);
            
            return (
              <div key={idx} className="shap-row">
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '4px' }}>
                  <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{feature}</span>
                  <span style={{ color: getShapColor(value), fontWeight: 700 }}>
                    {typeof value === 'number' ? `${value > 0 ? '+' : ''}${value.toFixed(4)}` : 'N/A'}
                  </span>
                </div>
                <div style={{ height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${percentage}%` }}
                    transition={{ duration: 0.8, delay: idx * 0.1 }}
                    style={{ 
                      height: '100%', 
                      background: getShapColor(value),
                      boxShadow: `0 0 10px ${getShapColor(value)}50`
                    }}
                  />
                </div>
              </div>
            );
          })}
            </div>
          );
        } else {
          return (
            <div className="empty-state-small" style={{ marginBottom: '2rem' }}>
              No SHAP data available for this event.
            </div>
          );
        }
      })()}

      {/* Stage Scores Section */}
      <div className="detail-section-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
        <Activity size={16} className="text-primary" />
        <span style={{ fontSize: '0.9rem', fontWeight: 700, letterSpacing: '0.05em', textTransform: 'uppercase' }}>Detection Stage Breakdown</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
        <ScoreMetric 
          label="Signature" 
          value={stageScores.signature || 0} 
          color="var(--primary)" 
        />
        <ScoreMetric 
          label="ML Engine" 
          value={stageScores.ml || alert.confidence / 100 || 0} 
          color="var(--secondary)" 
        />
        <ScoreMetric 
          label="Anomaly" 
          value={stageScores.anomaly || anomalyScore || 0} 
          color="var(--warning)" 
        />
      </div>
    </div>
  );
};

const ScoreMetric = ({ label, value, color }) => {
  const percentage = Math.min(Math.max(value * 100, 0), 100);
  
  return (
    <div style={{ 
      background: 'rgba(255,255,255,0.03)', 
      padding: '0.75rem', 
      borderRadius: '12px', 
      border: '1px solid rgba(255,255,255,0.05)',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '0.5rem'
    }}>
      <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontWeight: 600, textTransform: 'uppercase' }}>{label}</span>
      <div style={{ position: 'relative', width: '40px', height: '40px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <svg viewBox="0 0 36 36" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
          <circle cx="18" cy="18" r="16" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="3" />
          <motion.circle
            cx="18"
            cy="18"
            r="16"
            fill="none"
            stroke={color}
            strokeWidth="3"
            strokeDasharray="100 100"
            initial={{ strokeDashoffset: 100 }}
            animate={{ strokeDashoffset: 100 - percentage }}
            transition={{ duration: 1, ease: "easeOut" }}
            strokeLinecap="round"
          />
        </svg>
        <span style={{ position: 'absolute', fontSize: '0.7rem', fontWeight: 800, color: '#fff' }}>
          {Math.round(percentage)}%
        </span>
      </div>
    </div>
  );
};

export default ShapPanel;
