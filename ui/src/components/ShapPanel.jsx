/* eslint-disable no-unused-vars */
import React from 'react';
import { motion } from 'framer-motion';
import { Info, AlertCircle, BarChart3, Activity, ShieldCheck, Brain, Terminal } from 'lucide-react';

const ShapPanel = ({ alert }) => {
  if (!alert) return null;

  const shapTop3 = alert.shap_top3 || [];
  const stageScores = alert.forensics?.stage_scores || {};
  const anomalyScore = alert.anomaly_score || 0;
  const prediction = (alert.prediction || 'normal').toLowerCase();
  const sigPresent = alert.sig_present || false;

  // Helper to get color based on value
  const getShapColor = (val) => {
    return val > 0 ? 'var(--danger)' : 'var(--success)';
  };

  return (
    <div className="shap-explanation-container" style={{ marginTop: '1.5rem' }}>
      {/* XAI Natural Language Explanation */}
      {alert.xai_explanation && (
        <div style={{
          background: 'rgba(59, 130, 246, 0.1)',
          borderLeft: '4px solid var(--primary)',
          padding: '1rem',
          borderRadius: '0 8px 8px 0',
          marginBottom: '1.5rem',
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'flex-start'
        }}>
          <Info size={20} style={{ color: 'var(--primary)', flexShrink: 0, marginTop: '2px' }} />
          <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
            {alert.xai_explanation}
          </p>
        </div>
      )}

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
                          background: value > 0
                            ? 'linear-gradient(90deg, var(--danger-glow), var(--danger))'
                            : 'linear-gradient(90deg, var(--success-glow), var(--success))',
                          boxShadow: `0 0 12px ${value > 0 ? 'var(--danger-glow)' : 'var(--success-glow)'}`
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          );
        } else {
          // Render a custom premium explanation card based on the classification and signature state
          let cardConfig = {
            icon: <Info size={24} style={{ color: 'var(--text-secondary)' }} />,
            bgGlow: 'rgba(255, 255, 255, 0.015)',
            borderColor: 'rgba(255, 255, 255, 0.04)',
            title: "Explainability Unavailable",
            desc: "Detailed machine learning feature contribution metrics are not available for this alert."
          };

          if (prediction === 'normal') {
            cardConfig = {
              icon: <ShieldCheck size={26} style={{ color: 'var(--success)', filter: 'drop-shadow(0 0 4px var(--success-glow))' }} />,
              bgGlow: 'rgba(0, 255, 159, 0.05)',
              borderColor: 'rgba(0, 255, 159, 0.15)',
              title: "Verified Benign Flow",
              desc: "This network flow aligns with normal baseline behaviors. Deep packet and timing metrics are within expected operational bounds."
            };
          } else if (sigPresent) {
            cardConfig = {
              icon: <Terminal size={24} style={{ color: 'var(--primary)', filter: 'drop-shadow(0 0 4px var(--primary-glow))' }} />,
              bgGlow: 'rgba(0, 229, 255, 0.05)',
              borderColor: 'rgba(0, 229, 255, 0.15)',
              title: "Signature-Based Alert",
              desc: "This alert was triggered by a pre-defined IDS signature. Explanations (SHAP) are calculated exclusively for behavior-based ML classifications."
            };
          } else if (prediction === 'anomaly' || prediction === 'zero-day anomaly') {
            cardConfig = {
              icon: <Brain size={24} style={{ color: 'var(--warning)', filter: 'drop-shadow(0 0 4px var(--warning-glow))' }} />,
              bgGlow: 'rgba(255, 170, 0, 0.05)',
              borderColor: 'rgba(255, 170, 0, 0.15)',
              title: "Zero-Day Behavioral Anomaly",
              desc: "Flagged by the Variational Autoencoder (VAE) based on multi-dimensional reconstruction error. High-dimensional anomalies do not map directly to tree-based SHAP values."
            };
          }

          return (
            <div style={{
              background: cardConfig.bgGlow,
              border: `1px solid ${cardConfig.borderColor}`,
              padding: '1.25rem',
              borderRadius: '12px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              textAlign: 'center',
              gap: '0.75rem',
              marginBottom: '2rem',
              boxShadow: 'inset 0 1px 4px rgba(255,255,255,0.02)',
              backdropFilter: 'blur(8px)'
            }}>
              <div style={{
                width: '48px',
                height: '48px',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255,255,255,0.05)',
                marginBottom: '0.25rem'
              }}>
                {cardConfig.icon}
              </div>
              <h5 style={{ margin: 0, fontSize: '0.85rem', fontWeight: 700, color: '#fff', letterSpacing: '0.02em' }}>
                {cardConfig.title}
              </h5>
              <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4, maxWidth: '280px' }}>
                {cardConfig.desc}
              </p>
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
            style={{ filter: `drop-shadow(0px 0px 3px ${color})` }}
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
