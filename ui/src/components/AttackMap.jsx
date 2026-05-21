/* eslint-disable no-unused-vars */
import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Globe, Crosshair, AlertCircle } from 'lucide-react';
import { apiClient } from '../utils/apiClient';

/**
 * AttackMap: A high-performance SVG world map visualization.
 * Shows geographic distribution of threats and real-time attack arcs.
 */
const AttackMap = ({ alerts }) => {
  const [geoStats, setGeoStats] = useState([]);
  const [loading, setLoading] = useState(true);

  // Fetch density stats from backend
  useEffect(() => {
    const fetchGeo = async () => {
      try {
        const data = await apiClient.get('/api/stats/geo');
        if (data && data.stats) setGeoStats(data.stats);
      } catch (e) {
        console.error('Geo stats fetch failed', e);
      } finally {
        setLoading(false);
      }
    };
    fetchGeo();
    const interval = setInterval(fetchGeo, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, []);

  // Simplified World Map Paths (Low-poly for performance)
  // These are normalized coordinates [0, 800] x [0, 400]
  const worldPaths = useMemo(() => [
    { name: 'North America', d: "M100,50 L200,50 L250,150 L150,200 L50,150 Z" },
    { name: 'South America', d: "M200,200 L250,200 L230,350 L180,300 Z" },
    { name: 'Europe', d: "M400,50 L480,50 L500,100 L420,120 Z" },
    { name: 'Africa', d: "M420,130 L500,130 L520,280 L450,300 L400,200 Z" },
    { name: 'Asia', d: "M500,50 L750,50 L780,200 L600,250 L500,150 Z" },
    { name: 'Australia', d: "M650,280 L750,280 L730,350 L680,350 Z" }
  ], []);
  const [hoveredCountry, setHoveredCountry] = useState(null);

  // Map country codes to approximate map coordinates
  const getCoords = (cc) => {
    const mapping = {
      // North America
      'US': [150, 100], 'CA': [150, 60], 'MX': [160, 150],
      // South America
      'BR': [260, 260], 'AR': [220, 320], 'CO': [210, 200], 'CL': [200, 320], 'PE': [195, 250],
      // Europe
      'GB': [410, 70], 'IE': [395, 75], 'FR': [425, 95], 'DE': [450, 85], 'IT': [460, 110],
      'ES': [410, 120], 'NL': [442, 80], 'BE': [438, 85], 'CH': [445, 95], 'AT': [458, 95],
      'SE': [465, 55], 'PL': [480, 85], 'UA': [510, 95], 'RU': [620, 70],
      // Asia
      'CN': [660, 130], 'IN': [600, 175], 'JP': [735, 120], 'KR': [710, 125], 'SG': [665, 235],
      'MY': [660, 220], 'ID': [690, 260], 'VN': [670, 180], 'TH': [650, 190], 'PH': [710, 190],
      'PK': [580, 160], 'TR': [510, 125], 'SA': [535, 170], 'AE': [555, 175], 'IL': [510, 140],
      // Africa
      'ZA': [470, 320], 'EG': [490, 160], 'NG': [425, 210], 'KE': [495, 230], 'MA': [395, 145],
      // Oceania
      'AU': [730, 320], 'NZ': [780, 360]
    };
    if (mapping[cc]) return mapping[cc];
    
    // Hash-based deterministic fallback to keep coordinate stable on rerender
    let hash = 0;
    const str = String(cc || 'XX');
    for (let i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    const x = 50 + Math.abs((hash * 7) % 700);
    const y = 50 + Math.abs((hash * 13) % 300);
    return [x, y];
  };

  const activeThreats = useMemo(() => {
    return (alerts || [])
      .filter(a => {
        const p = (a.prediction || '').toLowerCase();
        return p.includes('attack') || p.includes('anomaly');
      })
      .slice(0, 5)
      .map((a, idx) => ({
        id: a.event_id || `threat-fallback-${a.timestamp || idx}-${idx}`,
        src: getCoords(a.enrichment?.country_code),
        dest: [300, 200], // Center target
        color: 'var(--danger)',
        country: a.enrichment?.country_code || 'Unknown'
      }));
  }, [alerts]);

  return (
    <div className="attack-map-container" style={{ position: 'relative', width: '100%', height: '75px', background: 'rgba(0,0,0,0.2)', borderRadius: '16px', overflow: 'hidden', border: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center' }}>
      <div style={{ position: 'absolute', top: '50%', transform: 'translateY(-50%)', left: '1.25rem', zIndex: 10, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Globe size={15} className="text-primary animate-spin" style={{ animationDuration: '10s' }} />
        <span className="gradient-text" style={{ fontWeight: 900, fontSize: '0.75rem', letterSpacing: '0.05em' }}>GLOBAL THREAT TELEMETRY</span>
      </div>

      <AnimatePresence>
        {hoveredCountry && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            style={{
              position: 'absolute',
              top: '50%',
              transform: 'translateY(-50%)',
              right: '1.25rem',
              zIndex: 20,
              background: 'rgba(15, 23, 42, 0.95)',
              border: '1px solid var(--primary-glow)',
              borderRadius: '8px',
              padding: '4px 8px',
              fontSize: '0.55rem',
              backdropFilter: 'blur(10px)',
              pointerEvents: 'none'
            }}
          >
            <span style={{ fontWeight: 900, color: 'var(--primary)' }}>{hoveredCountry.code}:</span>
            <span style={{ color: '#fff', marginLeft: '4px' }}>{hoveredCountry.count} THREATS</span>
          </motion.div>
        )}
      </AnimatePresence>

      <svg viewBox="0 70 800 240" style={{ width: '100%', height: '100%', opacity: 0.5 }}>
        {/* Background Grids */}
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
          </pattern>
          <linearGradient id="threat-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="var(--danger)" stopOpacity="1" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.4" />
          </linearGradient>
          <radialGradient id="radar-sweep-gradient" cx="0%" cy="0%" r="100%">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.2" />
            <stop offset="50%" stopColor="var(--primary)" stopOpacity="0.06" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
          </radialGradient>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />

        {/* Dotted Target Radar telemetry rings */}
        <circle cx="300" cy="200" r="15" fill="none" stroke="rgba(0, 229, 255, 0.08)" strokeWidth="0.75" strokeDasharray="3, 3" />
        <circle cx="300" cy="200" r="35" fill="none" stroke="rgba(0, 229, 255, 0.05)" strokeWidth="0.75" strokeDasharray="3, 3" />
        <circle cx="300" cy="200" r="50" fill="none" stroke="rgba(0, 229, 255, 0.03)" strokeWidth="0.75" strokeDasharray="3, 3" />

        {/* Active Radar Sweep Overlay */}
        <g transform="translate(300, 200)">
          <g className="radar-sweeper-group">
            {/* 30-degree faded tail sector */}
            <path 
              d="M 0 0 L 50 0 A 50 50 0 0 0 43.3 -25 Z" 
              fill="url(#radar-sweep-gradient)" 
              pointerEvents="none" 
            />
            {/* Primary sweeping sweep beam */}
            <line x1="0" y1="0" x2="50" y2="0" stroke="var(--primary)" strokeWidth="1.25" style={{ filter: 'drop-shadow(0 0 4px var(--primary))' }} />
          </g>
        </g>

        {/* World Paths */}
        {worldPaths.map(p => (
          <path
            key={p.name}
            d={p.d}
            fill="rgba(255,255,255,0.03)"
            stroke="rgba(255,255,255,0.08)"
            strokeWidth="1"
          />
        ))}

        {/* Threat Density Bubbles */}
        {geoStats.map(stat => {
          const [x, y] = getCoords(stat.country_code);
          const radius = Math.min(Math.max(stat.count * 2.5, 5), 25);
          return (
            <g key={stat.country_code}>
              <circle
                cx={x} cy={y}
                r={radius}
                fill="var(--danger)"
                fillOpacity="0.12"
                stroke="var(--danger)"
                strokeWidth="1"
                style={{ filter: 'drop-shadow(0 0 8px var(--danger))', cursor: 'pointer' }}
                onMouseEnter={() => setHoveredCountry({ code: stat.country_code, count: stat.count })}
                onMouseLeave={() => setHoveredCountry(null)}
              />
              <circle
                cx={x} cy={y}
                r={radius + 4}
                fill="none"
                stroke="var(--danger)"
                strokeWidth="0.5"
                strokeOpacity="0.3"
                className="pulsing-wave-ring"
                style={{ pointerEvents: 'none' }}
              />
            </g>
          );
        })}

        {/* Real-time Attack Arcs */}
        <AnimatePresence>
          {activeThreats.map(threat => (
            <React.Fragment key={threat.id}>
              {/* Thicker neon glow underlay path */}
              <motion.path
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 0.25 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 1.2, ease: "easeInOut" }}
                d={`M${threat.src[0]},${threat.src[1]} Q${(threat.src[0]+threat.dest[0])/2},${Math.min(threat.src[1], threat.dest[1])-60} ${threat.dest[0]},${threat.dest[1]}`}
                fill="none"
                stroke="var(--danger)"
                strokeWidth="4"
                style={{ filter: 'blur(2px)' }}
              />
              {/* Flowing dashed core arc */}
              <motion.path
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 1.2, ease: "easeInOut" }}
                d={`M${threat.src[0]},${threat.src[1]} Q${(threat.src[0]+threat.dest[0])/2},${Math.min(threat.src[1], threat.dest[1])-60} ${threat.dest[0]},${threat.dest[1]}`}
                fill="none"
                stroke="url(#threat-gradient)"
                strokeWidth="2"
                className="threat-arc-flow"
                strokeDasharray="6,4"
              />
              <motion.circle
                initial={{ scale: 0 }}
                animate={{ scale: [1, 1.8, 1], opacity: [1, 0.4, 1] }}
                transition={{ repeat: Infinity, duration: 1.5 }}
                cx={threat.src[0]} cy={threat.src[1]}
                r="3.5"
                fill="var(--danger)"
                style={{ filter: 'drop-shadow(0 0 4px var(--danger))' }}
              />
            </React.Fragment>
          ))}
        </AnimatePresence>

        {/* Internal Target Node */}
        <circle cx="300" cy="200" r="7" fill="var(--primary)" style={{ filter: 'drop-shadow(0 0 10px var(--primary))' }} />
        <circle cx="300" cy="200" r="16" fill="none" stroke="var(--primary)" strokeWidth="1.5" strokeDasharray="3,3" className="animate-spin" style={{ animationDuration: '6s' }} />
      </svg>

      {/* Legend */}
      <div style={{ position: 'absolute', bottom: '1rem', right: '1.5rem', display: 'flex', gap: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.65rem', fontWeight: 800 }}>
          <div style={{ width: '8px', height: '8px', background: 'var(--danger)', borderRadius: '50%', boxShadow: '0 0 6px var(--danger)' }} />
          <span>ATTACK ORIGIN</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.65rem', fontWeight: 800 }}>
          <div style={{ width: '8px', height: '8px', background: 'var(--primary)', borderRadius: '50%', boxShadow: '0 0 6px var(--primary)' }} />
          <span>LOCAL ASSETS</span>
        </div>
      </div>
    </div>
  );
};

export default AttackMap;
