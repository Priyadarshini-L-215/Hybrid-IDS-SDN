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

  // Map country codes to approximate map coordinates
  const getCoords = (cc) => {
    const mapping = {
      'US': [150, 100], 'CN': [650, 120], 'RU': [600, 70], 'DE': [450, 80],
      'BR': [220, 280], 'AU': [700, 320], 'IN': [620, 180], 'GB': [430, 70],
      'FR': [440, 90], 'CA': [150, 60], 'UA': [490, 90], 'NL': [445, 75]
    };
    return mapping[cc] || [Math.random() * 800, Math.random() * 400];
  };

  const activeThreats = useMemo(() => {
    return alerts
      .filter(a => {
        const p = (a.prediction || '').toLowerCase();
        return p.includes('attack') || p.includes('anomaly');
      })
      .slice(0, 5)
      .map(a => ({
        id: a.event_id,
        src: getCoords(a.enrichment?.country_code),
        dest: [300, 200], // Center target
        color: 'var(--danger)'
      }));
  }, [alerts]);

  return (
    <div className="attack-map-container" style={{ position: 'relative', width: '100%', height: '350px', background: 'rgba(0,0,0,0.2)', borderRadius: '24px', overflow: 'hidden', border: '1px solid var(--glass-border)' }}>
      <div style={{ position: 'absolute', top: '1.5rem', left: '1.5rem', zIndex: 10, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        <Globe size={18} className="text-primary animate-spin" style={{ animationDuration: '10s' }} />
        <span className="gradient-text" style={{ fontWeight: 900, fontSize: '0.9rem', letterSpacing: '0.05em' }}>GLOBAL THREAT TELEMETRY</span>
      </div>

      <svg viewBox="0 0 800 400" style={{ width: '100%', height: '100%' }}>
        {/* Background Grids */}
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#grid)" />

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
          const radius = Math.min(Math.max(stat.count * 2, 4), 20);
          return (
            <circle
              key={stat.country_code}
              cx={x} cy={y}
              r={radius}
              fill="var(--danger)"
              fillOpacity="0.2"
              stroke="var(--danger)"
              strokeWidth="1"
              style={{ filter: 'blur(2px)' }}
            />
          );
        })}

        {/* Real-time Attack Arcs */}
        <AnimatePresence>
          {activeThreats.map(threat => (
            <React.Fragment key={threat.id}>
              <motion.path
                initial={{ pathLength: 0, opacity: 0 }}
                animate={{ pathLength: 1, opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 1.5, ease: "easeOut" }}
                d={`M${threat.src[0]},${threat.src[1]} Q${(threat.src[0]+threat.dest[0])/2},${Math.min(threat.src[1], threat.dest[1])-50} ${threat.dest[0]},${threat.dest[1]}`}
                fill="none"
                stroke="var(--danger)"
                strokeWidth="1.5"
                strokeDasharray="5,5"
              />
              <motion.circle
                initial={{ scale: 0 }}
                animate={{ scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }}
                transition={{ repeat: Infinity, duration: 2 }}
                cx={threat.src[0]} cy={threat.src[1]}
                r="3"
                fill="var(--danger)"
              />
            </React.Fragment>
          ))}
        </AnimatePresence>

        {/* Internal Target Node */}
        <circle cx="300" cy="200" r="6" fill="var(--primary)" style={{ filter: 'drop-shadow(0 0 8px var(--primary))' }} />
        <circle cx="300" cy="200" r="15" fill="none" stroke="var(--primary)" strokeWidth="1" strokeDasharray="2,2" className="animate-spin" />
      </svg>

      {/* Legend */}
      <div style={{ position: 'absolute', bottom: '1rem', right: '1.5rem', display: 'flex', gap: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.65rem', fontWeight: 800 }}>
          <div style={{ width: '8px', height: '8px', background: 'var(--danger)', borderRadius: '50%' }} />
          <span>ATTACK ORIGIN</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.65rem', fontWeight: 800 }}>
          <div style={{ width: '8px', height: '8px', background: 'var(--primary)', borderRadius: '50%' }} />
          <span>LOCAL ASSETS</span>
        </div>
      </div>
    </div>
  );
};

export default AttackMap;
