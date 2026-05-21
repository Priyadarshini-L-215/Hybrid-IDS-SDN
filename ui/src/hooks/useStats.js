import { useState, useRef, useEffect } from 'react';
import { apiClient } from '../utils/apiClient';

/**
 * Custom hook for managing derived statistics from alerts
 * 
 * Features:
 * - Derives statistics from alert array
 * - Memoized calculations for performance
 * - Tracks deltas for chart updates
 * - Fixed infinite loop by preventing circular dependency
 * 
 * Returns: { stats, chartData }
 */
export const useStats = (alerts) => {
  const [stats, setStats] = useState({
    processed_total: 0,
    attacks: 0,
    normal: 0
  });

  const [chartData, setChartData] = useState(() =>
    Array.from({ length: 20 }, (_, i) => {
      const d = new Date(Date.now() - (19 - i) * 2000);
      return {
        time: d.toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false
        }),
        normal: 0,
        attacks: 0
      };
    })
  );

  const seenIds = useRef(new Set());
  const statsRef = useRef(stats);
  const lastStatsRef = useRef({ processed_total: 0, attacks: 0 });

  // Keep statsRef updated for the interval closure
  useEffect(() => {
    statsRef.current = stats;
  }, [stats]);
  
  // Initial fetch for historical stats to prevent zero-reset on reload
  useEffect(() => {
    const fetchInitialData = async () => {
      try {
        const data = await apiClient.get('/api/alerts');
        if (data) {
          console.log('[Stats] Hydrating stats from API:', data.total_processed);

          const totalProcessed = data.total_processed || 0;
          const attackTotal = data.attack_total || 0;
          const normalTotal = data.normal_total || 0;

          setStats(prev => ({
            processed_total: Math.max(prev.processed_total, totalProcessed),
            attacks: Math.max(prev.attacks, attackTotal),
            normal: Math.max(prev.normal, normalTotal)
          }));

          // Update refs to prevent huge delta on first chart tick
          lastStatsRef.current = {
            processed_total: Math.max(lastStatsRef.current.processed_total, totalProcessed),
            attacks: Math.max(lastStatsRef.current.attacks, attackTotal)
          };

          // Seed seenIds so historical alerts aren't double-counted
          if (data.alerts) {
            data.alerts.forEach(a => {
              const id = a.event_id || a.id;
              if (id) seenIds.current.add(id);
            });
          }
        }
      } catch (err) {
        console.error('[Stats] Failed to fetch initial data:', err);
      }
    };
    
    fetchInitialData();
  }, []);

  // Process new alerts
  useEffect(() => {
    if (!alerts || alerts.length === 0) return;
    
    let newAttacks = 0;
    let newTotal = 0;

    alerts.forEach(a => {
      const id = a.event_id || a.id;
      if (id && !seenIds.current.has(id)) {
        seenIds.current.add(id);
        newTotal++;
        
        const pred = a.prediction?.toLowerCase() || '';
        if (pred.includes('attack') || pred.includes('anomaly') || pred.includes('suspicious')) {
          newAttacks++;
        }
      }
    });

    if (newTotal > 0) {
      setTimeout(() => {
        setStats(prev => ({
          processed_total: prev.processed_total + newTotal,
          attacks: prev.attacks + newAttacks,
          normal: prev.normal + (newTotal - newAttacks)
        }));
      }, 0);
    }
  }, [alerts]);

  // Chart update loop (runs every 2 seconds)
  useEffect(() => {
    const timer = setInterval(() => {
      const currentStats = statsRef.current;
      const lastStats = lastStatsRef.current;

      const deltaTotal = currentStats.processed_total - lastStats.processed_total;
      const deltaAttacks = currentStats.attacks - lastStats.attacks;

      // Handle stats reset (e.g. server restart)
      if (deltaTotal < 0 || deltaAttacks < 0) {
        lastStatsRef.current = {
          processed_total: currentStats.processed_total,
          attacks: currentStats.attacks
        };
        return;
      }

      setChartData(prev => {
        const now = new Date().toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: false
        });

        const newData = {
          time: now,
          normal: Math.max(0, deltaTotal - deltaAttacks),
          attacks: Math.max(0, deltaAttacks)
        };

        return [...prev, newData].slice(-20); // Keep last 20 points
      });

      lastStatsRef.current = {
        processed_total: currentStats.processed_total,
        attacks: currentStats.attacks
      };
    }, 2000);

    return () => clearInterval(timer);
  }, []);

  return {
    stats,
    chartData
  };
};
