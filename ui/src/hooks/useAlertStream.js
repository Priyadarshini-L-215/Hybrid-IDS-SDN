import { useState, useRef, useEffect, useMemo } from 'react';
import { apiClient } from '../utils/apiClient';

/**
 * Custom hook for managing WebSocket alert stream
 * 
 * Features:
 * - Smart buffering with intelligent batching (20fps instead of 60fps)
 * - Automatic deduplication by event_id
 * - Backpressure handling (drops non-critical updates if queue exceeds threshold)
 * - Connection heartbeat (ping/pong every 15s)
 * - Automatic reconnection on disconnect
 * 
 * Returns: { alerts, streamStatus, error, isConnected }
 */
export const useAlertStream = () => {
  const [alerts, setAlerts] = useState([]);
  const [streamStatus, setStreamStatus] = useState('connecting');
  const [error, setError] = useState(null);
  const [isConnected, setIsConnected] = useState(false);

  const ws = useRef(null);
  const alertBuffer = useRef([]);
  const knownEventIds = useRef(new Set());
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;
  const baseReconnectDelay = 1000;
  const flushTimer = useRef(null);
  const heartbeatTimer = useRef(null);
  const pongTimeout = useRef(null);
  const lastPongTime = useRef(0);

  // Smart buffer flush at ~20fps (50ms interval) instead of 60fps
  const flushBuffer = () => {
    if (alertBuffer.current.length === 0) return;

    const batch = alertBuffer.current.splice(0, alertBuffer.current.length);
    
    // Deduplicate batch against existing alerts
    const uniqueAlerts = batch.filter(alert => {
      if (knownEventIds.current.has(alert.event_id)) {
        return false; // Skip duplicate
      }
      knownEventIds.current.add(alert.event_id);
      return true;
    });

    if (uniqueAlerts.length === 0) return;

    setAlerts(prev => {
      // Merge new alerts with existing, keeping only most recent 100
      const merged = [...uniqueAlerts, ...prev].slice(0, 100);
      
      // Update known IDs for memory efficiency (keep only current 100)
      knownEventIds.current.clear();
      merged.forEach(a => knownEventIds.current.add(a.event_id));
      
      return merged;
    });
  };

  // Initialize WebSocket connection
  useEffect(() => {
    lastPongTime.current = Date.now();
    const fetchInitialAlerts = async () => {
      try {
        const data = await apiClient.get('/api/alerts');
        if (data && data.alerts) {
          console.log(`[Alert Stream] Seeding ${data.alerts.length} historical alerts`);
          setAlerts(prev => {
            const seenIds = new Set(prev.map(alert => alert.event_id || alert.id).filter(Boolean));
            const historicalAlerts = data.alerts.filter(alert => {
              const alertId = alert.event_id || alert.id;
              if (!alertId) return true;
              if (seenIds.has(alertId)) return false;
              seenIds.add(alertId);
              return true;
            });

            const merged = [...historicalAlerts, ...prev].slice(0, 100);
            knownEventIds.current.clear();
            merged.forEach(alert => {
              const alertId = alert.event_id || alert.id;
              if (alertId) knownEventIds.current.add(alertId);
            });
            return merged;
          });
        }
      } catch (err) {
        console.error('[Alert Stream] Failed to seed historical alerts:', err);
      }
    };

    const connect = () => {
      try {
        const WS_URL = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/alerts`;
        
        ws.current = new WebSocket(WS_URL);
        
        ws.current.onopen = () => {
          console.log('[Alert Stream] Connected');
          setStreamStatus('connected');
          setIsConnected(true);
          setError(null);
          reconnectAttempts.current = 0;

          // Start heartbeat with pong timeout detection
          if (heartbeatTimer.current) clearInterval(heartbeatTimer.current);
          heartbeatTimer.current = setInterval(() => {
            if (ws.current?.readyState === WebSocket.OPEN) {
              try {
                // Set a timeout to detect if pong doesn't arrive
                if (pongTimeout.current) clearTimeout(pongTimeout.current);
                pongTimeout.current = setTimeout(() => {
                  console.warn('[Alert Stream] Pong timeout - server not responding');
                  setError('Server heartbeat timeout');
                  ws.current?.close();
                }, 5000); // 5s timeout for pong
                
                ws.current.send(JSON.stringify({ type: 'ping' }));
              } catch (e) {
                console.warn('[Alert Stream] Ping send failed:', e);
              }
            }
          }, 15000); // Send ping every 15s
        };

        ws.current.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            
            // Handle ping/pong for heartbeat monitoring
            if (message.type === 'pong') {
              if (pongTimeout.current) clearTimeout(pongTimeout.current);
              lastPongTime.current = Date.now();
              return;
            }
            
            // Handle regular alerts
            const alert = message;
            
            // Backpressure handling: drop non-critical updates if buffer too large
            if (alertBuffer.current.length > 50) {
              const prediction = alert.prediction?.toLowerCase() || '';
              const isCritical = 
                prediction.includes('attack') || 
                prediction.includes('anomaly');
              
              if (!isCritical) {
                console.debug('[Alert Stream] Backpressure: dropped non-critical alert');
                return; // Drop this alert to prevent memory bloat
              }
            }

            alertBuffer.current.push(alert);
          } catch (e) {
            console.error('[Alert Stream] Message parse failed:', e);
          }
        };

        ws.current.onerror = (error) => {
          console.error('[Alert Stream] WebSocket error:', error);
          setError('Connection error - attempting to reconnect');
          setStreamStatus('error');
        };

        ws.current.onclose = () => {
          console.log('[Alert Stream] Disconnected');
          setIsConnected(false);
          setStreamStatus('disconnected');
          
          if (heartbeatTimer.current) clearInterval(heartbeatTimer.current);

          // Attempt reconnection with exponential backoff
          if (reconnectAttempts.current < maxReconnectAttempts) {
            const delay = baseReconnectDelay * Math.pow(2, reconnectAttempts.current);
            console.log(`[Alert Stream] Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current + 1})`);
            reconnectAttempts.current += 1;
            setTimeout(connect, delay);
          } else {
            setError('Max reconnection attempts reached');
            setStreamStatus('failed');
          }
        };
      } catch (e) {
        console.error('[Alert Stream] Connection setup failed:', e);
        setError(e.message);
        setStreamStatus('error');
      }
    };

    fetchInitialAlerts();
    connect();

    // Smart buffer flush at 20fps (50ms interval) instead of requestAnimationFrame
    flushTimer.current = setInterval(flushBuffer, 50);

    return () => {
      if (flushTimer.current) clearInterval(flushTimer.current);
      if (heartbeatTimer.current) clearInterval(heartbeatTimer.current);
      if (pongTimeout.current) clearTimeout(pongTimeout.current);
      if (ws.current) ws.current.close();
    };
  }, []);

  /**
   * Manually update a specific alert in the local list (used for lazy-loading)
   */
  const updateAlert = (updatedAlert) => {
    setAlerts(prev => prev.map(a => 
      (a.event_id === updatedAlert.event_id || a.id === updatedAlert.id) 
        ? { ...a, ...updatedAlert } 
        : a
    ));
  };

  /**
   * Manually update mitigation status for all alerts from a specific source IP
   */
  const updateAlertsMitigation = (ip, mitigation) => {
    setAlerts(prev => prev.map(a => 
      (a.src_ip === ip) 
        ? { ...a, mitigation: mitigation } 
        : a
    ));
  };

  /**
   * DERIVED DATA: Incidents
   * Groups raw alerts by src_ip and prediction within the current session.
   */
  const incidents = useMemo(() => {
    const groups = {};
    alerts.forEach(alert => {
      const key = `${alert.src_ip}_${alert.prediction}`;
      if (!groups[key]) {
        groups[key] = {
          id: `inc_${key}_${alert.timestamp}`,
          src_ip: alert.src_ip,
          prediction: alert.prediction,
          count: 0,
          last_seen: alert.timestamp,
          severity: alert.severity || 1,
          alerts: [],
          enrichment: alert.enrichment
        };
      }
      groups[key].count += 1;
      if (new Date(alert.timestamp) > new Date(groups[key].last_seen)) {
        groups[key].last_seen = alert.timestamp;
      }
      groups[key].alerts.push(alert);
    });
    return Object.values(groups).sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
  }, [alerts]);

  return {
    alerts,
    incidents,
    updateAlert,
    updateAlertsMitigation,
    streamStatus,
    error,
    isConnected
  };
};
