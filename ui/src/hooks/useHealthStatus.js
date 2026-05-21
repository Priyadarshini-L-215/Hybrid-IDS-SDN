import { useState, useRef, useEffect } from 'react';
import { apiClient } from '../utils/apiClient';

/**
 * Custom hook for managing health status polling
 * 
 * Features:
 * - Polls /api/pipeline/status every 3s
 * - Debounced updates to prevent excessive re-renders
 * - Detects connection issues
 * - Returns health data and connection status
 * 
 * Returns: { health, isHealthy, lastUpdate, isLoading, error }
 */
export const useHealthStatus = () => {
  const [health, setHealth] = useState(null);
  const [isHealthy, setIsHealthy] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const pollTimerRef = useRef(null);
  const lastHealthRef = useRef(null);

  const fetchStatus = async (isPolling = false) => {
    try {
      const data = await apiClient.get('/api/pipeline/status', {
        timeout: 10000 // 10s timeout
      });
      
      // Only update if data actually changed (reduce re-renders)
      if (JSON.stringify(data) !== JSON.stringify(lastHealthRef.current)) {
        setHealth(data);
        lastHealthRef.current = data;
        setLastUpdate(new Date().toISOString());

        // Determine if system is healthy
        const healthy = 
          data?.checks?.consumer_running && 
          data?.checks?.redis_ok;
        setIsHealthy(healthy);
      }

      setError(null);
    } catch (e) {
      setError(`Health check failed: ${e.message}`);
      setIsHealthy(false);
    } finally {
      if (!isPolling) setIsLoading(false);
    }
  };

  // Initial fetch and setup polling
  useEffect(() => {
    // Defer initial status fetch to prevent cascading renders during mount
    const timer = setTimeout(() => {
      fetchStatus(false);
    }, 0);

    // Poll every 3 seconds
    pollTimerRef.current = setInterval(() => fetchStatus(true), 3000);

    return () => {
      clearTimeout(timer);
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Manual refresh function
  const refresh = () => {
    setIsLoading(true);
    fetchStatus(false);
  };

  return {
    health,
    setHealth,
    isHealthy,
    lastUpdate,
    isLoading,
    error,
    refresh
  };
};
