from prometheus_client import Counter, Histogram, Gauge

# --- SHARED METRICS ---

# Packets & Flows
PROM_PACKETS = Counter('sentinel_packets_total', 'Total events processed')
PROM_DROPPED = Counter('sentinel_dropped_total', 'Total events dropped due to errors')

# Detection Stats
PROM_ALERTS = Counter('sentinel_alerts_total', 'Total alerts generated', ['classification'])
PROM_LATENCY = Histogram('sentinel_detection_latency_seconds', 'End-to-end detection latency', 
                         buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])

# Mitigation & IPS
PROM_REPUTATION = Gauge('sentinel_reputation_ips', 'Number of IPs tracked in reputation system')
PROM_BLOCKED = Gauge('sentinel_blocked_ips', 'Current number of permanent blocks')
PROM_TEMP_BLOCKED = Gauge('sentinel_temp_blocked_ips', 'Current number of temporary blocks')

# Resource Usage (Optional, basic)
PROM_WORKER_TASKS = Gauge('sentinel_worker_tasks_active', 'Number of active worker tasks')
