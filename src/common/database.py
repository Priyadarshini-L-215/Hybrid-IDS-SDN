import sqlite3
import json
import logging
import threading
import zlib
import time
from common.config import DB_PATH

logger = logging.getLogger(__name__)

class DatabaseHandler:
    """Manages thread-safe database connections for high-performance logging."""
    _local = threading.local()

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._pruner_thread = None
        self._stop_event = threading.Event()
        
        # Initial connection to setup schema
        conn = self._get_conn()
        self.init_db(conn)
        
        # Start pruner in a separate thread
        self._pruner_thread = threading.Thread(target=self._pruner_loop, daemon=True)
        self._pruner_thread.start()

    def _get_conn(self):
        """Get or create a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            try:
                # Set a generous busy timeout and enable WAL mode for high concurrency
                self._local.conn = sqlite3.connect(self.db_path, timeout=60)
                self._local.conn.execute("PRAGMA journal_mode=WAL")
                self._local.conn.execute("PRAGMA synchronous=NORMAL")
                self._local.conn.execute("PRAGMA cache_size=-20000")
                self._local.conn.execute("PRAGMA busy_timeout=60000")
                self._local.conn.row_factory = sqlite3.Row
            except sqlite3.Error as e:
                logger.error(f"Database connection failed in thread {threading.current_thread().name}: {e}")
                raise
        return self._local.conn

    def _pruner_loop(self):
        """Background task to prune old records every hour."""
        RETENTION_DAYS = 7
        while not self._stop_event.is_set():
            try:
                conn = self._get_conn()
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM alerts WHERE created_at < datetime('now', ?)",
                    (f'-{RETENTION_DAYS} days',)
                )
                deleted = cursor.rowcount
                conn.commit()
                if deleted > 0:
                    logger.info(f"[DB] Pruned {deleted} alerts older than {RETENTION_DAYS} days.")
            except Exception as e:
                logger.error(f"[DB] Pruner error: {e}")
            
            self._stop_event.wait(3600)

    def init_db(self, conn=None):
        """Initialize the database schema."""
        if conn is None: conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                alert_sig TEXT,
                prediction TEXT,
                confidence REAL,
                severity INTEGER,
                category TEXT,
                mitigation TEXT,
                is_mitigated INTEGER DEFAULT 0,
                ja3_hash TEXT,
                ja3_string TEXT,
                raw_event BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                src_ip TEXT,
                prediction TEXT,
                confidence REAL,
                alert_sig TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            ''')
            # Migrations for existing DBs
            try:
                cursor.execute("ALTER TABLE alerts ADD COLUMN mitigation TEXT")
            except: pass
            try:
                cursor.execute("ALTER TABLE alerts ADD COLUMN is_mitigated INTEGER DEFAULT 0")
            except: pass
            try:
                cursor.execute("ALTER TABLE alerts ADD COLUMN ja3_hash TEXT")
                cursor.execute("ALTER TABLE alerts ADD COLUMN ja3_string TEXT")
            except: pass
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_prediction ON alerts(prediction)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)')
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")

    def add_alert(self, alert_data):
        """Insert a new alert into the database."""
        try:
            raw_event = json.dumps(alert_data.get('raw_event'))
            compressed_raw = zlib.compress(raw_event.encode('utf-8'))
            
            conn = self._get_conn()
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO alerts (
                timestamp, event_type, src_ip, src_port, dst_ip, dst_port,
                protocol, alert_sig, prediction, confidence, severity, category, 
                mitigation, is_mitigated, ja3_hash, ja3_string, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('timestamp'),
                alert_data.get('event_type'),
                alert_data.get('src_ip'),
                alert_data.get('src_port'),
                alert_data.get('dst_ip'),
                alert_data.get('dst_port'),
                alert_data.get('protocol'),
                alert_data.get('alert_sig'),
                alert_data.get('prediction'),
                alert_data.get('confidence'),
                alert_data.get('severity'),
                alert_data.get('category'),
                alert_data.get('mitigation'),
                1 if alert_data.get('is_mitigated') else 0,
                alert_data.get('ja3_hash'),
                alert_data.get('ja3_string'),
                sqlite3.Binary(compressed_raw)
            ))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to add alert: {e}")

    def batch_add_alerts(self, alerts_data_list):
        """Insert a batch of alerts in a single transaction."""
        if not alerts_data_list: return
        try:
            params = []
            for alert_data in alerts_data_list:
                raw_json = json.dumps(alert_data.get('raw_event'))
                compressed_raw = zlib.compress(raw_json.encode('utf-8'))
                params.append((
                    alert_data.get('timestamp'),
                    alert_data.get('event_type'),
                    alert_data.get('src_ip'),
                    alert_data.get('src_port'),
                    alert_data.get('dst_ip'),
                    alert_data.get('dst_port'),
                    alert_data.get('protocol'),
                    alert_data.get('alert_sig'),
                    alert_data.get('prediction'),
                    alert_data.get('confidence'),
                    alert_data.get('severity'),
                    alert_data.get('category'),
                    alert_data.get('mitigation'),
                    1 if alert_data.get('is_mitigated') else 0,
                    alert_data.get('ja3_hash'),
                    alert_data.get('ja3_string'),
                    sqlite3.Binary(compressed_raw)
                ))
            
            conn = self._get_conn()
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            cursor.executemany('''
            INSERT INTO alerts (
                timestamp, event_type, src_ip, src_port, dst_ip, dst_port,
                protocol, alert_sig, prediction, confidence, severity, category, 
                mitigation, is_mitigated, ja3_hash, ja3_string, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', params)
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Batch insert failed: {e}")
            # Fallback
            for alert_data in alerts_data_list:
                self.add_alert(alert_data)

    def query_alerts(self, limit=100, filter_type=None, offset=0):
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # Prioritize attack/alert events over normal flow events
            # Order by event_type (alert first) then by timestamp DESC to get recent important events
            query = """
            SELECT * FROM alerts
            WHERE 1=1
            """
            params = []
            
            if filter_type and filter_type.lower() != 'all':
                if filter_type.lower() == 'attack':
                    query += " AND lower(prediction) IN ('attack', 'zero-day anomaly', 'suspicious')"
                else:
                    query += " AND lower(prediction) = ?"
                    params.append(filter_type.lower())
            
            # Order by: alert events first (event_type='alert'), then by timestamp DESC
            query += """
            ORDER BY 
                CASE WHEN event_type = 'alert' THEN 0 ELSE 1 END,
                timestamp DESC
            LIMIT ? OFFSET ?
            """
            params.append(limit)
            params.append(offset)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            alerts = []
            for row in rows:
                alert = dict(row)
                try:
                    raw_data = alert['raw_event']
                    if raw_data:
                        decompressed = zlib.decompress(raw_data).decode('utf-8')
                        alert['raw_event'] = json.loads(decompressed)
                except Exception:
                    alert['raw_event'] = {}
                alerts.append(alert)
            return alerts
        except sqlite3.Error as e:
            logger.error(f"Query failed: {e}")
            return []

    def get_ip_forensics(self, ip):
        """Returns detailed forensic metadata for a specific IP address."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # 1. Timeline metrics
            cursor.execute("""
                SELECT 
                    MIN(timestamp) as first_seen, 
                    MAX(timestamp) as last_seen,
                    COUNT(*) as total_events
                FROM alerts WHERE src_ip = ?
            """, (ip,))
            timeline = dict(cursor.fetchone())
            
            # 2. Prediction distribution
            cursor.execute("""
                SELECT prediction, COUNT(*) as count 
                FROM alerts WHERE src_ip = ? 
                GROUP BY prediction
            """, (ip,))
            predictions = {row['prediction']: row['count'] for row in cursor.fetchall()}
            
            # 3. Get Top Signatures and JA3
            cursor.execute("""
                SELECT alert_sig, COUNT(*) as count FROM alerts 
                WHERE src_ip = ? AND alert_sig IS NOT NULL
                GROUP BY alert_sig ORDER BY count DESC LIMIT 3
            """, (ip,))
            top_sigs = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT ja3_hash, COUNT(*) as count FROM alerts 
                WHERE src_ip = ? AND ja3_hash IS NOT NULL
                GROUP BY ja3_hash ORDER BY count DESC LIMIT 1
            """, (ip,))
            primary_ja3 = cursor.fetchone()
            primary_ja3_hash = primary_ja3['ja3_hash'] if primary_ja3 else None
            
            # 4. Recent history & Latency Stats
            cursor.execute("""
                SELECT timestamp, prediction, confidence, alert_sig, mitigation, raw_event
                FROM alerts WHERE src_ip = ? 
                ORDER BY timestamp DESC LIMIT 10
            """, (ip,))
            history_rows = cursor.fetchall()
            
            history = []
            latencies = []
            cti_data = None
            for row in history_rows:
                h = dict(row)
                try:
                    raw_data = h['raw_event']
                    if raw_data:
                        decompressed = zlib.decompress(raw_data).decode('utf-8')
                        evt = json.loads(decompressed)
                        # Extract latency
                        lat = evt.get("latency", {}).get("total_ms")
                        if lat: latencies.append(lat)
                        # Extract CTI from the most recent event that has it
                        if not cti_data:
                            cti_data = evt.get("enrichment", {}).get("cti")
                except Exception:
                    pass
                h.pop('raw_event', None)
                history.append(h)
            
            avg_latency = sum(latencies) / len(latencies) if latencies else 0
            
            return {
                "ip": ip,
                "first_seen": timeline.get("first_seen"),
                "last_seen": timeline.get("last_seen"),
                "total_events": timeline.get("total_events"),
                "avg_latency_ms": round(avg_latency, 2),
                "cti": cti_data,
                "ja3_hash": primary_ja3_hash,
                "predictions": predictions,
                "top_signatures": top_sigs,
                "history": history
            }
        except sqlite3.Error as e:
            logger.error(f"Forensics query failed for {ip}: {e}")
            return None

    def find_similar_ips(self, ip, limit=5):
        """
        Finds other IPs that exhibit a similar attack pattern.
        Pattern similarity is calculated based on overlapping alert signatures.
        """
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # 1. Get signatures and JA3 for the target IP
            cursor.execute("SELECT DISTINCT alert_sig FROM alerts WHERE src_ip = ? AND alert_sig IS NOT NULL", (ip,))
            target_sigs = [row['alert_sig'] for row in cursor.fetchall()]
            
            cursor.execute("SELECT DISTINCT ja3_hash FROM alerts WHERE src_ip = ? AND ja3_hash IS NOT NULL", (ip,))
            target_ja3s = [row['ja3_hash'] for row in cursor.fetchall()]
            
            if not target_sigs and not target_ja3s:
                return []
                
            # 2. Find IPs that share these patterns
            sig_placeholders = ', '.join(['?'] * len(target_sigs)) if target_sigs else "NULL"
            ja3_placeholders = ', '.join(['?'] * len(target_ja3s)) if target_ja3s else "NULL"
            
            query = f"""
                SELECT 
                    src_ip, 
                    COUNT(DISTINCT alert_sig) as shared_sigs,
                    COUNT(DISTINCT ja3_hash) as shared_ja3s,
                    COUNT(*) as total_alerts
                FROM alerts 
                WHERE (alert_sig IN ({sig_placeholders}) OR ja3_hash IN ({ja3_placeholders}))
                  AND src_ip != ?
                GROUP BY src_ip
                ORDER BY shared_ja3s DESC, shared_sigs DESC, total_alerts DESC
                LIMIT ?
            """
            
            params = []
            if target_sigs: params.extend(target_sigs)
            if target_ja3s: params.extend(target_ja3s)
            params.append(ip)
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            logger.error(f"Similarity search failed for {ip}: {e}")
            return []

    def add_false_positive(self, alert_id):
        """Logs an alert as a false positive for future retraining."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            
            # 1. Get alert data
            cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = cursor.fetchone()
            if not row: return False
            
            alert = dict(row)
            
            # 2. Insert into false_positives table
            cursor.execute("""
                INSERT INTO false_positives (alert_id, src_ip, prediction, confidence, alert_sig)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_id, alert['src_ip'], alert['prediction'], alert['confidence'], alert['alert_sig']))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to log false positive: {e}")
            return False

    def get_stats(self):
        """Calculate system stats."""
        try:
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE lower(category) != 'attack simulation'")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE lower(category) != 'attack simulation' AND lower(prediction) IN ('attack', 'suspicious')")
            attacks = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE lower(category) != 'attack simulation' AND lower(prediction) = 'normal'")
            normal = cursor.fetchone()[0]
            return {
                "total_processed": total,
                "attack_total": attacks,
                "normal_total": normal
            }
        except sqlite3.Error as e:
            logger.error(f"Stats query failed: {e}")
            return {"total_processed": 0, "attack_total": 0, "normal_total": 0}

    def close(self):
        self._stop_event.set()
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

_handler = None
_lock = threading.Lock()

def _get_handler():
    global _handler
    if _handler is None:
        with _lock:
            if _handler is None:
                _handler = DatabaseHandler()
    return _handler

def init_db(): _get_handler().init_db()
def add_alert(data): _get_handler().add_alert(data)
def batch_add_alerts(data_list): _get_handler().batch_add_alerts(data_list)
def query_alerts(limit=100, filter_type=None, offset=0): return _get_handler().query_alerts(limit, filter_type, offset)
def get_recent_alerts(limit=100): return _get_handler().query_alerts(limit)
def get_stats(): return _get_handler().get_stats()
def get_ip_forensics(ip): return _get_handler().get_ip_forensics(ip)
def find_similar_ips(ip): return _get_handler().find_similar_ips(ip)
def add_false_positive(alert_id): return _get_handler().add_false_positive(alert_id)
db = _get_handler()
