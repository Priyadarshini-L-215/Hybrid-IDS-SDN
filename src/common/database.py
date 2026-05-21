import aiosqlite
import sqlite3
import orjson
import structlog
import asyncio
import zlib
import functools
import inspect
from typing import List, Dict, Any, Optional, Union
from common.config import DB_PATH, DB_RETENTION_DAYS

logger = structlog.get_logger(__name__)

class DatabaseHandler:
    """Manages asynchronous database connections using aiosqlite."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._conn = None
        self._lock = asyncio.Lock()
        self._pruner_task = None

    @staticmethod
    @functools.lru_cache(maxsize=500) # Increased cache size
    def _decompress_event(raw_data: bytes) -> dict:
        """Cached decompression and JSON parsing of forensic events."""
        try:
            decompressed = zlib.decompress(raw_data)
            return orjson.loads(decompressed)
        except Exception:
            return {}

    async def _get_conn(self) -> aiosqlite.Connection:
        """Get or create a persistent async database connection."""
        async with self._lock:
            if self._conn is None:
                try:
                    self._conn = await aiosqlite.connect(self.db_path, timeout=60)
                    await self._conn.execute("PRAGMA journal_mode=WAL")
                    await self._conn.execute("PRAGMA synchronous=NORMAL")
                    await self._conn.execute("PRAGMA cache_size=-20000")
                    await self._conn.execute("PRAGMA busy_timeout=60000")
                    self._conn.row_factory = aiosqlite.Row
                    
                    # Initialize schema if new connection
                    await self.init_db(self._conn)
                    
                    # Start pruner task
                    if self._pruner_task is None:
                        self._pruner_task = asyncio.create_task(self._pruner_loop())
                except Exception as e:
                    logger.error("Database connection failed", error=str(e))
                    raise
            return self._conn

    async def _pruner_loop(self):
        """Background task to prune old records every hour."""
        while True:
            try:
                conn = await self._get_conn()
                async with conn.execute("DELETE FROM alerts WHERE created_at < datetime('now', ?)", (f'-{DB_RETENTION_DAYS} days',)):
                    deleted = conn.total_changes
                    await conn.commit()
                    if deleted > 0:
                        logger.info("Pruned old alerts", count=deleted, retention_days=DB_RETENTION_DAYS)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Pruner error", error=str(e))
            
            await asyncio.sleep(3600)

    async def init_db(self, conn: Optional[aiosqlite.Connection] = None):
        """Initialize the database schema."""
        if conn is None:
            conn = self._conn
        
        if conn is None:
            logger.error("Attempted to init_db without connection")
            return

        try:
            await conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
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
                shap_top3 TEXT,
                xai_explanation TEXT,
                enrichment TEXT,
                mitre_id TEXT,
                anomaly_score REAL,
                correlation_id TEXT,
                raw_event BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # Optimized Indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ts ON alerts (src_ip, created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_pred_ts ON alerts (prediction, created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts (event_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_prediction ON alerts(prediction)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)")

            await conn.execute('''
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
            
            # Migrations for existing columns (wrapped in try/except)
            migrations = [
                "ALTER TABLE alerts ADD COLUMN event_id TEXT",
                "ALTER TABLE alerts ADD COLUMN ja3_hash TEXT",
                "ALTER TABLE alerts ADD COLUMN ja3_string TEXT",
                "ALTER TABLE alerts ADD COLUMN mitigation TEXT",
                "ALTER TABLE alerts ADD COLUMN is_mitigated INTEGER DEFAULT 0",
                "ALTER TABLE alerts ADD COLUMN shap_top3 TEXT",
                "ALTER TABLE alerts ADD COLUMN xai_explanation TEXT",
                "ALTER TABLE alerts ADD COLUMN enrichment TEXT",
                "ALTER TABLE alerts ADD COLUMN mitre_id TEXT",
                "ALTER TABLE alerts ADD COLUMN anomaly_score REAL",
                "ALTER TABLE alerts ADD COLUMN correlation_id TEXT"
            ]
            for m in migrations:
                try:
                    await conn.execute(m)
                except sqlite3.OperationalError as e:
                    if "duplicate column name" not in str(e).lower():
                        logger.debug("Migration already applied or failed", sql=m, error=str(e))

            await conn.commit()
        except Exception as e:
            logger.error("Failed to initialize database", error=str(e))
            if conn:
                await conn.rollback()

    async def add_alert(self, alert_data: Dict[str, Any]):
        """Insert a new alert into the database."""
        try:
            def _prepare_payload():
                raw_json = orjson.dumps(alert_data.get('raw_event'))
                return zlib.compress(raw_json)
                
            compressed_raw = await asyncio.to_thread(_prepare_payload)
            
            conn = await self._get_conn()
            await conn.execute('''
            INSERT OR IGNORE INTO alerts (
                event_id, timestamp, event_type, src_ip, src_port, dst_ip, dst_port,
                protocol, alert_sig, prediction, confidence, severity, category, 
                mitigation, is_mitigated, ja3_hash, ja3_string, 
                shap_top3, xai_explanation, enrichment, mitre_id, anomaly_score, correlation_id, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('event_id'),
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
                orjson.dumps(alert_data.get('shap_top3', [])).decode(),
                alert_data.get('xai_explanation', ''),
                orjson.dumps(alert_data.get('enrichment', {})).decode(),
                alert_data.get('mitre', {}).get('id') if isinstance(alert_data.get('mitre'), dict) else alert_data.get('mitre_id'),
                alert_data.get('anomaly_score', 0.0),
                alert_data.get('forensics', {}).get('correlation_id') if isinstance(alert_data.get('forensics'), dict) else alert_data.get('correlation_id'),
                compressed_raw
            ))
            await conn.commit()
        except Exception as e:
            logger.error("Failed to add alert", error=str(e))
            await conn.rollback()

    async def batch_add_alerts(self, alerts_data_list: List[Dict[str, Any]]):
        """Insert a batch of alerts in a single transaction."""
        if not alerts_data_list: return
        try:
            def _prepare_batch():
                params = []
                for alert_data in alerts_data_list:
                    raw_json = orjson.dumps(alert_data.get('raw_event'))
                    compressed_raw = zlib.compress(raw_json)
                    params.append((
                        alert_data.get('event_id'),
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
                        orjson.dumps(alert_data.get('shap_top3', [])).decode(),
                        alert_data.get('xai_explanation', ''),
                        orjson.dumps(alert_data.get('enrichment', {})).decode(),
                        alert_data.get('mitre', {}).get('id') if isinstance(alert_data.get('mitre'), dict) else alert_data.get('mitre_id'),
                        alert_data.get('anomaly_score', 0.0),
                        alert_data.get('forensics', {}).get('correlation_id') if isinstance(alert_data.get('forensics'), dict) else alert_data.get('correlation_id'),
                        compressed_raw
                    ))
                return params
            
            # Offload serialization and compression to background thread
            params = await asyncio.to_thread(_prepare_batch)
            
            conn = await self._get_conn()
            await conn.executemany('''
            INSERT OR IGNORE INTO alerts (
                event_id, timestamp, event_type, src_ip, src_port, dst_ip, dst_port,
                protocol, alert_sig, prediction, confidence, severity, category, 
                mitigation, is_mitigated, ja3_hash, ja3_string, 
                shap_top3, xai_explanation, enrichment, mitre_id, anomaly_score, correlation_id, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', params)
            await conn.commit()
        except Exception as e:
            logger.error("Batch insert failed", error=str(e))
            await conn.rollback()

    async def query_alerts(self, limit=100, filter_type=None, offset=0) -> List[Dict[str, Any]]:
        try:
            conn = await self._get_conn()
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            
            if filter_type and filter_type.lower() != 'all':
                if filter_type.lower() == 'attack':
                    query += " AND lower(prediction) IN ('attack', 'zero-day anomaly', 'suspicious', 'anomaly')"
                else:
                    query += " AND lower(prediction) = ?"
                    params.append(filter_type.lower())
            
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
            
            alerts = []
            for row in rows:
                alert = dict(row)
                for field in ['shap_top3', 'enrichment']:
                    if alert.get(field):
                        try:
                            alert[field] = orjson.loads(alert[field])
                        except Exception:
                            alert[field] = {} if field == 'enrichment' else []
                alert.pop('raw_event', None)
                alerts.append(alert)
            return alerts
        except Exception as e:
            logger.error("Query failed", error=str(e))
            return []

    async def search_alerts(self, query_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Advanced search with multiple filters."""
        try:
            conn = await self._get_conn()
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []

            if query_params.get("src_ip"):
                query += " AND src_ip LIKE ?"
                params.append(f"%{query_params['src_ip']}%")
            
            if query_params.get("prediction"):
                query += " AND lower(prediction) = ?"
                params.append(query_params['prediction'].lower())
            
            if query_params.get("severity"):
                query += " AND severity >= ?"
                params.append(query_params['severity'])
            
            if query_params.get("start_time"):
                query += " AND timestamp >= ?"
                params.append(query_params['start_time'])
            
            if query_params.get("end_time"):
                query += " AND timestamp <= ?"
                params.append(query_params['end_time'])
            
            if query_params.get("protocol"):
                query += " AND lower(protocol) = ?"
                params.append(query_params['protocol'].lower())

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(query_params.get("limit", 100))

            async with conn.execute(query, params) as cursor:
                rows = await cursor.fetchall()
            
            alerts = []
            for row in rows:
                alert = dict(row)
                for field in ['shap_top3', 'enrichment']:
                    if alert.get(field):
                        try: alert[field] = orjson.loads(alert[field])
                        except Exception: alert[field] = {}
                alert.pop('raw_event', None)
                alerts.append(alert)
            return alerts
        except Exception as e:
            logger.error("Search failed", error=str(e))
            return []

    async def get_mitre_stats(self) -> List[Dict[str, Any]]:
        """Aggregates alert counts by MITRE ATT&CK tactic/ID."""
        try:
            conn = await self._get_conn()
            query = """
                SELECT mitre_id, COUNT(*) as count, MAX(created_at) as last_seen
                FROM alerts WHERE mitre_id IS NOT NULL
                GROUP BY mitre_id ORDER BY count DESC
            """
            async with conn.execute(query) as cursor:
                return [dict(row) for row in await cursor.fetchall()]
        except Exception as e:
            logger.error("MITRE stats failed", error=str(e))
            return []

    async def get_geo_stats(self) -> List[Dict[str, Any]]:
        """Aggregates threat origins for map visualization."""
        try:
            conn = await self._get_conn()
            # This requires parsing JSON enrichment in SQLite or doing it in Python
            # For simplicity and performance, we'll fetch recent malicious alerts and aggregate here
            query = """
                SELECT enrichment FROM alerts 
                WHERE lower(prediction) IN ('attack', 'anomaly', 'zero-day anomaly')
                AND enrichment IS NOT NULL
                ORDER BY created_at DESC LIMIT 500
            """
            async with conn.execute(query) as cursor:
                rows = await cursor.fetchall()
            
            stats = {}
            for row in rows:
                try:
                    data = orjson.loads(row['enrichment'])
                    cc = data.get("country_code")
                    if cc:
                        if cc not in stats:
                            stats[cc] = {"count": 0, "lat": data.get("lat"), "lon": data.get("lon")}
                        stats[cc]["count"] += 1
                except Exception: continue
            
            return [{"country_code": k, **v} for k, v in stats.items()]
        except Exception as e:
            logger.error("Geo stats failed", error=str(e))
            return []

    async def get_ip_forensics(self, ip: str) -> Optional[Dict[str, Any]]:
        """Returns detailed forensic metadata for a specific IP address."""
        try:
            conn = await self._get_conn()
            
            # 1. Timeline metrics
            async with conn.execute("""
                SELECT MIN(timestamp) as first_seen, MAX(timestamp) as last_seen, COUNT(*) as total_events
                FROM alerts WHERE src_ip = ?
            """, (ip,)) as cursor:
                row = await cursor.fetchone()
                timeline = dict(row) if row else {"total_events": 0}
            
            if timeline.get("total_events") == 0:
                return None

            # 2. Prediction distribution
            async with conn.execute("""
                SELECT prediction, COUNT(*) as count FROM alerts WHERE src_ip = ? GROUP BY prediction
            """, (ip,)) as cursor:
                predictions = {row['prediction']: row['count'] for row in await cursor.fetchall()}
            
            # 3. Top Signatures and JA3
            async with conn.execute("""
                SELECT alert_sig, COUNT(*) as count FROM alerts 
                WHERE src_ip = ? AND alert_sig IS NOT NULL
                GROUP BY alert_sig ORDER BY count DESC LIMIT 3
            """, (ip,)) as cursor:
                top_sigs = [dict(row) for row in await cursor.fetchall()]

            async with conn.execute("""
                SELECT ja3_hash, COUNT(*) as count FROM alerts 
                WHERE src_ip = ? AND ja3_hash IS NOT NULL
                GROUP BY ja3_hash ORDER BY count DESC LIMIT 1
            """, (ip,)) as cursor:
                primary_ja3_row = await cursor.fetchone()
                primary_ja3_hash = primary_ja3_row['ja3_hash'] if primary_ja3_row else None
            
            # 4. Recent history
            async with conn.execute("""
                SELECT timestamp, prediction, confidence, alert_sig, mitigation, 
                       shap_top3, xai_explanation, enrichment, anomaly_score, raw_event
                FROM alerts WHERE src_ip = ? 
                ORDER BY timestamp DESC LIMIT 20
            """, (ip,)) as cursor:
                history_rows = await cursor.fetchall()
            
            history = []
            latencies = []
            cti_data = None
            for row in history_rows:
                h = dict(row)
                if h.get('raw_event'):
                    evt = self._decompress_event(h['raw_event'])
                    lat = evt.get("latency", {}).get("total_ms")
                    if lat: latencies.append(lat)
                    if not cti_data:
                        cti_data = evt.get("enrichment", {}).get("cti")
                
                for field in ['shap_top3', 'enrichment']:
                    if h.get(field):
                        try: h[field] = orjson.loads(h[field])
                        except Exception: h[field] = {} if field == 'enrichment' else []
                
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
        except Exception as e:
            logger.error("Forensics query failed", ip=ip, error=str(e))
            return None

    async def find_similar_ips(self, ip: str, limit=5) -> List[Dict[str, Any]]:
        try:
            conn = await self._get_conn()
            async with conn.execute("SELECT DISTINCT alert_sig FROM alerts WHERE src_ip = ? AND alert_sig IS NOT NULL", (ip,)) as cursor:
                target_sigs = [row['alert_sig'] for row in await cursor.fetchall()]
            
            async with conn.execute("SELECT DISTINCT ja3_hash FROM alerts WHERE src_ip = ? AND ja3_hash IS NOT NULL", (ip,)) as cursor:
                target_ja3s = [row['ja3_hash'] for row in await cursor.fetchall()]
            
            if not target_sigs and not target_ja3s: return []
                
            sig_placeholders = ', '.join(['?'] * len(target_sigs)) if target_sigs else "NULL"
            ja3_placeholders = ', '.join(['?'] * len(target_ja3s)) if target_ja3s else "NULL"
            
            query = f"""
                SELECT src_ip, COUNT(DISTINCT alert_sig) as shared_sigs, COUNT(DISTINCT ja3_hash) as shared_ja3s, COUNT(*) as total_alerts
                FROM alerts 
                WHERE (alert_sig IN ({sig_placeholders}) OR ja3_hash IN ({ja3_placeholders})) AND src_ip != ?
                GROUP BY src_ip ORDER BY shared_ja3s DESC, shared_sigs DESC, total_alerts DESC LIMIT ?
            """
            params = target_sigs + target_ja3s + [ip, limit]
            async with conn.execute(query, params) as cursor:
                return [dict(row) for row in await cursor.fetchall()]
        except Exception as e:
            logger.error("Similarity search failed", ip=ip, error=str(e))
            return []

    async def add_false_positive(self, alert_id: int) -> bool:
        try:
            conn = await self._get_conn()
            async with conn.execute("SELECT src_ip, prediction, confidence, alert_sig FROM alerts WHERE id = ?", (alert_id,)) as cursor:
                alert = await cursor.fetchone()
            
            if not alert: return False
            
            await conn.execute("""
                INSERT INTO false_positives (alert_id, src_ip, prediction, confidence, alert_sig)
                VALUES (?, ?, ?, ?, ?)
            """, (alert_id, alert['src_ip'], alert['prediction'], alert['confidence'], alert['alert_sig']))
            await conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to log false positive", alert_id=alert_id, error=str(e))
            await conn.rollback()
            return False

    async def get_stats(self) -> Dict[str, int]:
        try:
            conn = await self._get_conn()
            async with conn.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN lower(prediction) IN ('attack', 'suspicious', 'anomaly', 'zero-day anomaly') THEN 1 ELSE 0 END) as attacks,
                       SUM(CASE WHEN lower(prediction) = 'normal' THEN 1 ELSE 0 END) as normal
                FROM alerts WHERE lower(category) != 'attack simulation'
            """) as cursor:
                r = await cursor.fetchone()
                row = dict(r) if r else {"total": 0, "attacks": 0, "normal": 0}
            
            return {
                "total_processed": row['total'] or 0,
                "attack_total": row['attacks'] or 0,
                "normal_total": row['normal'] or 0
            }
        except Exception as e:
            logger.error("Stats query failed", error=str(e))
            return {"total_processed": 0, "attack_total": 0, "normal_total": 0}

    async def get_alert_by_id(self, alert_id: Union[int, str]) -> Optional[Dict[str, Any]]:
        try:
            conn = await self._get_conn()
            if str(alert_id).isdigit():
                async with conn.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)) as cursor:
                    row = await cursor.fetchone()
            else:
                async with conn.execute("SELECT * FROM alerts WHERE event_id = ?", (str(alert_id),)) as cursor:
                    row = await cursor.fetchone()
            
            if not row: return None
            alert = dict(row)
            if alert.get("raw_event"):
                alert["raw_event"] = self._decompress_event(alert["raw_event"])
            for field in ("shap_top3", "enrichment"):
                if alert.get(field):
                    try: alert[field] = orjson.loads(alert[field])
                    except Exception: alert[field] = {} if field == "enrichment" else []
            return alert
        except Exception as e:
            logger.error("get_alert_by_id failed", alert_id=alert_id, error=str(e))
            return None

    async def get_alert_signature(self, alert_id: int) -> Optional[str]:
        try:
            conn = await self._get_conn()
            async with conn.execute("SELECT alert_sig FROM alerts WHERE id = ?", (alert_id,)) as cursor:
                row = await cursor.fetchone()
            return row["alert_sig"] if row else None
        except Exception as e:
            logger.error("get_alert_signature failed", alert_id=alert_id, error=str(e))
            return None

    async def close(self):
        if self._pruner_task:
            self._pruner_task.cancel()
            try: await self._pruner_task
            except asyncio.CancelledError: pass
        if self._conn:
            await self._conn.close()
            self._conn = None

_handler = None
_lock = asyncio.Lock()

async def _get_handler():
    global _handler
    if _handler is None:
        async with _lock:
            if _handler is None:
                _handler = DatabaseHandler()
    return _handler

async def init_db(): await (await _get_handler())._get_conn()
async def add_alert(data): await (await _get_handler()).add_alert(data)
async def batch_add_alerts(data_list): await (await _get_handler()).batch_add_alerts(data_list)
async def query_alerts(limit=100, filter_type=None, offset=0): return await (await _get_handler()).query_alerts(limit, filter_type, offset)
async def get_recent_alerts(limit=100): return await (await _get_handler()).query_alerts(limit)
async def get_stats(): return await (await _get_handler()).get_stats()
async def get_ip_forensics(ip): return await (await _get_handler()).get_ip_forensics(ip)
async def find_similar_ips(ip, limit=5): return await (await _get_handler()).find_similar_ips(ip, limit)
async def add_false_positive(alert_id): return await (await _get_handler()).add_false_positive(alert_id)
async def get_alert_by_id(alert_id): return await (await _get_handler()).get_alert_by_id(alert_id)
async def get_alert_signature(alert_id: int): return await (await _get_handler()).get_alert_signature(alert_id)
async def search_alerts(params): return await (await _get_handler()).search_alerts(params)
async def get_mitre_stats(): return await (await _get_handler()).get_mitre_stats()
async def get_geo_stats(): return await (await _get_handler()).get_geo_stats()

# For backward compatibility if someone uses 'db' object directly
class DBProxy:
    def __getattr__(self, name):
        async def wrapper(*args, **kwargs):
            handler = await _get_handler()
            method = getattr(handler, name)
            if inspect.iscoroutinefunction(method):
                return await method(*args, **kwargs)
            return method(*args, **kwargs)
        return wrapper
db = DBProxy()
