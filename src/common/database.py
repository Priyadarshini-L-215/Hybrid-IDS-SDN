import sqlite3
import json
import logging
from datetime import datetime, timezone
from common.config import BASE_DIR

DB_PATH = BASE_DIR / "data" / "alerts.db"
logger = logging.getLogger(__name__)

class DatabaseHandler:
    """Manages persistent database connections for high-performance logging."""
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.conn = None
        self._connect()

    def _connect(self):
        try:
            # Allow multi-threaded access (synchronization handled by SQLite or app logic)
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def init_db(self):
        """Initialize the database schema."""
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            alert_sig TEXT,
            prediction TEXT,
            confidence REAL,
            severity INTEGER,
            category TEXT,
            raw_event TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_prediction ON alerts(prediction)')
        self.conn.commit()

    def add_alert(self, alert_data):
        """Insert a new alert into the database using the persistent connection."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            INSERT INTO alerts (
                timestamp, event_type, src_ip, src_port, dest_ip, dest_port,
                protocol, alert_sig, prediction, confidence, severity, category, raw_event
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert_data.get('timestamp'),
                alert_data.get('event_type'),
                alert_data.get('src_ip'),
                alert_data.get('src_port'),
                alert_data.get('dest_ip'),
                alert_data.get('dest_port'),
                alert_data.get('protocol'),
                alert_data.get('alert_sig'),
                alert_data.get('prediction'),
                alert_data.get('confidence'),
                alert_data.get('severity'),
                alert_data.get('category'),
                json.dumps(alert_data.get('raw_event'))
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to add alert: {e}")

    def query_alerts(self, limit=100, filter_type=None):
        cursor = self.conn.cursor()
        query = "SELECT * FROM alerts"
        params = []
        if filter_type and filter_type.lower() != 'all':
            query += " WHERE lower(prediction) = ?"
            params.append(filter_type.lower())
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            alert = dict(row)
            alert['raw_event'] = json.loads(alert['raw_event'])
            alerts.append(alert)
        return alerts

    def get_stats(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE lower(prediction) = 'attack'")
        attacks = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE lower(prediction) = 'normal'")
        normal = cursor.fetchone()[0]
        return {
            "total_processed": total,
            "attack_total": attacks,
            "normal_total": normal
        }

    def close(self):
        if self.conn:
            self.conn.close()

# --- Legacy Functional Interface (for compatibility) ---
_default_handler = None

def _get_handler():
    global _default_handler
    if _default_handler is None:
        _default_handler = DatabaseHandler()
    return _default_handler

def init_db(): _get_handler().init_db()
def add_alert(data): _get_handler().add_alert(data)
def query_alerts(limit=100, filter_type=None): return _get_handler().query_alerts(limit, filter_type)
def get_stats(): return _get_handler().get_stats()
