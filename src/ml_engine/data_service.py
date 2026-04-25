import json
import logging
import sqlite3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from threading import Thread
from common.database import query_alerts, get_stats
from common.config import DATA_SERVICE_PORT

logger = logging.getLogger(__name__)

class DataServiceHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path.startswith('/api/alerts'):
                params = parse_qs(urlparse(self.path).query)
                limit = int(params.get('limit', ['500'])[0])
                offset = int(params.get('offset', ['0'])[0])
                limit = max(limit, 1)
                offset = max(offset, 0)
                data = query_alerts(limit=limit, offset=offset)
                self._send_response(data)
            elif self.path == '/api/stats':
                data = get_stats()
                self._send_response(data)
            else:
                self.send_error(404, "Not Found")
        except (ValueError, OSError, sqlite3.Error) as exc:
            logger.error(f"Data Service Error: {exc}")
            self.send_error(500, str(exc))

    def _send_response(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def log_message(self, format, *args):
        # Silence default logging to avoid cluttering consumer console
        pass

def start_data_service():
    """Starts the internal data bridge service on port 5001."""
    server = HTTPServer(('0.0.0.0', DATA_SERVICE_PORT), DataServiceHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"[Data Service] Bridge active on 0.0.0.0:{DATA_SERVICE_PORT}")
