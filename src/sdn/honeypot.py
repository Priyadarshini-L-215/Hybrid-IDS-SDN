# honeypot.py - Dionaea-inspired simple TCP honeypot for Sentinel
# Listens on common attack ports and logs connection metadata.

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("data/logs/honeypot.jsonl")
PORTS = [21, 22, 23, 80, 443, 3306, 3389, 5900, 8080]

BANNERS = {
    21: b"220 (vsFTPd 3.0.3)\r\n",
    22: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
    23: b"\r\n\r\nUser Access Verification\r\n\r\nUsername: ",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><body><h1>It works!</h1></body></html>",
}

class HoneypotServer:
    def __init__(self):
        self.stats = {"total_connections": 0, "unique_ips": set()}

    async def handle_connection(self, reader, writer):
        addr = writer.get_extra_info('peername')
        local_addr = writer.get_extra_info('sockname')
        port = local_addr[1]
        ip = addr[0]

        self.stats["total_connections"] += 1
        self.stats["unique_ips"].add(ip)

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "connection",
            "src_ip": ip,
            "src_port": addr[1],
            "dst_port": port,
            "proto": "TCP"
        }

        print(f"[HONEYPOT] Connection from {ip}:{addr[1]} on port {port}")
        
        try:
            # Send banner if defined
            if port in BANNERS:
                writer.write(BANNERS[port])
                await writer.drain()

            # Read some data (maybe an exploit or command)
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            if data:
                log_entry["payload_hex"] = data.hex()
                log_entry["payload_text"] = data.decode('utf-8', errors='ignore')

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log_entry["error"] = str(e)
        finally:
            self.write_log(log_entry)
            writer.close()
            await writer.wait_closed()

    def write_log(self, entry):
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

async def main():
    hp = HoneypotServer()
    servers = []
    
    print(f"[HONEYPOT] Starting simple Dionaea-style sink on ports: {PORTS}")
    
    for port in PORTS:
        try:
            server = await asyncio.start_server(hp.handle_connection, '0.0.0.0', port)
            servers.append(server)
            print(f"  - Listening on port {port}")
        except Exception as e:
            print(f"  - Failed to bind to port {port}: {e}")

    if not servers:
        print("[HONEYPOT] Critical: No ports could be bound. Exiting.")
        return

    # Keep alive
    async with asyncio.gather(*[s.serve_forever() for s in servers]):
        pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
