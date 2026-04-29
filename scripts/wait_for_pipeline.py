import socket
import time
import sys
import argparse
import http.client

def check_tcp(host, port):
    """Pure TCP check — correct for WebSocket servers."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False

def check_http(host, port, path="/health"):
    """HTTP check — for Flask relay only."""
    conn = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=1)
        conn.request("GET", path)
        res = conn.getresponse()
        return 200 <= res.status < 500  # any non-5xx = service is up
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False
    finally:
        if conn:
            try: conn.close()
            except: pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--mode", choices=["tcp", "http"], default="http",
                        help="tcp = raw socket (use for WebSocket); http = GET /health")
    args = parser.parse_args()

    probe = check_tcp if args.mode == "tcp" else check_http
    print(f"[*] Waiting for {args.host}:{args.port} via {args.mode.upper()} (timeout {args.timeout}s)...")
    
    start_time = time.time()
    while time.time() - start_time < args.timeout:
        if probe(args.host, args.port):
            print(f"[OK] {args.host}:{args.port} is ready!")
            time.sleep(0.5) # Grace period for server-side handshake tasks
            sys.exit(0)
        time.sleep(0.5)
    
    print(f"[ERROR] Readiness check for {args.host}:{args.port} timed out.")
    sys.exit(1)

if __name__ == "__main__":
    main()
