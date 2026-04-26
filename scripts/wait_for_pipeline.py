import socket
import time
import sys
import argparse

def check_port(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()

    print(f"[*] Waiting for pipeline at {args.host}:{args.port} (timeout {args.timeout}s)...")
    start_time = time.time()
    while time.time() - start_time < args.timeout:
        if check_port(args.host, args.port):
            print("[OK] Pipeline is ready!")
            sys.exit(0)
        time.sleep(1)
    
    print("[ERROR] Pipeline readiness check timed out.")
    sys.exit(1)

if __name__ == "__main__":
    main()
