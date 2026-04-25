import socket
import sys

def test_connection(host, port):
    print(f"Testing connection to {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((host, port))
        if result == 0:
            print(f"Success: Port {port} on {host} is reachable via TCP.")
        else:
            print(f"Failure: Port {port} on {host} is unreachable. Error code: {result}")
        s.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    wsl_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    test_connection("127.0.0.1", 8765)
    test_connection(wsl_ip, 8765)
