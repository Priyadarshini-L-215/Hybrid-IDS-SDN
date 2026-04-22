import asyncio
import sys
import websockets

async def check_ws_ready(uri, timeout=3):
    """
    Attempts a proper WebSocket handshake to verify the server is fully ready.
    """
    try:
        # Increase the open_timeout to give the WSL bridge some breathing room
        async with websockets.connect(uri, open_timeout=timeout) as ws:
            # We connected and completed the handshake successfully
            return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python check_ws_ready.py <ws_uri>")
        sys.exit(1)
        
    uri = sys.argv[1]
    
    # Run the check
    success = asyncio.run(check_ws_ready(uri))
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)
