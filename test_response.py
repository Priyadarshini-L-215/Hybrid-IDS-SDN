import websockets
from websockets.http11 import Response
from websockets.datastructures import Headers
try:
    r = Response(200, "OK", Headers([("Content-Type", "text/plain")]), b"OK\n")
    print("Success")
except Exception as e:
    print(f"Error: {e}")
