import asyncio
from typing import Set, Dict
import structlog
from fastapi import WebSocket

logger = structlog.get_logger(__name__)

class ConnectionManager:
    """
    Manages active WebSocket connections.
    Handles fan-out broadcasting and graceful cleanup.
    """
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("New dashboard client connected", count=len(self.active_connections))

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info("Dashboard client disconnected", count=len(self.active_connections))

    async def broadcast(self, message: str):
        """Sends a message to all connected clients concurrently."""
        async with self._lock:
            if not self.active_connections:
                return
            
            # Create send tasks for all clients
            tasks = []
            for connection in self.active_connections:
                tasks.append(self._send_safe(connection, message))
            
            # Execute concurrently
            await asyncio.gather(*tasks)

    async def _send_safe(self, websocket: WebSocket, message: str):
        """Helper to send message and handle stale connections."""
        try:
            await websocket.send_text(message)
        except Exception:
            # Connection likely closed; will be handled by disconnect() in the route handler
            pass
