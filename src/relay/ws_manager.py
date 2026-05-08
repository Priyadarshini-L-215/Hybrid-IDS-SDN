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
        """Sends a message to all connected clients concurrently with timeout protection."""
        # 1. Take a snapshot of connections and release lock immediately
        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)
        
        # 2. Execute concurrently with timeout protection
        if connections:
            tasks = [asyncio.create_task(self._send_safe(c, message)) for c in connections]
            # Wait for all with a timeout to prevent slow clients from blocking the pipeline
            _, pending = await asyncio.wait(tasks, timeout=2.0)
            
            if pending:
                logger.warning("Broadcast timeout for some clients", count=len(pending))
                for t in pending: t.cancel()

    async def _send_safe(self, websocket: WebSocket, message: str):
        """Helper to send message and handle stale connections."""
        try:
            await websocket.send_text(message)
        except Exception:
            # Connection likely closed; will be handled by disconnect() in the route handler
            pass
