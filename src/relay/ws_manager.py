"""
WebSocket Connection Manager

Manages active WebSocket connections and broadcasts alerts to all connected clients.
Handles stale connection cleanup after failed sends.
"""
import asyncio
import structlog
from fastapi import WebSocket

logger = structlog.get_logger("ws_manager")


class ConnectionManager:
    def __init__(self):
        self.active_connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("WebSocket client connected", total=len(self.active_connections))

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected", total=len(self.active_connections))

    async def broadcast(self, message: str):
        """
        Broadcast a message to all connected clients.
        Stale connections (those that fail to receive) are collected and removed
        after the broadcast round completes to avoid mutating the set mid-iteration.
        """
        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)

        stale: set[WebSocket] = set()

        # Send to all connections concurrently; track failures without throwing
        async def _send_safe(ws: WebSocket):
            try:
                await ws.send_text(message)
            except Exception:
                stale.add(ws)

        tasks = [asyncio.create_task(_send_safe(c)) for c in connections]

        # Wait up to 2 seconds for all sends; cancel stragglers
        done, pending = await asyncio.wait(tasks, timeout=2.0)
        for t in pending:
            t.cancel()

        # Remove stale connections discovered during this broadcast
        if stale:
            async with self._lock:
                self.active_connections -= stale
            logger.warning(
                "Removed stale WebSocket connections",
                removed=len(stale),
                remaining=len(self.active_connections),
            )
