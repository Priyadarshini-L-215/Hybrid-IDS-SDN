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

    async def broadcast_batch(self, messages: list[str]):
        """
        Broadcast a batch of messages to all connected clients.
        """
        if not messages:
            return

        async with self._lock:
            if not self.active_connections:
                return
            connections = list(self.active_connections)

        stale: set[WebSocket] = set()

        async def _send_batch_safe(ws: WebSocket):
            try:
                for msg in messages:
                    await ws.send_text(msg)
            except Exception:
                stale.add(ws)

        tasks = [asyncio.create_task(_send_batch_safe(c)) for c in connections]
        done, pending = await asyncio.wait(tasks, timeout=3.0)
        for t in pending:
            t.cancel()

        if stale:
            async with self._lock:
                self.active_connections -= stale
            logger.warning("Removed stale WebSocket connections", removed=len(stale))

    async def broadcast(self, message: str):
        await self.broadcast_batch([message])
