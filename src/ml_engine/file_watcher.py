"""Compatibility async file watcher for the Redis pipeline tests.

The current ingestion path is Unix-socket based, but older validation scripts
still expect an AsyncFileWatcher surface. This module provides a lightweight
stand-in that records basic stats and can be extended later if file-tail
watching is reintroduced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AsyncFileWatcher:
    """Minimal async watcher compatibility shim."""

    path: str
    batch_size: int = 10
    poll_interval: float = 0.01
    inode_tracking: bool = True
    _running: bool = field(default=False, init=False, repr=False)
    _events_seen: int = field(default=0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = str(Path(self.path))

    def get_stats(self) -> dict:
        return {
            "path": self.path,
            "batch_size": self.batch_size,
            "poll_interval": self.poll_interval,
            "inode_tracking": self.inode_tracking,
            "running": self._running,
            "events_seen": self._events_seen,
        }

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def watch(self):
        """Compatibility async generator placeholder."""
        self._running = True
        if False:
            yield None
