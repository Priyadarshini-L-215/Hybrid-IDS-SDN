import os
import time
import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("SentinelML")

class AsyncFileWatcher:
    """
    High-performance file tailer designed for sub-10ms pipeline latency.
    
    Optimizations:
    1. Replaces legacy fixed-size batching with immediate dynamic forwarding.
    2. Uses a 5ms polling interval (adjustable via sleep).
    3. Implements diagnostic tracer timestamping (T1) directly at the I/O layer.
    4. Robust against log rotation and truncation.
    """
    def __init__(self, filepath, batch_size=None, flush_timeout=None):
        """
        Args:
            filepath: Path to the log file to watch.
            batch_size: (Deprecated) Maintained for API compatibility.
            flush_timeout: (Deprecated) Maintained for API compatibility.
        """
        self.filepath = Path(filepath)
        self.last_position = 0
        self.last_inode = None
        
        # Performance metrics
        self.line_count = 0
        self.batch_count = 0
        self.last_data_time = time.time()

    async def watch(self, callback):
        """
        Main loop: poll for changes and execute callback.
        """
        logger.info(f"[FileWatcher] Monitoring {self.filepath}")
        
        # Initialize inode for rotation detection
        if self.filepath.exists():
            self.last_inode = os.stat(self.filepath).st_ino
            # Optional: self.last_position = os.path.getsize(self.filepath)
            # For testing, we start at 0 to ensure we don't miss tracers injected at startup

        while True:
            try:
                # 1. Handle File Rotation/Truncation
                if self.filepath.exists():
                    current_stat = os.stat(self.filepath)
                    current_inode = current_stat.st_ino
                    current_size = current_stat.st_size
                    
                    # Truncation check
                    if current_size < self.last_position:
                        logger.info(f"[FileWatcher] File truncation detected, resetting position")
                        self.last_position = 0
                        
                    # Rotation check
                    if self.last_inode is not None and current_inode != self.last_inode:
                        logger.info(f"[FileWatcher] File rotation detected, resetting position")
                        self.last_position = 0
                        self.last_inode = current_inode
                else:
                    # File disappeared - wait and retry
                    await asyncio.sleep(1)
                    continue

                # 2. Read new content
                content = ""
                try:
                    with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_position)
                        content = f.read()
                        self.last_position = f.tell()
                except IOError as e:
                    logger.error(f"[FileWatcher] Read error: {e}")
                    await asyncio.sleep(1)
                    continue

                # 3. Process lines and execute callback
                if content:
                    lines = content.splitlines()
                    read_ts = time.time()  # T1: moment lines were read from file
                    self.line_count += len(lines)
                    
                    stamped_lines = []
                    for line in lines:
                        if "SENTINEL_LATENCY_PROBE" in line:
                            try:
                                import json
                                event = json.loads(line.strip())
                                event["_watcher_read_ts"] = read_ts
                                line = json.dumps(event)
                                # Keep log for diagnostic visibility
                                logger.info(f"[TRACER] T1 FileWatcher read at {read_ts:.6f}")
                            except Exception:
                                pass
                        
                        stamped_lines.append(line)
                    
                    if stamped_lines:
                        # Forward immediately to Redis callback
                        await callback(stamped_lines)
                        self.batch_count += 1
                        self.last_data_time = time.time()

                # 4. Low-latency sleep (5ms)
                await asyncio.sleep(0.005)

            except Exception as e:
                logger.error(f"[FileWatcher] Unexpected error: {e}")
                await asyncio.sleep(1)

    async def flush(self, callback):
        """No-op in dynamic mode, kept for API compatibility."""
        pass
