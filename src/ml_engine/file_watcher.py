"""
Async File Watcher
Monitors EVE JSON file for changes and batches lines for processing.
Replaces polling interval with instant file-change detection.
"""

import asyncio
import os
from pathlib import Path
import logging
import time

logger = logging.getLogger(__name__)


class AsyncFileWatcher:
    """
    Watch a file for changes and send batches to callback.
    Handles file rotation via inode tracking.
    """

    def __init__(self, filepath, batch_size=50, flush_timeout=0.2):
        """
        Initialize watcher.
        
        Args:
            filepath: Path to file to watch (e.g., EVE JSON log)
            batch_size: Number of lines per batch before triggering callback
            flush_timeout: Time in seconds before forcibly sending a partial batch
        """
        self.filepath = Path(filepath)
        self.batch_size = batch_size
        self.flush_timeout = flush_timeout
        self.last_position = 0
        self.last_inode = None
        self.buffer = []
        self.batch_count = 0
        self.line_count = 0
        self.last_data_time = time.time()

    async def watch(self, callback):
        """
        Watch file and call callback with batches.
        
        Args:
            callback: async function(batch: list[str]) - receives batches of lines
            
        Runs indefinitely. Call await asyncio.sleep(0) to allow cancellation.
        """
        logger.info(f"[FileWatcher] Monitoring {self.filepath} (batch size: {self.batch_size})")
        
        while True:
            try:
                # Check if file exists
                if not self.filepath.exists():
                    logger.warning(f"[FileWatcher] File not found: {self.filepath}")
                    await asyncio.sleep(1)
                    continue

                # Check for file rotation via inode
                stat = os.stat(self.filepath)
                current_inode = stat.st_ino
                
                if self.last_inode and current_inode != self.last_inode:
                    logger.info(f"[FileWatcher] File rotated (old inode: {self.last_inode}, new: {current_inode})")
                    self.last_position = 0
                    self.buffer.clear()  # Clear partial batch on rotation
                
                self.last_inode = current_inode
                
                # Read new lines from file
                try:
                    with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_position)
                        lines = f.readlines()
                        self.last_position = f.tell()
                    
                    if lines:
                        self.line_count += len(lines)
                        self.buffer.extend(lines)
                        self.last_data_time = time.time()
                        
                        # Send batches
                        while len(self.buffer) >= self.batch_size:
                            batch = self.buffer[:self.batch_size]
                            self.buffer = self.buffer[self.batch_size:]
                            
                            self.batch_count += 1
                            
                            # Invoke callback
                            try:
                                await callback(batch)
                            except Exception as e:
                                logger.error(f"[FileWatcher] Callback error: {e}")
                    
                    if self.buffer and (time.time() - self.last_data_time) > self.flush_timeout:
                        batch = self.buffer
                        self.buffer = []
                        self.batch_count += 1
                        try:
                            await callback(batch)
                        except Exception as e:
                            logger.error(f"[FileWatcher] Timeout flush callback error: {e}")
                        self.last_data_time = time.time()
                
                except IOError as e:
                    logger.error(f"[FileWatcher] Read error: {e}")
                
                # Sleep briefly to yield control
                # Small sleep (10ms) to check for new data frequently but not busy-spin
                await asyncio.sleep(0.01)
                
            except Exception as e:
                logger.error(f"[FileWatcher] Unexpected error: {e}")
                await asyncio.sleep(1)

    async def flush(self, callback):
        """
        Manually flush any remaining buffered lines.
        Useful for graceful shutdown.
        
        Args:
            callback: async function(batch: list[str])
        """
        if self.buffer:
            try:
                await callback(self.buffer)
                logger.info(f"[FileWatcher] Flushed {len(self.buffer)} remaining lines")
                self.buffer.clear()
            except Exception as e:
                logger.error(f"[FileWatcher] Flush error: {e}")

    def get_stats(self):
        """Return watcher statistics."""
        return {
            "batches_sent": self.batch_count,
            "lines_read": self.line_count,
            "buffered_lines": len(self.buffer),
            "last_position": self.last_position,
            "current_inode": self.last_inode
        }
