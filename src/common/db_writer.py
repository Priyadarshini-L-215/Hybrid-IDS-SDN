import asyncio
import structlog
import time
from typing import List, Dict, Any
from common.database import db

logger = structlog.get_logger(__name__)

class AsyncAlertWriter:
    """
    Asynchronous write buffer for database alerts.
    Prevents lock contention by batching multiple events into a single transaction.
    """
    def __init__(self, batch_size: int = 50, flush_interval: float = 1.0):
        self.queue = asyncio.Queue()
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._worker_task = None
        self._running = False

    async def start(self):
        """Starts the background flush worker."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._flush_worker())
        logger.info("AsyncAlertWriter started", batch_size=self.batch_size, interval=self.flush_interval)

    async def stop(self):
        """Gracefully stops the worker and flushes remaining alerts."""
        self._running = False
        if self._worker_task:
            # Wait for the worker to finish processing the current queue
            await self.queue.join()
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("AsyncAlertWriter stopped")

    async def add_alert(self, alert_data: Dict[str, Any]):
        """Queues an alert for asynchronous writing."""
        await self.queue.put(alert_data)

    async def add_alerts(self, alerts_data: List[Dict[str, Any]]):
        """Queues multiple alerts for asynchronous writing."""
        for alert in alerts_data:
            await self.queue.put(alert)

    async def _flush_worker(self):
        """Background loop to batch-write alerts."""
        while self._running:
            batch = []
            try:
                # 1. Wait for the first item
                item = await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval)
                batch.append(item)
                
                # 2. Try to fill the batch quickly
                while len(batch) < self.batch_size:
                    try:
                        item = self.queue.get_nowait()
                        batch.append(item)
                    except asyncio.QueueEmpty:
                        break
                
                # 3. Perform batch write
                if batch:
                    try:
                        start_t = time.time()
                        # Use the native async batch_add_alerts
                        await db.batch_add_alerts(batch)

                        lat = (time.time() - start_t) * 1000
                        logger.debug("Async batch write complete", count=len(batch), latency_ms=round(lat, 2))
                    except Exception as e:
                        logger.error("AsyncAlertWriter db write error", error=str(e))
                    finally:
                        # Ensure we mark the items as processed even if the DB write fails
                        for _ in range(len(batch)):
                            self.queue.task_done()
                    
            except asyncio.TimeoutError:
                # No alerts arrived within the flush interval
                continue
            except Exception as e:
                logger.error("AsyncAlertWriter worker error", error=str(e))
                # Prevent tight error loops
                await asyncio.sleep(1)

# Global singleton instance
alert_writer = AsyncAlertWriter()
