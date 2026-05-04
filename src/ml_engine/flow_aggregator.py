import time
import asyncio
import collections
from typing import Dict, List, Optional, Any
import structlog
from common.schemas import RawEvent, FlowAggregate

logger = structlog.get_logger(__name__)

class FlowAggregator:
    """
    Sliding window flow aggregator.
    Groups raw packets/events by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
    Calculates features like duration, PPS, BPS, and state ratios.
    """
    
    def __init__(self, 
                 window_size: float = 1.0, 
                 idle_timeout: float = 1.0, 
                 max_duration: float = 1.0):
        
        self.window_size = window_size
        self.idle_timeout = idle_timeout
        self.max_duration = max_duration
        
        # State: {flow_key: flow_data}
        self.active_flows = {}
        self._lock = asyncio.Lock()
        
        logger.info("Flow Aggregator initialized", 
                    window=window_size, 
                    idle_timeout=idle_timeout)

    def _get_flow_key(self, event: RawEvent) -> str:
        # Standard 5-tuple key
        return f"{event.src_ip}:{event.src_port}->{event.dst_ip}:{event.dst_port}|{event.protocol}"

    async def add_event(self, event: RawEvent) -> Optional[FlowAggregate]:
        """Adds a raw event and returns an aggregate if the flow is ready to flush."""
        key = self._get_flow_key(event)
        now = time.time()
        
        async with self._lock:
            if key not in self.active_flows:
                self.active_flows[key] = {
                    "start_ts": now,
                    "last_ts": now,
                    "packet_count": 0,
                    "byte_count": 0,
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol
                }
            
            flow = self.active_flows[key]
            flow["last_ts"] = now
            flow["packet_count"] += (event.packet_count or 1)
            flow["byte_count"] += (event.byte_count or 64) # Dummy size if missing
            
            # Check for immediate flush if duration exceeds max
            duration = now - flow["start_ts"]
            if duration >= self.max_duration:
                return await self._flush_flow_internal(key)
                
        return None

    async def cleanup_loop(self, callback):
        """Background task to flush idle flows."""
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            to_flush = []
            
            # 1. Identify keys to flush while holding lock
            async with self._lock:
                for key, flow in list(self.active_flows.items()):
                    if (now - flow["last_ts"]) >= self.idle_timeout:
                        to_flush.append(key)
            
            # 2. Flush each identified key (re-acquiring lock for each pop)
            for key in to_flush:
                async with self._lock:
                    if key in self.active_flows: # Check if still there
                        agg = await self._flush_flow_internal(key)
                        if callback:
                            await callback(agg)

    async def _flush_flow_internal(self, key: str) -> FlowAggregate:
        """Internal pop and compute metrics. ASSUMES LOCK IS HELD."""
        data = self.active_flows.pop(key)
        now = time.time()
        duration = max(now - data["start_ts"], 0.001)
        
        pps = data["packet_count"] / duration
        bps = data["byte_count"] / duration
        
        logger.debug("Flow flushed", key=key, duration=round(duration, 2), packets=data["packet_count"])
        
        return FlowAggregate(
            flow_id=key,
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            protocol=data["protocol"],
            duration=duration,
            packet_count=data["packet_count"],
            byte_count=data["byte_count"],
            pps=pps,
            bps=bps
        )

    def get_status(self):
        return {"active_flows": len(self.active_flows)}
