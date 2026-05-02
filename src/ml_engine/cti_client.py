import httpx
import asyncio
import structlog
import time
from typing import Dict, Any, Optional
from common.config import ALIENTVAULT_KEY

logger = structlog.get_logger("cti_client")

CACHE_TTL = 3600  # 1 hour
MAX_CACHE_SIZE = 1000

class CTIClient:
    """Asynchronous client for External Cyber Threat Intelligence."""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    def __init__(self, api_key: str = ALIENTVAULT_KEY):
        self.api_key = api_key
        self.cache: Dict[str, tuple] = {}  # {ip: (data, timestamp)}
        self.client = httpx.AsyncClient(timeout=5.0)

    async def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Fetches reputation data for an IP from AlienVault OTX."""
        if not self.api_key or self.api_key == "PASTE_YOUR_OTX_KEY_HERE":
            return {"status": "unconfigured"}

        # 1. Check Cache with TTL
        if ip in self.cache:
            data, timestamp = self.cache[ip]
            if time.time() - timestamp < CACHE_TTL:
                return data
            else:
                del self.cache[ip]

        try:
            url = f"{self.BASE_URL}/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.api_key}
            
            response = await self.client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant fields
                reputation = {
                    "status": "success",
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "tags": data.get("tags", []),
                    "reputation_score": self._calculate_score(data),
                    "is_malicious": data.get("pulse_info", {}).get("count", 0) > 0,
                    "last_updated": time.time()
                }
                
                # 3. Update Cache (with size limit)
                if len(self.cache) >= MAX_CACHE_SIZE:
                    # Remove oldest entry
                    oldest_ip = min(self.cache, key=lambda k: self.cache[k][1])
                    del self.cache[oldest_ip]

                self.cache[ip] = (reputation, time.time())
                return reputation
            
            elif response.status_code == 403:
                logger.error("AlienVault API Key invalid or expired", ip=ip)
                return {"status": "error", "message": "Invalid API Key"}
            
            return {"status": "error", "message": f"HTTP {response.status_code}"}

        except Exception as e:
            logger.error("CTI lookup failed", ip=ip, error=str(e))
            return {"status": "error", "message": str(e)}

    def _calculate_score(self, data: Dict[str, Any]) -> float:
        """Calculates a normalized reputation score [0, 1] from OTX data."""
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        # Logarithmic scaling for pulse counts
        import math
        if pulse_count == 0: return 0.0
        score = math.log10(pulse_count + 1) / 2.0  # Normalized (capped at 1.0 for ~100 pulses)
        return min(score, 1.0)

    async def close(self):
        if self.client is not None:
            await self.client.aclose()
            self.client = None


async def close_cti_client():
    """Close the process-wide CTI client if it exists."""
    global _instance
    if _instance is None:
        return

    try:
        await _instance.close()
    finally:
        _instance = None

# Global singleton instance
_instance = None

def get_cti_client():
    global _instance
    if _instance is None:
        _instance = CTIClient()
    return _instance
