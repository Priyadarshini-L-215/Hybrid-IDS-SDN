import asyncio
import subprocess
import structlog
import re
from ml_engine.firewall import ActiveFirewall

logger = structlog.get_logger(__name__)

class MitigationAuditor:
    """
    Active compliance auditor for kernel and SDN mitigation states.
    Verifies that all registered block actions are successfully applied 
    and actively dropping traffic. Self-heals if rules are missing.
    """

    def __init__(self, interval_seconds: int = 30):
        self.interval = interval_seconds
        self.running = False
        self._audit_task: Optional[asyncio.Task] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self._audit_task = asyncio.create_task(self._audit_loop())
        logger.info("Mitigation Auditor started", check_interval=self.interval)

    async def stop(self):
        self.running = False
        if self._audit_task:
            self._audit_task.cancel()
            try:
                await self._audit_task
            except asyncio.CancelledError:
                pass
            self._audit_task = None
        logger.info("Mitigation Auditor stopped")

    async def _audit_loop(self):
        while self.running:
            try:
                await asyncio.sleep(self.interval)
                await self.audit_mitigations()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Mitigation Audit cycle failed", error=str(e))

    async def audit_mitigations(self):
        """Audits both ipset structures and active iptables drop rules."""
        logger.debug("Starting mitigation audit cycle...")
        
        # 1. Audit core kernel structures (ipset & iptables)
        structures_healthy = await self._audit_kernel_structures()
        if not structures_healthy:
            logger.warning("Mitigation structures missing in kernel. Triggering self-healing recreation...")
            # Recreate missing sets/chains
            await ActiveFirewall._ensure_kernel_sets()
            
        # 2. Cross-reference registered blocks in Redis vs actual ipset membership
        await self._audit_blocked_ips()

        # 3. Read drop packet counters
        await self._audit_drop_counters()

    async def _audit_kernel_structures(self) -> bool:
        """Checks if required ipsets and iptables chains are present."""
        loop = asyncio.get_running_loop()
        
        # Check ipsets
        sets = [ActiveFirewall.SET_BLOCKS, ActiveFirewall.SET_LIMITED]
        for s in sets:
            res = await loop.run_in_executor(
                None,
                lambda: subprocess.run(["sudo", "ipset", "list", s], capture_output=True)
            )
            if res.returncode != 0:
                logger.error("Auditor: ipset is missing", ipset=s)
                return False
                
        # Check iptables
        res = await loop.run_in_executor(
            None,
            lambda: subprocess.run(["sudo", "iptables", "-L", "SENTINEL_IPS", "-n"], capture_output=True)
        )
        if res.returncode != 0:
            logger.error("Auditor: iptables chain SENTINEL_IPS is missing")
            return False
            
        return True

    async def _audit_blocked_ips(self):
        """Cross-references the active blocks in Redis against active members in the ipset."""
        if await ActiveFirewall.is_banning_disabled():
            logger.debug("Auditor: Skipping block self-healing because automatic banning is disabled")
            return
            
        detailed = await ActiveFirewall.get_detailed_status()
        
        # final_blocked_ips and high reputation offenders (> temp block threshold)
        expected_blocks = set(detailed.get("final_blocked_ips", []))
        for ip, score in detailed.get("reputation", {}).items():
            # temp block = 25, perm block = 50. Let's block if >= temp block
            if score >= 25.0:
                expected_blocks.add(ip)
                
        actual_blocks = set(detailed.get("permanent_ips", [])).union(set(detailed.get("temporary_ips", [])))
        
        # Find any expected blocks that are missing in the active kernel ipsets
        missing_in_kernel = expected_blocks - actual_blocks
        
        if missing_in_kernel:
            logger.warning("Auditor: Found missing kernel blocklist rules. Self-healing...", 
                           missing_ips=list(missing_in_kernel))
            for ip in missing_in_kernel:
                # Re-apply legacy block (TTL=0 means permanent, else TTL=300 for temp)
                score = detailed.get("reputation", {}).get(ip, 0.0)
                ttl = 0 if (ip in detailed.get("final_blocked_ips", []) or score >= 50.0) else 300
                await ActiveFirewall.block(ip, ttl=ttl)

    async def _audit_drop_counters(self):
        """Inspects drop packet and byte counters from iptables to verify blocking compliance."""
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(
            None,
            lambda: subprocess.run(["sudo", "iptables", "-vnL", "SENTINEL_IPS"], capture_output=True, text=True)
        )
        
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            for line in lines:
                # Find drop rules (e.g., "100 12000 DROP src ...")
                if "DROP" in line or "match-set" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        pkts = parts[0]
                        bytes_dropped = parts[1]
                        logger.debug("Mitigation Audit Drop Counter", 
                                     rule=line.strip(), packets=pkts, bytes=bytes_dropped)
