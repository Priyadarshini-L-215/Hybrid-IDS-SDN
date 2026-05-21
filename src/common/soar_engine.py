import yaml
import asyncio
import structlog
from typing import Dict, Any, List, Optional
from pathlib import Path

logger = structlog.get_logger("common.soar_engine")

class SOAREngine:
    """
    Automated Security Orchestration, Automation, and Response (SOAR) Engine.
    Executes context-aware, closed-loop playbooks based on MITRE mappings and SHAP feature analysis.
    """
    
    def __init__(self, playbooks_path: str = "config/playbooks.yaml"):
        self.playbooks_path = Path(playbooks_path)
        self.playbooks = {}
        self.load_playbooks()

    def load_playbooks(self):
        try:
            if self.playbooks_path.exists():
                with open(self.playbooks_path, "r") as f:
                    data = yaml.safe_load(f) or {}
                    self.playbooks = data.get("playbooks", {})
                logger.info("SOAR: Playbooks loaded successfully", count=len(self.playbooks))
            else:
                logger.warning("SOAR: Playbook config file not found", path=str(self.playbooks_path))
        except Exception as e:
            logger.error("SOAR: Failed to load playbooks", error=str(e))

    async def execute_playbook(self, 
                               classification: str, 
                               confidence: float, 
                               mitre_info: Optional[Dict[str, Any]], 
                               shap_features: List[Dict[str, Any]], 
                               event: Dict[str, Any]):
        """Evaluates triggers and executes playbooks asynchronously for a threat event."""
        src_ip = event.get("src_ip") or event.get("source_ip")
        if not src_ip:
            return  # Can't mitigate without a source IP

        # Skip protected internal IPs
        from common.config import get_protected_ips
        if src_ip in get_protected_ips():
            logger.debug("SOAR: Skipping mitigation for protected IP", ip=src_ip)
            return

        mitre_info = mitre_info or {}
        mitre_tactic = mitre_info.get("tactic")
        mitre_technique = mitre_info.get("technique")

        matched_playbooks = []
        for name, pb in self.playbooks.items():
            trigger = pb.get("trigger", {})
            
            # Check classification matching
            if "classification" in trigger and trigger["classification"] != classification:
                continue
                
            # Check MITRE tactic matching
            if "mitre_tactic" in trigger and trigger["mitre_tactic"] != mitre_tactic:
                continue
                
            # Check MITRE technique matching
            if "mitre_technique" in trigger and trigger["mitre_technique"] != mitre_technique:
                continue
                
            # Check confidence mapping
            if "min_confidence" in trigger and confidence < trigger["min_confidence"]:
                continue
                
            matched_playbooks.append((name, pb))

        if not matched_playbooks:
            # Fallback: Process standard reputation incident
            from ml_engine.firewall import ActiveFirewall
            delta = 10.0 if classification == "anomaly" else (25.0 if classification == "suspicious" else 50.0)
            await ActiveFirewall.process_incident(src_ip, delta=delta)
            return

        for name, pb in matched_playbooks:
            logger.info("SOAR: Triggering Playbook", playbook=name, src_ip=src_ip)
            # Log metrics for the action
            try:
                from common.metrics import PROM_MITIGATIONS_TOTAL
                PROM_MITIGATIONS_TOTAL.labels(action=f"playbook_{name}").inc()
            except Exception:
                pass
            
            asyncio.create_task(self._run_actions(pb.get("actions", []), src_ip, shap_features, event))

    async def _run_actions(self, actions: List[Dict[str, Any]], src_ip: str, shap_features: List[Dict[str, Any]], event: Dict[str, Any]):
        from ml_engine.firewall import ActiveFirewall
        
        for action in actions:
            action_type = action.get("type")
            params = action.get("params", {})
            logger.info("SOAR: Executing action", action=action.get("name"), type=action_type)

            try:
                if action_type == "micro_block":
                    # Perform protocol-level fine-grained micro-mitigation based on SHAP impacts
                    protocol = event.get("proto") or "TCP"
                    dport = event.get("dest_port") or event.get("dport")
                    ttl = params.get("ttl", 300)

                    # Extract dport from SHAP if missing in event
                    if not dport and shap_features:
                        for f in shap_features:
                            fname = f.get("feature", "")
                            if "port" in fname or "dport" in fname:
                                dport = 80  # Default heuristic if matching port feature is suspicious

                    if protocol and dport:
                        success = await ActiveFirewall.micro_block(src_ip, str(protocol), int(dport), ttl)
                        if success:
                            logger.warning("SOAR Action: Micro-Block applied", ip=src_ip, proto=protocol, port=dport)
                            continue
                    
                    # Fallback to standard blocking
                    fallback = params.get("fallback", "temp_block")
                    if fallback == "perm_block":
                        await ActiveFirewall.block(src_ip, ttl=0)
                    else:
                        await ActiveFirewall.block(src_ip, ttl=ttl)

                elif action_type == "honeypot_redirect":
                    ttl = params.get("ttl", 300)
                    success = await ActiveFirewall.redirect_to_honeypot(src_ip, ttl)
                    if success:
                        logger.warning("SOAR Action: Decoy Redirection applied", ip=src_ip, ttl=ttl)
                    else:
                        # Fallback to rate limit if redirection failed
                        await ActiveFirewall.rate_limit(src_ip)

                elif action_type == "rate_limit":
                    await ActiveFirewall.rate_limit(src_ip)

                elif action_type == "penalize_reputation":
                    penalty = float(params.get("penalty", 10.0))
                    await ActiveFirewall.process_incident(src_ip, delta=penalty)

                elif action_type == "log_forensics" or action_type == "elevated_logging":
                    logger.warning("SOAR Forensics Audit logged", src_ip=src_ip, event_type=event.get("event_type"))

            except Exception as action_err:
                logger.error("SOAR: Action execution failed", action=action.get("name"), error=str(action_err))
