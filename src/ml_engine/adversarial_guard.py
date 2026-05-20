import structlog
from typing import Tuple, List, Dict, Any, Optional

logger = structlog.get_logger("ml_engine.adversarial_guard")

class AdversarialGuard:
    """
    State-of-the-Art (SOTA) Adversarial Evasion Guard.
    
    Checks flow features and raw event structures for impossible or highly anomalous
    physical inconsistencies (e.g. payload padding or timing perturbation attacks)
    commonly used to evade machine learning classifiers.
    """
    
    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold

    def detect_evasion(self, event: dict, features: Optional[List[float]] = None, 
                       feature_names: Optional[List[str]] = None) -> Tuple[float, List[str]]:
        """
        Analyzes a network event and its extracted features for adversarial evasion signatures.
        
        Returns:
            Tuple[evasion_score, reasons]
            - evasion_score: Float [0, 1] representing the likelihood of evasion.
            - reasons: List of detected anomaly signatures.
        """
        score = 0.0
        reasons = []
        
        if not isinstance(event, dict):
            return score, reasons

        flow = event.get("flow", {}) or {}
        proto = str(event.get("proto") or "").upper()
        app_proto = str(event.get("app_proto") or "").lower()
        
        fwd_pkts = float(flow.get('pkts_toserver') or event.get('packet_count') or 0)
        bwd_pkts = float(flow.get('pkts_toclient') or 0)
        fwd_bytes = float(flow.get('bytes_toserver') or event.get('byte_count') or 0)
        bwd_bytes = float(flow.get('bytes_toclient') or 0)
        age = float(flow.get('age') or event.get('duration') or 0)
        
        total_pkts = fwd_pkts + bwd_pkts
        total_bytes = fwd_bytes + bwd_bytes

        # 1. Payload Dilution Detection (diluting mean packet size with empty padding packets)
        if total_pkts > 50:
            avg_len = total_bytes / total_pkts
            # HTTP, TLS, SSH handshakes require headers; an average length < 15 bytes across 50+ packets
            # strongly indicates hundreds of empty TCP ACK/dummy packets were injected to bypass ML models.
            if avg_len < 15.0 and app_proto in ["http", "ftp", "tls", "ssh"]:
                score += 0.45
                reasons.append("suspicious_payload_dilution")

        # 2. Impossible Packet Payload Ratio
        # e.g., average payload size per packet exceeds normal ethernet MTU boundaries (typically 1500)
        # without IP fragmentation, which indicates simulated/synthetic evasion inputs.
        if total_pkts > 0:
            avg_fwd_len = fwd_bytes / max(fwd_pkts, 1)
            avg_bwd_len = bwd_bytes / max(bwd_pkts, 1)
            if (avg_fwd_len > 3000 or avg_bwd_len > 3000) and proto == "TCP":
                score += 0.5
                reasons.append("impossible_packet_payload_ratio")

        # 3. Stealth Timing Evasion
        # Extremely slow-rate packet bursts spanning long durations mapped to interactive control protocols.
        if age > 120.0 and 0 < total_pkts < 8:
            if app_proto in ["http", "ftp", "dns"]:
                score += 0.4
                reasons.append("stealth_timing_evasion")

        # 4. Feature Vector Consistency Checks (if aligned features are provided)
        if features and feature_names:
            try:
                feat_dict = dict(zip(feature_names, features))
                spkts = float(feat_dict.get("spkts", 0))
                sbytes = float(feat_dict.get("sbytes", 0))
                sload = float(feat_dict.get("sload", 0))
                
                # If source load is massive but packet count is extremely low
                if sload > 5000000.0 and spkts < 5:
                    score += 0.45
                    reasons.append("anomalous_feature_load_ratio")
            except Exception:
                pass

        final_score = min(score, 1.0)
        if final_score >= self.threshold:
            logger.warning("Adversarial evasion signature detected!", 
                           score=final_score, reasons=reasons, app_proto=app_proto)
            
        return final_score, reasons
