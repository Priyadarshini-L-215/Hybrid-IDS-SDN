"""
Shared alert payload builder.

Consolidates the duplicated alert-construction logic from consumer.py
(legacy pipeline) and worker_pool.py (Redis pipeline) into a single
reusable function.
"""
import hashlib
import json
import uuid
import math
from common.mitre_mapper import get_mitre_info
from common.xai_translator import translate_shap_to_text

def safe_float(v):
    try:
        val = float(v or 0.0)
        return 0.0 if math.isnan(val) or math.isinf(val) else val
    except (ValueError, TypeError):
        return 0.0



SIGNATURE_MAP = {
    # ICMP
    "SURICATA ICMPv4 unknown code": "Invalid ICMPv4 Code (Decoder Anomaly)",
    "SURICATA ICMPv4 unknown type": "Invalid ICMPv4 Type (Decoder Anomaly)",
    "SURICATA ICMPv4 truncated packet": "Truncated ICMPv4 Packet",
    "SURICATA ICMPv6 unknown type": "Invalid ICMPv6 Type",
    
    # TCP/IP
    "SURICATA IPv4 length too small": "Malformed IPv4 Header (Too Short)",
    "SURICATA TCP invalid header length": "Invalid TCP Header Length",
    "SURICATA TCP packet too short": "Truncated TCP Packet",
    "SURICATA UDP packet too short": "Truncated UDP Packet",
    
    # TLS/SSL
    "SURICATA TLS invalid record type": "TLS Protocol Violation (Invalid Record)",
    "SURICATA TLS invalid version": "Legacy/Invalid TLS Version Detected",
    
    # HTTP
    "SURICATA HTTP request line too long": "HTTP Flood/Buffer Exhaustion Attempt",
    "SURICATA HTTP invalid header name": "Malformed HTTP Header",
}

def normalize_signature(sig: str) -> str:
    """Cleans up cryptic Suricata signatures into readable text."""
    if not sig: return sig
    if sig in SIGNATURE_MAP:
        return SIGNATURE_MAP[sig]
    # Fallback: Strip SURICATA prefix and title-case
    if sig.startswith("SURICATA "):
        cleaned = sig.replace("SURICATA ", "").replace("_", " ").strip()
        return cleaned.title()
    return sig

def build_alert_payload(event: dict, prediction: dict, *, event_id: str = None) -> dict:
    """
    Build a normalised alert dict from a raw Suricata event and an ML prediction.

    Args:
        event: Raw Suricata EVE JSON event.
        prediction: Dict with keys: classification, confidence, layer, etc.
        event_id: Optional pre-computed unique event ID.

    Returns:
        Alert dict ready for DB insertion and WebSocket broadcast.
    """
    alert_info = event.get("alert", {})
    final_classification = prediction.get("prediction", prediction.get("classification", "normal"))
    final_confidence = safe_float(prediction.get("confidence") or 0.0)

    # Normalize confidence if it's already in [0, 100]
    if final_confidence > 1.0:
        final_confidence = final_confidence / 100.0

    # Note: Signature integration is now handled by DecisionEngine to allow for nuanced confidence.
    sig_present = event.get("event_type") == "alert"

    # Dynamic Signature Enrichment
    sig = alert_info.get("signature") or event.get("alert_signature")
    if not sig:
        etype = event.get("event_type", "flow")
        if etype == "dns":
            dns = event.get("dns", {})
            sig = f"DNS Query: {dns.get('rrname', 'unknown')}"
        elif etype == "http":
            http = event.get("http", {})
            sig = f"HTTP {http.get('http_method')} -> {http.get('hostname', 'unknown')}"
        elif etype == "ssh":
            sig = "SSH Connection Attempt"
        else:
            proto = event.get("protocol") or event.get("proto") or "TCP"
            port = event.get("dst_port") or event.get("dest_port") or ""
            is_malicious = final_classification in {"attack", "suspicious", "zero-day anomaly"}
            sig = f"{proto} Potential Probe (Port {port})" if is_malicious else f"{proto} Flow"

    if event_id is None:
        event_id = str(uuid.uuid4())

    normalized_sig = normalize_signature(sig)

    return {
        "event_id": event_id,
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip") or event.get("dest_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port") or event.get("dest_port"),
        "protocol": event.get("protocol") or event.get("proto") or "unknown",
        "alert_sig": normalized_sig,
        "prediction": final_classification,
        "confidence": round(final_confidence * 100, 2),
        "severity": alert_info.get("severity", 4),
        "category": alert_info.get("category", "ML Detection"),
        "mitigation": None,
        "is_mitigated": False,
        "sig_present": sig_present,
        "processing_time_ms": 0.0,
        "duplicate_count": prediction.get("duplicate_count", 1),
        "alert_source": event.get("alert_source"),
        "is_simulation": event.get("is_simulation"),
        "mitre": get_mitre_info(final_classification, normalized_sig),
        "shap_top3": prediction.get("shap_top3", []),
        "xai_explanation": translate_shap_to_text(prediction.get("shap_top3", []), final_classification),
        "anomaly_score": safe_float(prediction.get("anomaly_score")),
        "ja3_hash": event.get("tls", {}).get("ja3", {}).get("hash"),
        "ja3_string": event.get("tls", {}).get("ja3", {}).get("string"),
        "enrichment": {}, # Populated by worker pool
        "forensics": {
            "packet_hash": hashlib.sha256(str(event.get("raw", event)).encode()).hexdigest()[:16],
            "stage_scores": {
                "signature": 1.0 if sig_present else 0.0,
                "ml": safe_float(prediction.get("ml_score")),
                "anomaly": safe_float(prediction.get("anomaly_score"))
            },
            "correlation_id": hashlib.md5(f"{event.get('src_ip')}-{event.get('dst_ip')}".encode()).hexdigest()[:8]
        },
        "raw_event": event,
    }

