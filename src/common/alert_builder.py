"""
Shared alert payload builder.

Consolidates the duplicated alert-construction logic from consumer.py
(legacy pipeline) and worker_pool.py (Redis pipeline) into a single
reusable function.
"""


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
    final_classification = prediction.get("classification", "normal")
    final_confidence = float(prediction.get("confidence") or 0.0)

    # Override ML verdict when Suricata itself flagged the event
    if event.get("event_type") == "alert":
        final_classification = "attack"
        final_confidence = max(final_confidence, 90.0)

    # Dynamic Signature Enrichment
    sig = alert_info.get("signature")
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
            proto = event.get("proto") or "TCP"
            port = event.get("dest_port", "")
            is_malicious = final_classification in {"attack", "zero-day anomaly"}
            sig = f"{proto} Potential Probe (Port {port})" if is_malicious else f"{proto} Flow"

    if event_id is None:
        event_id = f"{event.get('timestamp')}-{event.get('flow_id', '0')}-{event.get('event_type')}"

    return {
        "event_id": event_id,
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "protocol": event.get("proto") or "unknown",
        "alert_sig": sig,
        "prediction": final_classification,
        "confidence": final_confidence,
        "severity": alert_info.get("severity", 4),
        "category": alert_info.get("category", "ML Detection"),
        "raw_event": event,
    }
