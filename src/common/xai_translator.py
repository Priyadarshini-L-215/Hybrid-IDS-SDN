"""
Explainable AI (XAI) Translator Utility

This module translates raw machine learning feature importances (e.g. from SHAP)
into human-readable, natural language explanations for security analysts.
"""

from typing import List, Dict, Any

# Map of raw feature names to human-readable descriptions
FEATURE_DESCRIPTIONS = {
    # Packet counts
    "spkts": "source-to-destination packet count",
    "dpkts": "destination-to-source packet count",
    "total_fwd_packets": "forward packet count",
    "total_bwd_packets": "backward packet count",
    
    # Byte counts
    "sbytes": "source-to-destination byte volume",
    "dbytes": "destination-to-source byte volume",
    "total_fwd_bytes": "forward byte volume",
    "total_bwd_bytes": "backward byte volume",
    "smeansz": "average packet size from source",
    "dmeansz": "average packet size from destination",
    "res_bdy_len": "HTTP response body length",
    
    # Timing / Rates
    "flow_duration": "overall flow duration",
    "sload": "source transmission rate (bits/sec)",
    "dload": "destination transmission rate (bits/sec)",
    "sloss": "source packet loss rate",
    "dloss": "destination packet loss rate",
    "sinpkt": "source inter-packet arrival time",
    "dinpkt": "destination inter-packet arrival time",
    "sjit": "source jitter (timing variance)",
    "djit": "destination jitter (timing variance)",
    "tcprtt": "TCP round-trip time",
    "synack": "TCP SYN-ACK latency",
    "ackdat": "TCP ACK data latency",
    
    # TCP Flags / State
    "sttl": "source time-to-live (TTL)",
    "dttl": "destination time-to-live (TTL)",
    "swin": "source TCP window size",
    "dwin": "destination TCP window size",
    "stcpb": "source TCP base sequence number",
    "dtcpb": "destination TCP base sequence number",
    "ct_state_ttl": "connection state TTL behavior",
    
    # Contextual / Connection Counts (CT)
    "ct_srv_src": "number of connections to the same service from this source",
    "ct_srv_dst": "number of connections to the same service to this destination",
    "ct_dst_ltm": "number of connections to this destination in the last 100 flows",
    "ct_src_ltm": "number of connections from this source in the last 100 flows",
    "ct_src_dport_ltm": "number of connections from this source to this port in the last 100 flows",
    "ct_dst_sport_ltm": "number of connections to this destination from this port in the last 100 flows",
    "ct_dst_src_ltm": "number of connections between this source and destination in the last 100 flows",
    "ct_ftp_cmd": "FTP command count",
    "ct_flw_http_mthd": "HTTP method count",
    
    # Protocol / Application
    "app_proto": "application layer protocol pattern",
    "is_sm_ips_ports": "source/destination port matching",
    "is_ftp_login": "FTP login behavior",
    "trans_depth": "HTTP request depth"
}

def translate_shap_to_text(shap_top3: List[Dict[str, Any]], prediction: str) -> str:
    """
    Translates a list of SHAP feature impact dictionaries into a readable sentence.
    
    Args:
        shap_top3: List of dicts e.g., [{"feature": "sbytes", "impact": 1.5}, ...]
        prediction: The final classification (e.g., 'attack', 'anomaly', 'normal')
        
    Returns:
        A human-readable explanation string.
    """
    if not shap_top3:
        return "No behavioral explanation available."
        
    # Filter out features with near-zero impact (handle both dict and string format for tests)
    significant_features = []
    for f in shap_top3:
        if isinstance(f, dict):
            if f.get("impact", 0) > 0.01:
                significant_features.append(f)
        elif isinstance(f, str):
            significant_features.append({"feature": f, "impact": 1.0})
    
    if not significant_features:
        return "The machine learning model did not identify any strongly anomalous features."
        
    # Get the top 1 or 2 features for the summary
    top_feature = significant_features[0]
    feature_name = top_feature.get("feature", "unknown")
    readable_name = FEATURE_DESCRIPTIONS.get(feature_name, feature_name.replace("_", " "))
    
    if prediction.lower() in ["attack", "suspicious", "anomaly", "zero-day anomaly"]:
        explanation = f"Flagged primarily due to unusual patterns in {readable_name}."
        
        if len(significant_features) > 1:
            second_feature = significant_features[1]
            feature_name2 = second_feature.get("feature", "unknown")
            readable_name2 = FEATURE_DESCRIPTIONS.get(feature_name2, feature_name2.replace("_", " "))
            explanation += f" Abnormal {readable_name2} also contributed to this decision."
            
        return explanation
    else:
        return f"Traffic appears normal. The model relied heavily on {readable_name} to confirm benign behavior."
