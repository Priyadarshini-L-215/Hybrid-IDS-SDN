"""
Unified feature extraction module for Hybrid IDS.

Extracts all 77 CICIDS features from Suricata EVE JSON events.
This module is shared between consumer.py and integration.py to ensure
consistent feature engineering across the system.

Feature List (77 total):
- Flow duration and packet counts
- Packet length statistics (max, mean, std dev)
- Inter-arrival time (IAT) statistics
- Packet rates and ratios
- TCP flag counts
- Window sizes and segment sizes
- Header lengths
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_CACHED_FEATURES = None

def load_feature_names(features_path: str | Path = None) -> list:
    """
    Load the ordered list of 77 feature names from features.json.
    
    Args:
        features_path: Path to features.json. If None, uses default path.
    
    Returns:
        List of 77 feature names in exact order expected by model.
    """
    if features_path is None:
        # Default to models/features.json relative to project root
        features_path = Path(__file__).resolve().parents[2] / "models" / "features.json"
    
    features_path = Path(features_path)
    
    global _CACHED_FEATURES
    if _CACHED_FEATURES is not None:
        return _CACHED_FEATURES

    try:
        with open(features_path, 'r', encoding='utf-8') as f:
            features = json.load(f)
        
        if not isinstance(features, list):
            raise ValueError(f"features.json must contain a JSON array, got {type(features)}")
        
        if len(features) != 77:
            logger.warning(f"Expected 77 features, but got {len(features)}. " 
                         "Model may have been trained on different feature set.")
        
        _CACHED_FEATURES = features
        return features
    except FileNotFoundError:
        logger.error(f"features.json not found at {features_path}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in features.json: {e}")
        raise


def extract_features_from_eve(event: dict, features: list = None) -> list | None:
    """
    Extract all 77 features from a Suricata EVE JSON event.
    
    Args:
        event: Suricata EVE JSON event dictionary
        features: List of feature names (if None, will be loaded from features.json)
    
    Returns:
        List of 77 feature values in exact order, or None if event is not a 'flow' type
    """
    # Process both 'flow' and 'alert' events
    if event.get('event_type') not in ['flow', 'alert']:
        return None
    
    if features is None:
        features = load_feature_names()
    
    # Standardized schema fallback
    flow = event.get('flow', {})
    if not flow and 'raw_event' in event:
        flow = event['raw_event'].get('flow', {})
    
    # ===== BASIC FLOW METRICS =====
    fwd_pkts = float(flow.get('pkts_toserver', 0))
    bwd_pkts = float(flow.get('pkts_toclient', 0))
    fwd_bytes = float(flow.get('bytes_toserver', 0))
    bwd_bytes = float(flow.get('bytes_toclient', 0))
    flow_age_sec = float(flow.get('age', 0))
    flow_age_us = flow_age_sec * 1_000_000  # Convert to microseconds
    
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    
    # Avoid division by zero
    safe_age = max(flow_age_sec, 0.0001)
    
    # ===== PACKET LENGTH STATISTICS =====
    # Note: Suricata doesn't provide per-packet statistics in flow events
    # We estimate based on average packet size
    fwd_avg_pkt_len = fwd_bytes / max(fwd_pkts, 1)
    bwd_avg_pkt_len = bwd_bytes / max(bwd_pkts, 1)
    avg_pkt_len = total_bytes / max(total_pkts, 1)
    
    # For std dev, we use simplified calculation (assuming Gaussian distribution)
    # In production, you'd want to capture this at packet capture time
    fwd_pkt_len_std = fwd_avg_pkt_len * 0.1  # Placeholder: 10% of mean
    bwd_pkt_len_std = bwd_avg_pkt_len * 0.1
    pkt_len_variance = (fwd_pkt_len_std ** 2 + bwd_pkt_len_std ** 2)
    pkt_len_std = (pkt_len_variance) ** 0.5
    
    # ===== INTER-ARRIVAL TIME (IAT) STATISTICS =====
    # Simplified: Use flow age / number of packets as proxy for IAT
    if total_pkts > 1:
        flow_iat_mean = flow_age_us / (total_pkts - 1)
    else:
        flow_iat_mean = 0
    
    flow_iat_std = flow_iat_mean * 0.2  # Placeholder
    flow_iat_max = flow_age_us if total_pkts > 0 else 0
    flow_iat_min = flow_iat_mean if total_pkts > 1 else 0
    
    # Forward IAT
    fwd_iat_total = flow_age_us if fwd_pkts > 1 else 0
    fwd_iat_mean = fwd_iat_total / max(fwd_pkts - 1, 1) if fwd_pkts > 1 else 0
    fwd_iat_std = fwd_iat_mean * 0.15
    fwd_iat_max = flow_age_us if fwd_pkts > 0 else 0
    fwd_iat_min = fwd_iat_mean if fwd_pkts > 1 else 0
    
    # Backward IAT
    bwd_iat_total = flow_age_us if bwd_pkts > 1 else 0
    bwd_iat_mean = bwd_iat_total / max(bwd_pkts - 1, 1) if bwd_pkts > 1 else 0
    bwd_iat_std = bwd_iat_mean * 0.15
    bwd_iat_max = flow_age_us if bwd_pkts > 0 else 0
    bwd_iat_min = bwd_iat_mean if bwd_pkts > 1 else 0
    
    # ===== PACKET RATES =====
    fwd_pkts_per_sec = fwd_pkts / safe_age
    bwd_pkts_per_sec = bwd_pkts / safe_age
    flow_pkts_per_sec = total_pkts / safe_age
    flow_bytes_per_sec = total_bytes / safe_age
    
    # ===== TCP FLAG COUNTS =====
    # Suricata includes tcp flags in the event.tcp object or raw_event.tcp object
    tcp_info = event.get('tcp', {})
    if not tcp_info and 'raw_event' in event:
        tcp_info = event['raw_event'].get('tcp', {})
        
    syn_flag_count = 1.0 if tcp_info.get('syn') else 0.0
    fin_flag_count = 1.0 if tcp_info.get('fin') else 0.0
    rst_flag_count = 1.0 if tcp_info.get('rst') else 0.0
    psh_flag_count = 1.0 if tcp_info.get('psh') else 0.0
    ack_flag_count = 1.0 if tcp_info.get('ack') else 0.0
    urg_flag_count = 1.0 if tcp_info.get('urg') else 0.0
    cwe_flag_count = 1.0 if tcp_info.get('cwr') else 0.0 # Note: CICIDS uses CWE, Suricata uses CWR
    ece_flag_count = 1.0 if tcp_info.get('ece') else 0.0
    
    fwd_psh_flags = psh_flag_count  # Simple approximation, as directional flags aren't always split in standard EVE
    
    # ===== SEGMENT SIZES =====
    fwd_header_length = 20 if fwd_pkts > 0 else 0  # TCP header is 20 bytes (IPv4)
    bwd_header_length = 20 if bwd_pkts > 0 else 0
    fwd_segment_size_min = fwd_avg_pkt_len
    avg_fwd_segment_size = fwd_avg_pkt_len
    avg_bwd_segment_size = bwd_avg_pkt_len
    avg_packet_size = avg_pkt_len
    
    # ===== SUBFLOW METRICS (Same as flow for single flow) =====
    subflow_fwd_packets = fwd_pkts
    subflow_fwd_bytes = fwd_bytes
    subflow_bwd_packets = bwd_pkts
    subflow_bwd_bytes = bwd_bytes
    
    # ===== WINDOW SIZES (TCP-specific, not in Suricata flow events) =====
    init_fwd_win_bytes = 0  # Would need TCP capture
    init_bwd_win_bytes = 0
    
    # ===== ACTIVE/IDLE TIME (Simplified) =====
    # Active time: time from first to last packet
    active_mean = flow_age_us / 2 if flow_age_us > 0 else 0
    active_std = flow_age_us * 0.1
    active_max = flow_age_us
    active_min = 0
    
    # Idle time: simplified as not having inter-packet gaps
    idle_mean = 0
    idle_std = 0
    idle_max = 0
    idle_min = 0
    
    # ===== PACKET LENGTH STATISTICS (continued) =====
    fwd_act_data_packets = fwd_pkts  # All fwd packets considered data packets
    packet_length_max = max(fwd_avg_pkt_len, bwd_avg_pkt_len)
    packet_length_mean = avg_pkt_len
    
    # ===== PROTOCOL MAPPING =====
    proto_str = (event.get('protocol') or event.get('proto') or 'TCP').upper()
    proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "HOPOPT": 0, "IPV6-ICMP": 58}
    protocol_num = float(proto_map.get(proto_str, 0))

    # ===== BUILD FEATURE DICTIONARY (77 FEATURES) =====
    feature_dict = {
        "Protocol": protocol_num,
        "Flow Duration": flow_age_us,
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Fwd Packets Length Total": fwd_bytes,
        "Bwd Packets Length Total": bwd_bytes,
        "Fwd Packet Length Max": fwd_avg_pkt_len,
        "Fwd Packet Length Min": fwd_avg_pkt_len * 0.8, # Estimated
        "Fwd Packet Length Mean": fwd_avg_pkt_len,
        "Fwd Packet Length Std": fwd_pkt_len_std,
        "Bwd Packet Length Max": bwd_avg_pkt_len,
        "Bwd Packet Length Min": bwd_avg_pkt_len * 0.8, # Estimated
        "Bwd Packet Length Mean": bwd_avg_pkt_len,
        "Bwd Packet Length Std": bwd_pkt_len_std,
        "Flow Bytes/s": flow_bytes_per_sec,
        "Flow Packets/s": flow_pkts_per_sec,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": fwd_psh_flags,
        "Bwd PSH Flags": 0.0,
        "Fwd URG Flags": 0.0,
        "Bwd URG Flags": 0.0,
        "Fwd Header Length": fwd_header_length,
        "Bwd Header Length": bwd_header_length,
        "Fwd Packets/s": fwd_pkts_per_sec,
        "Bwd Packets/s": bwd_pkts_per_sec,
        "Packet Length Min": min(fwd_avg_pkt_len, bwd_avg_pkt_len) * 0.8,
        "Packet Length Max": packet_length_max,
        "Packet Length Mean": packet_length_mean,
        "Packet Length Std": pkt_len_std,
        "Packet Length Variance": pkt_len_variance,
        "FIN Flag Count": fin_flag_count,
        "SYN Flag Count": syn_flag_count,
        "RST Flag Count": rst_flag_count,
        "PSH Flag Count": psh_flag_count,
        "ACK Flag Count": ack_flag_count,
        "URG Flag Count": urg_flag_count,
        "CWE Flag Count": cwe_flag_count,
        "ECE Flag Count": ece_flag_count,
        "Down/Up Ratio": bwd_pkts / max(fwd_pkts, 1),
        "Avg Packet Size": avg_packet_size,
        "Avg Fwd Segment Size": avg_fwd_segment_size,
        "Avg Bwd Segment Size": avg_bwd_segment_size,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": subflow_fwd_packets,
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Packets": subflow_bwd_packets,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init Fwd Win Bytes": init_fwd_win_bytes,
        "Init Bwd Win Bytes": init_bwd_win_bytes,
        "Fwd Act Data Packets": fwd_act_data_packets,
        "Fwd Seg Size Min": fwd_segment_size_min,
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min,
    }
    
    # ===== BUILD FEATURE VECTOR IN EXACT ORDER =====
    feature_vector = []
    for feature_name in features:
        value = feature_dict.get(feature_name, 0.0)
        feature_vector.append(float(value))
    
    return feature_vector

def validate_feature_vector(vector: list) -> bool:
    if not isinstance(vector, list):
        return False
    # Enforce strict 77-feature dimension as required by production models
    if len(vector) != 77:
        logger.error(f"Feature vector length mismatch: expected 77, got {len(vector)}")
        return False
    return True

def extract_features_batch(events: list[dict], features: list = None) -> list[list | None]:
    """
    Extract features for a batch of events efficiently.
    
    Args:
        events: List of Suricata EVE JSON event dictionaries
        features: List of feature names
        
    Returns:
        List containing the feature vector or None for each event.
    """
    if features is None:
        features = load_feature_names()
        
    return [extract_features_from_eve(event, features) for event in events]
