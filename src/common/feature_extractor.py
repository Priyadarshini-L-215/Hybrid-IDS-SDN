"""
Unified feature extraction module for Hybrid IDS (Sentinel Core V4).
Extracts 49 UNSW-NB15 style features from Suricata EVE JSON events.
Includes a StatefulFeatureTracker for temporal connection-tracking features.
"""

import json
import logging
import joblib
from pathlib import Path
from collections import deque

logger = logging.getLogger(__name__)

# --- STATEFUL TRACKING ---
class StatefulFeatureTracker:
    def __init__(self, window_size=100):
        self.window = deque(maxlen=window_size)

    def update(self, event_meta):
        self.window.append(event_meta)

    def get_ct_stats(self, src_ip, dst_ip, service, dst_port, src_port):
        ct_srv_src = 0
        ct_srv_dst = 0
        ct_dst_ltm = 0
        ct_src_ltm = 0
        ct_src_dport_ltm = 0
        ct_dst_sport_ltm = 0
        ct_dst_src_ltm = 0
        
        for entry in self.window:
            # Matches Source IP
            if entry['src_ip'] == src_ip:
                ct_src_ltm += 1
                if entry['service'] == service:
                    ct_srv_src += 1
                if entry['dst_ip'] == dst_ip:
                    ct_dst_src_ltm += 1
            
            # Matches Destination IP
            if entry['dst_ip'] == dst_ip:
                ct_dst_ltm += 1
                if entry['service'] == service:
                    ct_srv_dst += 1
                if entry['dst_port'] == dst_port:
                    ct_src_dport_ltm += 1
            
            # Matches Source Port for destination sport check
            if entry['src_port'] == src_port and entry['dst_ip'] == dst_ip:
                ct_dst_sport_ltm += 1
                    
        return {
            'ct_srv_src': float(ct_srv_src),
            'ct_srv_dst': float(ct_srv_dst),
            'ct_dst_ltm': float(ct_dst_ltm),
            'ct_src_ltm': float(ct_src_ltm),
            'ct_src_dport_ltm': float(ct_src_dport_ltm),
            'ct_dst_sport_ltm': float(ct_dst_sport_ltm),
            'ct_dst_src_ltm': float(ct_dst_src_ltm)
        }

# Singleton instance for the process
tracker = StatefulFeatureTracker()

# --- MODEL ASSETS ---
_CACHED_FEATURES = None
_LE_PROTO = None

DEFAULT_FEATURES = [
    'flow_duration','total_fwd_packets','total_bwd_packets',
    'total_fwd_bytes','total_bwd_bytes',
    'flow_iat_mean','flow_iat_std',
    'fwd_iat_mean','bwd_iat_mean',
    'pkt_len_mean','pkt_len_std',
    'spkts','dpkts','sbytes','dbytes',
    'sload','dload','sloss','dloss',
    'sttl','dttl','swin','dwin',
    'stcpb','dtcpb','tcprtt','synack','ackdat',
    'sinpkt','dinpkt','sjit','djit',
    'ct_state_ttl','ct_flw_http_mthd',
    'ct_srv_src','ct_srv_dst',
    'ct_dst_ltm','ct_src_ltm',
    'ct_src_dport_ltm','ct_dst_sport_ltm',
    'ct_dst_src_ltm',
    'smeansz','dmeansz','trans_depth','res_bdy_len',
    'is_sm_ips_ports','is_ftp_login','ct_ftp_cmd',
    'app_proto'
]

def load_feature_names(features_path: str | Path = None) -> list:
    if features_path is None:
        features_path = Path(__file__).resolve().parents[2] / "models" / "features.json"
    
    features_path = Path(features_path)
    global _CACHED_FEATURES
    if _CACHED_FEATURES is not None:
        return _CACHED_FEATURES

    try:
        if not features_path.exists():
            _CACHED_FEATURES = DEFAULT_FEATURES
            return DEFAULT_FEATURES
        with open(features_path, 'r', encoding='utf-8') as f:
            features = json.load(f)
        _CACHED_FEATURES = features
        return features
    except Exception:
        _CACHED_FEATURES = DEFAULT_FEATURES
        return DEFAULT_FEATURES

def get_proto_encoder():
    global _LE_PROTO
    if _LE_PROTO is None:
        le_path = Path(__file__).resolve().parents[2] / "models" / "le_proto.pkl"
        if le_path.exists():
            try:
                _LE_PROTO = joblib.load(le_path)
            except Exception as e:
                logger.error(f"Failed to load le_proto.pkl: {e}")
    return _LE_PROTO

def extract_features_from_eve(event: dict, features: list = None) -> list | None:
    if event.get('event_type') not in ['flow', 'alert']:
        return None
    
    if features is None:
        features = load_feature_names()
    
    flow = event.get('flow', {})
    if not flow and 'raw' in event:
        flow = event['raw'].get('flow', {})
    
    # Basic Metrics
    fwd_pkts = float(flow.get('pkts_toserver', 0))
    bwd_pkts = float(flow.get('pkts_toclient', 0))
    fwd_bytes = float(flow.get('bytes_toserver', 0))
    bwd_bytes = float(flow.get('bytes_toclient', 0))
    age_sec = float(flow.get('age', 0))
    age_ms = age_sec * 1000
    
    total_pkts = fwd_pkts + bwd_pkts
    total_bytes = fwd_bytes + bwd_bytes
    safe_age = max(age_sec, 0.001)
    
    # Jitter/IAT approximations
    fwd_iat_mean = (age_ms / max(fwd_pkts - 1, 1)) if fwd_pkts > 1 else 0
    bwd_iat_mean = (age_ms / max(bwd_pkts - 1, 1)) if bwd_pkts > 1 else 0
    flow_iat_mean = (age_ms / max(total_pkts - 1, 1)) if total_pkts > 1 else 0
    
    # TCP Info
    tcp = event.get('tcp', {}) or (event.get('raw', {}).get('tcp', {}))
    
    # Update Stateful Tracker
    src_ip = event.get('src_ip', '0.0.0.0')
    dst_ip = event.get('dest_ip', '0.0.0.0')
    service = event.get('app_proto', 'unknown')
    dst_port = int(event.get('dest_port', 0))
    src_port = int(event.get('src_port', 0))
    protocol = event.get('protocol', 'TCP').lower()
    
    tracker.update({
        'src_ip': src_ip, 
        'dst_ip': dst_ip, 
        'service': service, 
        'dst_port': dst_port,
        'src_port': src_port
    })
    ct_stats = tracker.get_ct_stats(src_ip, dst_ip, service, dst_port, src_port)

    # Protocol Encoding
    le = get_proto_encoder()
    try:
        proto_val = float(le.transform([protocol])[0]) if le else 0.0
    except:
        proto_val = 0.0

    # Feature Dictionary (49 features)
    feature_dict = {
        'flow_duration': age_ms,
        'total_fwd_packets': fwd_pkts,
        'total_bwd_packets': bwd_pkts,
        'total_fwd_bytes': fwd_bytes,
        'total_bwd_bytes': bwd_bytes,
        'flow_iat_mean': flow_iat_mean,
        'flow_iat_std': flow_iat_mean * 0.1, 
        'fwd_iat_mean': fwd_iat_mean,
        'bwd_iat_mean': bwd_iat_mean,
        'pkt_len_mean': total_bytes / max(total_pkts, 1),
        'pkt_len_std': (total_bytes / max(total_pkts, 1)) * 0.2,
        'spkts': fwd_pkts,
        'dpkts': bwd_pkts,
        'sbytes': fwd_bytes,
        'dbytes': bwd_bytes,
        'sload': (fwd_bytes * 8) / safe_age,
        'dload': (bwd_bytes * 8) / safe_age,
        'sloss': float(flow.get('emergency_fwd', 0)), # Placeholder for loss
        'dloss': float(flow.get('emergency_bwd', 0)),
        'sttl': float(event.get('ip', {}).get('ttl', 64)),
        'dttl': float(flow.get('dttl', 0)), 
        'swin': float(tcp.get('window', 0)),
        'dwin': float(tcp.get('ack', 0) % 65535), # Approximation
        'stcpb': float(tcp.get('seq', 0)),
        'dtcpb': float(tcp.get('ack', 0)),
        'tcprtt': float(flow.get('rtt', 0)),
        'synack': float(flow.get('rtt', 0) * 0.6),
        'ackdat': float(flow.get('rtt', 0) * 0.4),
        'sinpkt': fwd_iat_mean,
        'dinpkt': bwd_iat_mean,
        'sjit': fwd_iat_mean * 0.05,
        'djit': bwd_iat_mean * 0.05,
        'ct_state_ttl': float(ct_stats['ct_src_ltm'] * 0.5), # Heuristic
        'ct_flw_http_mthd': 1.0 if event.get('http', {}).get('http_method') in ['GET', 'POST'] else 0.0,
        'ct_srv_src': ct_stats['ct_srv_src'],
        'ct_srv_dst': ct_stats['ct_srv_dst'],
        'ct_dst_ltm': ct_stats['ct_dst_ltm'],
        'ct_src_ltm': ct_stats['ct_src_ltm'],
        'ct_src_dport_ltm': ct_stats['ct_src_dport_ltm'],
        'ct_dst_sport_ltm': ct_stats['ct_dst_sport_ltm'],
        'ct_dst_src_ltm': ct_stats['ct_dst_src_ltm'],
        'smeansz': fwd_bytes / max(fwd_pkts, 1),
        'dmeansz': bwd_bytes / max(bwd_pkts, 1),
        'trans_depth': float(event.get('http', {}).get('depth', 0)),
        'res_bdy_len': float(event.get('http', {}).get('length', 0)),
        'is_sm_ips_ports': 1.0 if src_ip == dst_ip and src_port == dst_port else 0.0,
        'is_ftp_login': 1.0 if service == 'ftp' and event.get('ftp', {}).get('command') == 'USER' else 0.0,
        'ct_ftp_cmd': float(event.get('ftp', {}).get('command_count', 0)),
        'app_proto': proto_val
    }
    
    feature_vector = []
    for feature_name in features:
        feature_vector.append(float(feature_dict.get(feature_name, 0.0)))
    
    return feature_vector

def validate_feature_vector(vector: list, expected_dim: int = None) -> bool:
    if not isinstance(vector, list): return False
    if expected_dim is not None and len(vector) != expected_dim:
        logger.error(f"Dim mismatch: expected {expected_dim}, got {len(vector)}")
        return False
    return True

def extract_features_batch(events: list[dict], features: list = None) -> list[list | None]:
    if features is None: features = load_feature_names()
    return [extract_features_from_eve(event, features) for event in events]
