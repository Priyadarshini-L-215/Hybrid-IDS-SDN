"""
Unified feature extraction module for Hybrid IDS (Sentinel Core V4).
Extracts 49 UNSW-NB15 style features from Suricata EVE JSON events.
Includes a StatefulFeatureTracker for temporal connection-tracking features.
"""

import json
import logging
import joblib
import threading
import time
import hashlib
import functools
from pathlib import Path
from collections import deque
import base64

def extract_ttl_from_packet(packet_b64: str) -> float:
    """Extracts TTL or Hop Limit from raw base64 packet."""
    try:
        packet_bytes = base64.b64decode(packet_b64)
        eth_type = packet_bytes[12:14].hex()
        sll_type = packet_bytes[14:16].hex()
        
        if eth_type == '8100': # VLAN Tagged
            vlan_eth_type = packet_bytes[16:18].hex()
            if vlan_eth_type == '0800': # IPv4
                return float(packet_bytes[18 + 8])
            elif vlan_eth_type == '86dd': # IPv6
                return float(packet_bytes[18 + 7])
        
        if eth_type == '0800': # IPv4 Ethernet
            return float(packet_bytes[14 + 8])
        elif eth_type == '86dd': # IPv6 Ethernet
            return float(packet_bytes[14 + 7])
        elif sll_type == '0800': # IPv4 SLL
            return float(packet_bytes[16 + 8])
        elif sll_type == '86dd': # IPv6 SLL
            return float(packet_bytes[16 + 7])
    except Exception:
        pass
    return 0.0

logger = logging.getLogger(__name__)

# --- CACHING DECORATOR ---
def event_cache(maxsize=128):
    """
    LRU Cache for feature extraction based on event payload fingerprint.
    Prevents redundant calculations for identical burst events.
    """
    def decorator(func):
        cache = {}
        # We don't use functools.lru_cache because dicts are unhashable
        # Instead we compute a stable hash of the event dict
        @functools.wraps(func)
        def wrapper(event_dict, *args, **kwargs):
            # Create stable fingerprint
            try:
                # Only hash fields that matter for extraction
                # Instead of expensive JSON + SHA256, use a fast tuple fingerprint
                # We sort the keys once and reuse the order for speed
                cache_keys = sorted([k for k in event_dict.keys() if k not in {'timestamp', 'flow_id', 'pcap_cnt'}])
                fingerprint = tuple(event_dict.get(k) for k in cache_keys)
                
                if fingerprint in cache:
                    return cache[fingerprint]
                
                result = func(event_dict, *args, **kwargs)
                
                if len(cache) >= maxsize:
                    # Simple FIFO eviction
                    cache.pop(next(iter(cache)))
                cache[fingerprint] = result
                return result
            except Exception:
                return func(event_dict, *args, **kwargs)
        return wrapper
    return decorator

# --- STATEFUL TRACKING ---
from collections import deque, Counter
import asyncio

# --- STATEFUL TRACKING ---
class StatefulFeatureTracker:
    def __init__(self, window_size=10000): # Increased default window size as per plan
        self.window = deque(maxlen=window_size)
        self._lock = asyncio.Lock()
        
        # Multi-level indices for O(1) lookups
        self.idx_src = Counter()
        self.idx_dst = Counter()
        self.idx_src_srv = Counter()
        self.idx_dst_srv = Counter()
        self.idx_dst_dport = Counter()
        self.idx_dst_sport = Counter()
        self.idx_src_dst = Counter()

    async def update(self, event_meta):
        async with self._lock:
            # If we're at max capacity, we need to decrement indices for the element being evicted
            if len(self.window) == self.window.maxlen:
                old = self.window[0] # peek oldest
                self._update_indices(old, -1)
            
            self.window.append(event_meta)
            self._update_indices(event_meta, 1)

    def _update_indices(self, entry, delta):
        """Helper to increment/decrement all related indices with zero-pruning."""
        s, d = entry['src_ip'], entry['dst_ip']
        srv = entry['service']
        dp, sp = entry['dst_port'], entry['src_port']
        
        # Helper to update and prune
        def _upd(idx, key, d):
            idx[key] += d
            if idx[key] <= 0:
                del idx[key]

        _upd(self.idx_src, s, delta)
        _upd(self.idx_dst, d, delta)
        _upd(self.idx_src_srv, (s, srv), delta)
        _upd(self.idx_dst_srv, (d, srv), delta)
        _upd(self.idx_dst_dport, (d, dp), delta)
        _upd(self.idx_dst_sport, (d, sp), delta)
        _upd(self.idx_src_dst, (s, d), delta)

    def get_ct_stats(self, src_ip, dst_ip, service, dst_port, src_port):
        """O(1) lookups instead of O(n) linear scan."""
        # Note: We don't hold the lock during read for maximum performance.
        # Minimal risk of slightly stale counts during concurrent update/read.
        return {
            'ct_srv_src': float(self.idx_src_srv.get((src_ip, service), 0)),
            'ct_srv_dst': float(self.idx_dst_srv.get((dst_ip, service), 0)),
            'ct_dst_ltm': float(self.idx_dst.get(dst_ip, 0)),
            'ct_src_ltm': float(self.idx_src.get(src_ip, 0)),
            'ct_src_dport_ltm': float(self.idx_dst_dport.get((dst_ip, dst_port), 0)),
            'ct_dst_sport_ltm': float(self.idx_dst_sport.get((dst_ip, src_port), 0)),
            'ct_dst_src_ltm': float(self.idx_src_dst.get((src_ip, dst_ip), 0))
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
    global _CACHED_FEATURES
    if features_path is None and _CACHED_FEATURES is not None:
        return _CACHED_FEATURES
    
    is_default = features_path is None
    if features_path is None:
        features_path = Path(__file__).resolve().parents[2] / "models" / "features.json"
    
    features_path = Path(features_path)
    try:
        if not features_path.exists():
            if is_default:
                _CACHED_FEATURES = DEFAULT_FEATURES
            return DEFAULT_FEATURES
        with open(features_path, 'r', encoding='utf-8') as f:
            features = json.load(f)
        if is_default:
            _CACHED_FEATURES = features
        return features
    except Exception:
        if is_default:
            _CACHED_FEATURES = DEFAULT_FEATURES
        return DEFAULT_FEATURES

def get_proto_encoder():
    global _LE_PROTO
    if _LE_PROTO is None:
        # Check multiple possible paths
        search_paths = [
            Path(__file__).resolve().parents[2] / "models" / "le_proto_multi.pkl",
            Path(__file__).resolve().parents[2] / "models" / "le_proto.pkl",
            Path(__file__).resolve().parents[2] / "new model" / "le_proto.pkl"
        ]
        for le_path in search_paths:
            if le_path.exists():
                try:
                    _LE_PROTO = joblib.load(le_path)
                    logger.info(f"Loaded protocol encoder from {le_path}")
                    break
                except Exception as e:
                    logger.error(f"Failed to load {le_path}: {e}")
    return _LE_PROTO

@event_cache(maxsize=256)
async def extract_features_from_eve(event: dict, features: list = None) -> list | None:
    if event.get('event_type') not in ['flow', 'alert']:
        return None
    
    if features is None:
        features = load_feature_names()
    
    flow = event.get('flow', {})
    if not flow and 'raw' in event:
        flow = event['raw'].get('flow', {})
    
    # Basic Metrics - Robust fallback for flat/aggregated events
    fwd_pkts = float(flow.get('pkts_toserver') or event.get('packet_count') or 0)
    bwd_pkts = float(flow.get('pkts_toclient') or 0)
    fwd_bytes = float(flow.get('bytes_toserver') or event.get('byte_count') or 0)
    bwd_bytes = float(flow.get('bytes_toclient') or 0)
    age_sec = float(flow.get('age') or event.get('duration') or 0)
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
    
    await tracker.update({
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
    # Notes on feature accuracy:
    # - IAT std, jitter: set to 0.0 — requires raw per-packet timestamps not available in EVE JSON
    # - synack/ackdat: use Suricata's syn_rtt field if present, otherwise split rtt 60/40
    # - dwin: TCP receive window size (not ACK number)
    # - sloss/dloss: approximate from retransmission counts if available; else 0.0
    rtt = float(flow.get('rtt', 0) or 0)
    syn_rtt = float(flow.get('syn_rtt', 0) or (rtt * 0.6))
    ackdat = max(rtt - syn_rtt, 0.0)

    feature_dict = {
        'flow_duration': float(age_ms),
        'total_fwd_packets': float(fwd_pkts),
        'total_bwd_packets': float(bwd_pkts),
        'total_fwd_bytes': float(fwd_bytes),
        'total_bwd_bytes': float(bwd_bytes),
        'flow_iat_mean': float(flow_iat_mean),
        'flow_iat_std': 0.0,
        'fwd_iat_mean': float(fwd_iat_mean),
        'bwd_iat_mean': float(bwd_iat_mean),
        'pkt_len_mean': float(total_bytes / max(total_pkts, 1)),
        'pkt_len_std': 0.0,
        'spkts': float(fwd_pkts),
        'dpkts': float(bwd_pkts),
        'sbytes': float(fwd_bytes),
        'dbytes': float(bwd_bytes),
        'sload': float((fwd_bytes * 8) / safe_age),
        'dload': float((bwd_bytes * 8) / safe_age),
        'sloss': float(flow.get('pkts_toserver_retrans', 0) or 0),
        'dloss': float(flow.get('pkts_toclient_retrans', 0) or 0),
        'sttl': float(
            (event.get('ip', {}) if isinstance(event.get('ip'), dict) else {}).get('ttl') or 
            (event.get('ipv6', {}) if isinstance(event.get('ipv6'), dict) else {}).get('hop_limit') or
            (extract_ttl_from_packet(event.get('raw', {}).get('packet', '')) if 'raw' in event and event['raw'].get('packet') else 0.0) or
            (extract_ttl_from_packet(event.get('packet', '')) if event.get('packet') else 0.0) or
            64.0
        ),
        'dttl': float(flow.get('dttl') or 0.0),
        'swin': float(tcp.get('window', 0) or 0),
        'dwin': float(tcp.get('window', 0) or 0),
        'stcpb': float(tcp.get('seq', 0) or 0),
        'dtcpb': float(tcp.get('ack', 0) or 0),
        'tcprtt': float(rtt),
        'synack': float(syn_rtt),
        'ackdat': float(ackdat),
        'sinpkt': float(fwd_iat_mean),
        'dinpkt': float(bwd_iat_mean),
        'sjit': 0.0,
        'djit': 0.0,
        'ct_state_ttl': float(ct_stats.get('ct_src_ltm', 0) * 0.5),
        'ct_flw_http_mthd': 1.0 if (event.get('http', {}) or {}).get('http_method') in ['GET', 'POST'] else 0.0,
        'ct_srv_src': float(ct_stats.get('ct_srv_src', 0)),
        'ct_srv_dst': float(ct_stats.get('ct_srv_dst', 0)),
        'ct_dst_ltm': float(ct_stats.get('ct_dst_ltm', 0)),
        'ct_src_ltm': float(ct_stats.get('ct_src_ltm', 0)),
        'ct_src_dport_ltm': float(ct_stats.get('ct_src_dport_ltm', 0)),
        'ct_dst_sport_ltm': float(ct_stats.get('ct_dst_sport_ltm', 0)),
        'ct_dst_src_ltm': float(ct_stats.get('ct_dst_src_ltm', 0)),
        'smeansz': float(fwd_bytes / max(fwd_pkts, 1)),
        'dmeansz': float(bwd_bytes / max(bwd_pkts, 1)),
        'trans_depth': float((event.get('http', {}) or {}).get('depth', 0) or 0),
        'res_bdy_len': float((event.get('http', {}) or {}).get('length', 0) or 0),
        'is_sm_ips_ports': 1.0 if src_ip == dst_ip and src_port == dst_port else 0.0,
        'is_ftp_login': 1.0 if service == 'ftp' and (event.get('ftp', {}) or {}).get('command') == 'USER' else 0.0,
        'ct_ftp_cmd': float((event.get('ftp', {}) or {}).get('command_count', 0) or 0),
        'app_proto': float(proto_val)
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

async def extract_features_batch(events: list[dict], features: list = None) -> list[list | None]:
    if features is None: features = load_feature_names()
    expected_dim = len(features)
    vectors = []
    for event in events:
        vec = await extract_features_from_eve(event, features)
        if vec and len(vec) < expected_dim:
            vec.extend([0.0] * (expected_dim - len(vec)))
        vectors.append(vec)
    return vectors
