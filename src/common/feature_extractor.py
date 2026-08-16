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
        @functools.wraps(func)
        async def wrapper(event_dict, *args, **kwargs):
            try:
                cache_keys = sorted([k for k in event_dict.keys() if k not in {'timestamp', 'flow_id', 'pcap_cnt'}])
                fingerprint = tuple(event_dict.get(k) for k in cache_keys)
                
                if fingerprint in cache:
                    return cache[fingerprint]
                
                result = await func(event_dict, *args, **kwargs)
                
                if len(cache) >= maxsize:
                    cache.pop(next(iter(cache)))
                cache[fingerprint] = result
                return result
            except Exception:
                return await func(event_dict, *args, **kwargs)
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
        # Using dict instead of Counter for faster updates
        self.idx_src = {}
        self.idx_dst = {}
        self.idx_src_srv = {}
        self.idx_dst_srv = {}
        self.idx_dst_dport = {}
        self.idx_dst_sport = {}
        self.idx_src_dst = {}
        
        # Additional state for C2 features
        self.connection_timestamps = {}  # (src_ip, dst_ip) -> deque(timestamps, maxlen=10)
        self.src_dst_counts = {}  # src_ip -> Counter of dst_ips

    async def update(self, event_meta):
        async with self._lock:
            # Get event time or fallback to current time
            now = event_meta.get('time') or time.time()
            
            # Load correlation window from config to evict old entries
            try:
                from common.config import get_cfg
                decay_window = float(get_cfg("detection.correlation_window", 60.0))
            except Exception:
                decay_window = 60.0
                
            # Evict entries older than the decay window
            while self.window and (now - (self.window[0].get('time') or 0.0) > decay_window):
                old = self.window.popleft()
                self._update_indices(old, -1)
                
            # If we're still at max capacity, evict the oldest
            if len(self.window) == self.window.maxlen:
                old = self.window.popleft()
                self._update_indices(old, -1)
            
            self.window.append(event_meta)
            self._update_indices(event_meta, 1)

    def _update_indices(self, entry, delta):
        """Helper to increment/decrement all related indices with zero-pruning."""
        s, d = entry['src_ip'], entry['dst_ip']
        srv = entry['service']
        dp, sp = entry['dst_port'], entry['src_port']
        t = entry.get('time')
        
        # Inlined dict updates for performance: 7 index updates per packet
        for idx, key in [
            (self.idx_src, s),
            (self.idx_dst, d),
            (self.idx_src_srv, (s, srv)),
            (self.idx_dst_srv, (d, srv)),
            (self.idx_dst_dport, (d, dp)),
            (self.idx_dst_sport, (d, sp)),
            (self.idx_src_dst, (s, d))
        ]:
            val = idx.get(key, 0) + delta
            if val <= 0:
                if key in idx: del idx[key]
            else:
                idx[key] = val

        # Update C2 specific metrics if time is tracked
        if t is not None:
            key = (s, d)
            if delta == 1:
                if key not in self.connection_timestamps:
                    self.connection_timestamps[key] = deque(maxlen=10)
                self.connection_timestamps[key].append(t)
                
                if s not in self.src_dst_counts:
                    self.src_dst_counts[s] = Counter()
                self.src_dst_counts[s][d] += 1
            else:
                if key in self.connection_timestamps:
                    try:
                        self.connection_timestamps[key].remove(t)
                    except ValueError:
                        if self.connection_timestamps[key]:
                            self.connection_timestamps[key].popleft()
                    if not self.connection_timestamps[key]:
                        del self.connection_timestamps[key]
                
                if s in self.src_dst_counts:
                    self.src_dst_counts[s][d] -= 1
                    if self.src_dst_counts[s][d] <= 0:
                        del self.src_dst_counts[s][d]
                    if not self.src_dst_counts[s]:
                        del self.src_dst_counts[s]

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

    def get_c2_stats(self, src_ip, dst_ip):
        ts = list(self.connection_timestamps.get((src_ip, dst_ip), []))
        if len(ts) >= 2:
            import numpy as np
            intervals = [ts[i] - ts[i-1] for i in range(1, len(ts))]
            mean_val = float(np.mean(intervals))
            std_val = float(np.std(intervals)) if len(intervals) >= 2 else 0.0
        else:
            mean_val = 0.0
            std_val = 0.0
            
        freq = float(len(ts))
        rep_count = float(len(self.src_dst_counts.get(src_ip, {})))
        
        return {
            'connection_frequency': freq,
            'repeated_destination_count': rep_count,
            'beacon_interval_mean': mean_val,
            'beacon_interval_std': std_val
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

async def extract_c2_features_from_eve(event: dict, features: list) -> list | None:
    event_type = event.get("event_type")
    if event_type not in ("flow", "tls", "dns", "http", "alert"):
        return None
        
    # Basic info
    src_ip = event.get('src_ip', '0.0.0.0')
    dst_ip = event.get('dest_ip', '0.0.0.0')
    service = event.get('app_proto', 'unknown')
    dst_port = int(event.get('dest_port', 0))
    src_port = int(event.get('src_port', 0))
    
    # Get timestamp for tracking
    timestamp_str = event.get("timestamp", "")
    try:
        from datetime import datetime
        t = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).timestamp()
    except:
        t = time.time()
        
    # Update stateful tracker with time
    await tracker.update({
        'src_ip': src_ip, 
        'dst_ip': dst_ip, 
        'service': service, 
        'dst_port': dst_port,
        'src_port': src_port,
        'time': t
    })
    
    c2_stats = tracker.get_c2_stats(src_ip, dst_ip)
    
    # 1. ja3_present
    ja3_present = 1.0 if event.get("tls", {}).get("ja3") else 0.0
    
    # 2-6. TLS certificate properties
    tls_info = event.get("tls", {}) or {}
    issuer_length = float(len(tls_info.get("issuerdn", "")))
    subject_length = float(len(tls_info.get("subject", "")))
    certificate_serial_length = float(len(tls_info.get("serial", "")))
    certificate_fingerprint_length = float(len(tls_info.get("fingerprint", "")))
    
    certificate_validity_days = 0.0
    try:
        nb = tls_info.get("notbefore")
        na = tls_info.get("notafter")
        if nb and na:
            nb = nb.split(".")[0].split("+")[0].rstrip("Z")
            na = na.split(".")[0].split("+")[0].rstrip("Z")
            dt_nb = datetime.fromisoformat(nb)
            dt_na = datetime.fromisoformat(na)
            certificate_validity_days = float((dt_na - dt_nb).days)
    except:
        pass
        
    # 7. self_signed_flag
    self_signed_flag = 1.0 if tls_info.get("self_signed", False) else 0.0
    
    # 8. tls_version
    tls_version = 0.0
    version_str = tls_info.get("version", "")
    if "1.3" in version_str: tls_version = 1.3
    elif "1.2" in version_str: tls_version = 1.2
    elif "1.1" in version_str: tls_version = 1.1
    elif "1.0" in version_str: tls_version = 1.0
    
    # 9. sni_dns_mismatch
    sni = tls_info.get("sni", "").lower()
    dns_info = event.get("dns", {}) or {}
    dns_query = dns_info.get("query", "").lower()
    http_info = event.get("http", {}) or {}
    http_host = http_info.get("hostname", "").lower()
    
    sni_dns_mismatch = 0.0
    if sni:
        if dns_query and sni != dns_query:
            sni_dns_mismatch = 1.0
        elif http_host and sni != http_host:
            sni_dns_mismatch = 1.0
            
    # Helper to compute Shannon entropy
    import math
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        text_len = len(text)
        frequencies = Counter(text)
        entropy = 0.0
        for count in frequencies.values():
            p = count / text_len
            entropy -= p * math.log2(p)
        return float(entropy)
        
    # 10. domain_length
    domain = dns_query or http_host or sni
    domain_length = float(len(domain))
    
    # 11. subdomain_depth
    subdomain_depth = float(domain.count(".")) if domain else 0.0
    
    # 12. dns_entropy
    dns_entropy = calculate_entropy(domain)
    
    # 13. resolved_domain_count
    answers = dns_info.get("answers", [])
    resolved_domain_count = float(len(answers)) if isinstance(answers, list) else 0.0
    
    # 14. dynamic_dns_indicator
    dynamic_dns_indicator = 0.0
    if domain:
        dyndns_suffixes = [".dyndns.org", ".no-ip.info", ".no-ip.org", ".ddns.net", ".duckdns.org", ".zapto.org"]
        if any(domain.endswith(suffix) for suffix in dyndns_suffixes):
            dynamic_dns_indicator = 1.0
            
    # 15. dns_ttl
    dns_ttl = 0.0
    if isinstance(answers, list) and answers:
        ttls = [float(a.get("ttl", 0.0)) for a in answers if isinstance(a, dict) and "ttl" in a]
        if ttls:
            dns_ttl = float(max(ttls))
            
    # 16-20. HTTP properties
    ua = http_info.get("http_user_agent", "")
    user_agent_length = float(len(ua))
    user_agent_entropy = calculate_entropy(ua)
    
    hostname_length = float(len(http_host))
    url = http_info.get("url", "")
    url_length = float(len(url))
    url_entropy = calculate_entropy(url)
    
    # 21. http_method_is_post
    method = http_info.get("http_method", "")
    http_method_is_post = 1.0 if method.upper() == "POST" else 0.0
    
    # 22-26. Connection state/beaconing properties (from tracker)
    connection_frequency = c2_stats['connection_frequency']
    repeated_destination_count = c2_stats['repeated_destination_count']
    beacon_interval_mean = c2_stats['beacon_interval_mean']
    beacon_interval_std = c2_stats['beacon_interval_std']
    
    flow = event.get("flow", {}) or {}
    session_duration = float(flow.get("age", 0.0))
    
    # 27-28. Ratios
    pkts_in = float(flow.get("pkts_toclient", 0.0))
    pkts_out = float(flow.get("pkts_toserver", 0.0))
    packet_ratio = float(pkts_out / (pkts_in + pkts_out)) if (pkts_in + pkts_out) > 0.0 else 0.5
    
    bytes_in = float(flow.get("bytes_toclient", 0.0))
    bytes_out = float(flow.get("bytes_toserver", 0.0))
    byte_ratio = float(bytes_out / (bytes_in + bytes_out)) if (bytes_in + bytes_out) > 0.0 else 0.5
    
    # 29. is_standard_port
    is_standard_port = 1.0 if dst_port in (80, 443, 8080, 8443) else 0.0
    
    # Protocol one-hot encoding for LightGBM C2 model
    proto = event.get("proto", "").upper()
    protocol_tcp = 1.0 if proto == "TCP" else 0.0
    protocol_udp = 1.0 if proto == "UDP" else 0.0
    
    # TLS version one-hot encoding for LightGBM C2 model
    tls_version_tls1_2 = 1.0 if "1.2" in version_str else 0.0
    tls_version_tls1_3 = 1.0 if "1.3" in version_str else 0.0

    feature_dict = {
        # Raw port features (used by 25-feature C2 model)
        'source_port': float(src_port),
        'destination_port': float(dst_port),
        # Protocol one-hot features (used by 25-feature C2 model)
        'protocol_tcp': protocol_tcp,
        'protocol_udp': protocol_udp,
        # TLS version one-hot features (used by 25-feature C2 model)
        'tls_version_tls1_2': tls_version_tls1_2,
        'tls_version_tls1_3': tls_version_tls1_3,
        # Common features (used by both 25 and 29-feature schemas)
        'ja3_present': ja3_present,
        'issuer_length': issuer_length,
        'subject_length': subject_length,
        'certificate_serial_length': certificate_serial_length,
        'certificate_fingerprint_length': certificate_fingerprint_length,
        'certificate_validity_days': certificate_validity_days,
        'self_signed_flag': self_signed_flag,
        'tls_version': tls_version,
        'sni_dns_mismatch': sni_dns_mismatch,
        'domain_length': domain_length,
        'subdomain_depth': subdomain_depth,
        'dns_entropy': dns_entropy,
        'resolved_domain_count': resolved_domain_count,
        'dynamic_dns_indicator': dynamic_dns_indicator,
        'dns_ttl': dns_ttl,
        'user_agent_length': user_agent_length,
        'user_agent_entropy': user_agent_entropy,
        'hostname_length': hostname_length,
        'url_length': url_length,
        'url_entropy': url_entropy,
        'http_method_is_post': http_method_is_post,
        'connection_frequency': connection_frequency,
        'repeated_destination_count': repeated_destination_count,
        'session_duration': session_duration,
        'beacon_interval_mean': beacon_interval_mean,
        'beacon_interval_std': beacon_interval_std,
        'packet_ratio': packet_ratio,
        'byte_ratio': byte_ratio,
        'is_standard_port': is_standard_port
    }
    
    feature_vector = []
    for fn in features:
        feature_vector.append(float(feature_dict.get(fn, 0.0)))
        
    return feature_vector

@event_cache(maxsize=256)
async def extract_features_from_eve(event: dict, features: list = None) -> list | None:
    if features is None:
        features = load_feature_names()
        
    if "features" in event and isinstance(event["features"], list):
        return event["features"]
        
    if features and "ja3_present" in features:
        return await extract_c2_features_from_eve(event, features)
        
    if event.get('event_type') not in ['flow', 'alert']:
        return None
    
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
    
    # Parse event timestamp if available, fallback to current time
    event_timestamp = event.get("timestamp")
    t = time.time()
    if event_timestamp:
        try:
            from datetime import datetime
            t = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00")).timestamp()
        except Exception:
            pass

    await tracker.update({
        'src_ip': src_ip, 
        'dst_ip': dst_ip, 
        'service': service, 
        'dst_port': dst_port,
        'src_port': src_port,
        'time': t
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
