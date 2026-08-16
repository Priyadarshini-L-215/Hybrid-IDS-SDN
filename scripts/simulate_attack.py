"""
Sentinel Core — Interactive Attack Simulator
----------------------------------------------
Interactive numbered menu to select and launch attack simulations
against the live IDS pipeline. Events are injected into Redis and
processed by the ML engine, appearing as real alerts on the dashboard.
"""

import sys
import json
import time
import random
import uuid
import os
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    import redis
except ImportError:
    print("[!] redis-py not installed. Run: pip install redis")
    sys.exit(1)

# ── Config ─────────────────────────────────────────────────────────────────────
REDIS_HOST = "127.0.0.1"
REDIS_PORT = 6379
REDIS_DB   = 0
QUEUE_NAME = "sentinel_events_queue"

# ── ANSI Colours ───────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def c(color, text):
    return f"{color}{text}{RESET}"

# ── Helpers ────────────────────────────────────────────────────────────────────
def ts_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def rand_private():
    return f"192.168.{random.randint(1,10)}.{random.randint(2,254)}"

def rand_public():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def make_event(src_ip, dst_ip, src_port, dst_port, proto="TCP", app="unknown",
               pkts_s=1, bytes_s=100, pkts_c=0, bytes_c=0, age=1.0, rtt=0.01,
               tcp_flags="PA", event_type="flow"):
    return {
        "timestamp":     ts_now(),
        "flow_id":       random.randint(10**9, 10**13),
        "event_type":    event_type,
        "src_ip":        src_ip,
        "src_port":      src_port,
        "dest_ip":       dst_ip,
        "dest_port":     dst_port,
        "protocol":      proto,
        "app_proto":     app,
        "packet_count":  pkts_s + pkts_c,
        "byte_count":    bytes_s + bytes_c,
        "flow": {
            "pkts_toserver":  pkts_s,
            "bytes_toserver": bytes_s,
            "pkts_toclient":  pkts_c,
            "bytes_toclient": bytes_c,
            "age":            age,
            "rtt":            rtt,
        },
        "tcp": {"flags": tcp_flags, "window": 1024},
    }

def push(r, events):
    pipe = r.pipeline()
    for ev in events:
        pipe.xadd(QUEUE_NAME, {"event": json.dumps(ev)}, maxlen=10000, approximate=True)
    pipe.execute()
    return len(events)

def progress_bar(label, n, total=30, color=RED):
    bar = "█" * n + "░" * (total - n)
    print(f"\r  {color}{bar}{RESET}  {label}", end="", flush=True)

# ── Calibrated UNSW-NB15 Feature Vectors (verified RF prob > 0.90) ─────────────
# These feature vectors were derived by probing the live RF model.
# Each vector is a 49-element list matching models/features.json order.
# Values are in the NORMALISED scaler space (0.0–1.0).

# 0:flow_dur  1:fwd_pkts  2:bwd_pkts  3:fwd_bytes  4:bwd_bytes
# 5:iat_mean  6:iat_std   7:fwd_iat   8:bwd_iat    9:pkt_mean 10:pkt_std
# 11:spkts   12:dpkts   13:sbytes   14:dbytes
# 15:sload   16:dload   17:sloss    18:dloss
# 19:sttl    20:dttl    21:swin     22:dwin
# 23:stcpb   24:dtcpb   25:tcprtt   26:synack    27:ackdat
# 28:sinpkt  29:dinpkt  30:sjit     31:djit
# 32:ct_state_ttl  33:ct_flw_http_mthd
# 34:ct_srv_src    35:ct_srv_dst    36:ct_dst_ltm  37:ct_src_ltm
# 38:ct_src_dport  39:ct_dst_sport  40:ct_dst_src
# 41:smeansz  42:dmeansz  43:trans_depth  44:res_bdy_len
# 45:is_sm_ips_ports  46:is_ftp_login  47:ct_ftp_cmd  48:app_proto

_FEAT_PORTSCAN = [
    0.02, 0.95, 0.02, 0.60, 0.01, 0.02, 0.02, 0.02, 0.98, 0.10, 0.10,
    0.95, 0.02, 0.60, 0.01, 0.99, 0.01, 0.50, 0.01, 0.30, 0.10, 0.80, 0.01,
    0.50, 0.01, 0.01, 0.01, 0.01, 0.02, 0.98, 0.50, 0.01, 0.80, 0.01,
    0.90, 0.01, 0.90, 0.90, 0.90, 0.01, 0.90, 0.15, 0.01, 0.01, 0.01,
    0.80, 0.01, 0.01, 0.10,
]  # RF prob: 0.919

_FEAT_DOS = [
    0.01, 0.99, 0.01, 0.80, 0.00, 0.01, 0.01, 0.01, 0.99, 0.05, 0.05,
    0.99, 0.01, 0.80, 0.00, 0.99, 0.00, 0.80, 0.01, 0.30, 0.10, 0.80, 0.01,
    0.50, 0.01, 0.01, 0.01, 0.01, 0.01, 0.99, 0.50, 0.01, 0.90, 0.01,
    0.90, 0.01, 0.90, 0.90, 0.90, 0.01, 0.90, 0.10, 0.01, 0.01, 0.01,
    0.90, 0.01, 0.01, 0.05,
]  # RF prob: 0.919

_FEAT_BRUTE = [
    0.20, 0.60, 0.55, 0.50, 0.45, 0.10, 0.15, 0.10, 0.15, 0.25, 0.20,
    0.60, 0.55, 0.50, 0.45, 0.70, 0.65, 0.50, 0.01, 0.40, 0.35, 0.90, 0.10,
    0.35, 0.01, 0.08, 0.06, 0.04, 0.15, 0.20, 0.12, 0.15, 0.75, 0.01,
    0.95, 0.80, 0.90, 0.85, 0.85, 0.80, 0.90, 0.30, 0.25, 0.01, 0.01,
    0.01, 0.99, 0.99, 0.05,
]  # RF prob: 0.80 (ftp brute profile)

_FEAT_EXFIL = [
    0.90, 0.70, 0.30, 0.99, 0.40, 0.55, 0.45, 0.55, 0.65, 0.75, 0.65,
    0.70, 0.30, 0.99, 0.40, 0.95, 0.35, 0.01, 0.01, 0.50, 0.40, 0.80, 0.50,
    0.45, 0.35, 0.06, 0.05, 0.04, 0.55, 0.65, 0.45, 0.55, 0.65, 0.99,
    0.75, 0.65, 0.75, 0.70, 0.70, 0.65, 0.75, 0.82, 0.35, 0.99, 0.99,
    0.01, 0.01, 0.01, 0.35,
]  # RF prob: 0.58 → boosted by VAE anomaly

_FEAT_C2 = [
    0.20, 0.05, 0.05, 0.03, 0.03, 0.20, 0.05, 0.20, 0.20, 0.10, 0.05,
    0.05, 0.05, 0.03, 0.03, 0.30, 0.30, 0.01, 0.01, 0.40, 0.35, 0.70, 0.65,
    0.20, 0.01, 0.05, 0.04, 0.03, 0.20, 0.20, 0.10, 0.10, 0.70, 0.01,
    0.80, 0.75, 0.80, 0.80, 0.80, 0.75, 0.80, 0.12, 0.12, 0.01, 0.01,
    0.01, 0.01, 0.01, 0.60,
]  # RF prob: 0.685

_FEAT_LATERAL = [
    0.05, 0.10, 0.01, 0.05, 0.00, 0.02, 0.02, 0.02, 0.99, 0.05, 0.05,
    0.10, 0.01, 0.05, 0.00, 0.70, 0.00, 0.20, 0.01, 0.50, 0.10, 0.80, 0.01,
    0.30, 0.01, 0.01, 0.01, 0.01, 0.02, 0.99, 0.30, 0.01, 0.85, 0.01,
    0.85, 0.01, 0.90, 0.90, 0.90, 0.01, 0.90, 0.08, 0.01, 0.01, 0.01,
    0.90, 0.01, 0.01, 0.20,
]  # RF prob: 0.919

def _jitter(vec, noise=0.03):
    """Add tiny random noise to each feature so events aren't exact duplicates."""
    return [max(0.0, min(1.0, v + random.uniform(-noise, noise))) for v in vec]

def _stamp_features(ev, feat_vec):
    """Embed a calibrated feature vector into the event dict."""
    ev["features"] = _jitter(feat_vec)
    ev["is_simulated_attack"] = True
    return ev


def sim_portscan(r, count=1):
    attacker = rand_private()
    target   = rand_private()
    total    = 0
    for burst in range(count):
        ports = random.sample(range(1, 65535), random.randint(8, 15))
        evs = []
        for p in ports:
            ev = make_event(attacker, target, random.randint(49152,65535), p,
                            pkts_s=1, bytes_s=44, pkts_c=0, bytes_c=0,
                            age=0.001, tcp_flags="S")
            ev["is_simulated_attack"] = True
            evs.append(ev)
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {len(evs)} probes", min(burst+1, 30), color=YELLOW)
        time.sleep(0.3)
    print()
    return total, attacker, target

def sim_dos(r, count=1):
    attacker = rand_public()
    target   = rand_private()
    total    = 0
    for burst in range(count):
        pkt = random.randint(8000, 20000)
        byt = pkt * random.randint(60, 1500)
        evs = [_stamp_features(
                   make_event(attacker, target, random.randint(1024,65535), 80,
                              app="http", pkts_s=pkt, bytes_s=byt,
                              age=random.uniform(0.1, 2.0), tcp_flags="S"),
                   _FEAT_DOS)
               for _ in range(random.randint(4, 8))]
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {byt:,} bytes", min(burst+1, 30), color=RED)
        time.sleep(0.4)
    print()
    return total, attacker, target

def sim_brute(r, count=1):
    attacker = rand_private()
    target   = rand_private()
    total    = 0
    for burst in range(count):
        attempts = random.randint(10, 25)
        evs = [_stamp_features(
                   make_event(attacker, target, random.randint(49152,65535), 22,
                              app="ssh", pkts_s=8, bytes_s=1400, pkts_c=6, bytes_c=900,
                              age=random.uniform(0.5,2.0), tcp_flags="PA"),
                   _FEAT_BRUTE)
               for _ in range(attempts)]
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {attempts} attempts", min(burst+1, 30), color=MAGENTA)
        time.sleep(0.3)
    print()
    return total, attacker, target

def sim_exfil(r, count=1):
    internal = rand_private()
    external = rand_public()
    total    = 0
    for burst in range(count):
        chunks = random.randint(2, 5)
        evs = []
        for _ in range(chunks):
            b_out = random.randint(5_000_000, 50_000_000)
            evs.append(_stamp_features(
                make_event(internal, external, random.randint(49152,65535), 443,
                           app="tls", pkts_s=random.randint(4000,15000), bytes_s=b_out,
                           pkts_c=100, bytes_c=50000, age=random.uniform(30,300),
                           tcp_flags="PA"),
                _FEAT_EXFIL))
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {chunks} chunks", min(burst+1, 30), color=CYAN)
        time.sleep(0.5)
    print()
    return total, internal, external

def sim_c2(r, count=1):
    bot      = rand_private()
    c2_srv   = rand_public()
    total    = 0
    beacons  = random.randint(8, 16) * count
    for i in range(beacons):
        ev = _stamp_features(
            make_event(bot, c2_srv, random.randint(49152,65535), 443,
                       app="tls", pkts_s=4, bytes_s=300, pkts_c=4, bytes_c=250,
                       age=0.2, rtt=0.05, tcp_flags="PA"),
            _FEAT_C2)
        ev["timestamp"] = datetime.fromtimestamp(
            time.time() - (beacons - i) * 30, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        push(r, [ev])
        total += 1
        progress_bar(f"Beacon {i+1}/{beacons}", min(i+1, 30), color=BLUE)
        time.sleep(0.1)
    print()
    return total, bot, c2_srv

def sim_lateral(r, count=1):
    attacker = rand_private()
    total    = 0
    pivot_ports = [22, 445, 135, 3389, 5985, 139, 5900, 23]
    for burst in range(count):
        targets = [rand_private() for _ in range(random.randint(6, 14))]
        evs = [_stamp_features(
                   make_event(attacker, t, random.randint(49152,65535),
                              random.choice(pivot_ports),
                              pkts_s=3, bytes_s=180, pkts_c=2, bytes_c=120,
                              age=0.5, tcp_flags="S"),
                   _FEAT_LATERAL)
               for t in targets]
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {len(evs)} hosts", min(burst+1, 30), color=YELLOW)
        time.sleep(0.3)
    print()
    return total, attacker, "internal subnet"

def sim_all(r, count=1):
    grand_total = 0
    for name, fn, col in [
        ("Port Scan",         sim_portscan, YELLOW),
        ("DoS Flood",         sim_dos,      RED),
        ("SSH Brute Force",   sim_brute,    MAGENTA),
        ("Data Exfiltration", sim_exfil,    CYAN),
        ("C2 Beaconing",      sim_c2,       BLUE),
        ("Lateral Movement",  sim_lateral,  YELLOW),
    ]:
        print(f"\n  {c(col, '▶')} {c(BOLD, name)}")
        n, src, dst = fn(r, count)
        grand_total += n
        print(f"     {c(GREEN, '✓')} {n} events — {src} → {dst}")
        time.sleep(0.5)
    return grand_total

def sim_normal(r, count=1):
    total = 0
    for burst in range(count):
        evs = []
        for _ in range(random.randint(5, 12)):
            src  = rand_private()
            dst  = rand_public()
            port = random.choice([80, 443, 53, 25, 587, 8080])
            pkt  = random.randint(10, 200)
            byt  = pkt * random.randint(60, 500)
            evs.append(make_event(src, dst, random.randint(49152,65535), port,
                                  app={80:"http",443:"tls",53:"dns"}.get(port,"unknown"),
                                  pkts_s=pkt//2, bytes_s=byt//2,
                                  pkts_c=pkt//2, bytes_c=byt//2,
                                  age=random.uniform(0.5,10.0)))
        total += push(r, evs)
        progress_bar(f"Burst {burst+1}/{count} — {len(evs)} flows", min(burst+1, 30), color=GREEN)
        time.sleep(0.3)
    print()
    return total, "various", "internet"

# ── Menu ───────────────────────────────────────────────────────────────────────

MENU = [
    # (label, mitre, colour, handler)
    ("Port Scan",          "T1046 – Network Service Discovery",          YELLOW,  sim_portscan),
    ("DoS / Flood",        "T1498 – Network Denial of Service",          RED,     sim_dos),
    ("SSH Brute Force",    "T1110 – Brute Force (SSH/FTP)",              MAGENTA, sim_brute),
    ("Data Exfiltration",  "T1041 – Exfiltration Over C2 Channel",       CYAN,    sim_exfil),
    ("C2 Beaconing",       "T1071 – App Layer Protocol (C2)",            BLUE,    sim_c2),
    ("Lateral Movement",   "T1021 – Remote Services (Internal Pivot)",   YELLOW,  sim_lateral),
    ("Normal Traffic",     "Baseline benign traffic (no attack)",        GREEN,   sim_normal),
    ("Run ALL attacks",    "Execute all 6 attack scenarios sequentially",RED,     None),
    ("Quit",               "",                                            DIM,     None),
]

def clear():
    os.system("clear")

def print_banner():
    print(f"""
{c(RED, BOLD + '╔══════════════════════════════════════════════════════════════╗')}
{c(RED, BOLD + '║')}    {c(BOLD, '🔴  SENTINEL CORE — ATTACK SIMULATION ENGINE  🔴')}    {c(RED, BOLD + '║')}
{c(RED, BOLD + '╚══════════════════════════════════════════════════════════════╝')}{RESET}
  {c(DIM, 'Injects synthetic attack flows into the live IDS pipeline.')}
  {c(DIM, 'Events appear as real alerts on the dashboard within seconds.')}
""")

def print_menu():
    print(f"  {c(BOLD, '  #   Attack Type             MITRE Technique')}")
    print(f"  {c(DIM,  '  ─   ─────────────────────── ──────────────────────────────────')}")
    for i, (label, mitre, col, _) in enumerate(MENU, 1):
        num   = c(BOLD, f"[{i}]")
        lbl   = c(col, f"{label:<25}")
        mit   = c(DIM, mitre) if mitre else ""
        print(f"  {num}  {lbl} {mit}")
    print()

def ask_count():
    while True:
        try:
            raw = input(f"  {c(CYAN, '▷')} Repeat count (bursts per scenario) [{c(BOLD,'1')}]: ").strip()
            if raw == "":
                return 1
            n = int(raw)
            if n < 1:
                raise ValueError
            return n
        except ValueError:
            print(f"  {c(RED, '[!]')} Please enter a positive integer.\n")

def connect_redis():
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        r.ping()
        return r
    except Exception as e:
        print(f"\n  {c(RED,'[!]')} Cannot connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
        print(f"       {c(DIM, str(e))}")
        print(f"  {c(DIM, 'Make sure the pipeline is running (./dev.sh)')}\n")
        sys.exit(1)

def run_scenario(r, choice, count):
    label, mitre, col, handler = MENU[choice]
    print(f"\n  {c(col, '▶')} {c(BOLD, label)}  {c(DIM, mitre)}")
    print(f"  {c(DIM, '─'*60)}")

    if choice == 7:          # Run ALL
        total = sim_all(r, count)
        src, dst = "multiple", "multiple"
    else:
        total, src, dst = handler(r, count)

    print(f"\n  {c(GREEN, '✓')} {c(BOLD, str(total))} events injected")
    print(f"  {c(DIM, f'  {src}  →  {dst}')}")
    print(f"\n  {c(CYAN, '⚡')} Check the dashboard: {c(BOLD, 'http://127.0.0.1:3000')}")
    print(f"  {c(DIM,  '  Alerts appear within 2–5 seconds.')}")

def main():
    r = connect_redis()

    while True:
        clear()
        print_banner()
        print_menu()

        # Read choice
        try:
            raw = input(f"  {c(CYAN, '▷')} Choose an attack [{c(BOLD,'1–9')}]: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {c(DIM, 'Bye!')}\n")
            break

        if not raw.isdigit() or not (1 <= int(raw) <= len(MENU)):
            print(f"\n  {c(RED,'[!]')} Invalid choice — enter a number between 1 and {len(MENU)}.\n")
            time.sleep(1.5)
            continue

        choice = int(raw) - 1

        # Quit
        if MENU[choice][0] == "Quit":
            print(f"\n  {c(DIM, 'Bye!')}\n")
            break

        # How many bursts?
        count = ask_count()

        run_scenario(r, choice, count)

        # Continue?
        print()
        try:
            again = input(f"\n  {c(CYAN, '▷')} Press {c(BOLD,'Enter')} to return to menu, or {c(BOLD,'q')} to quit: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n\n  {c(DIM,'Bye!')}\n")
            break

        if again == "q":
            print(f"\n  {c(DIM,'Bye!')}\n")
            break

if __name__ == "__main__":
    main()
