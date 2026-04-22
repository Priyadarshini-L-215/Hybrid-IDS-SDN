#!/usr/bin/env python3
"""
Sentinel Core - End-to-End Pipeline Latency Test (ASCII)
"""

import asyncio
import json
import subprocess
import sys
import time

try:
    import websockets
except ImportError:
    print("[ERROR] websockets library not found. Run: pip install websockets")
    sys.exit(1)


RELAY_WS_URL = "ws://127.0.0.1:5000/ws/alerts"
TRACER_SIG = "SENTINEL_LATENCY_PROBE"
TIMEOUT_SECONDS = 15


def inject_tracer():
    """Inject a tracer event via WSL."""
    print("[1/3] Injecting tracer event into eve.json...")
    result = subprocess.run(
        ["wsl", "python3", "scratch/inject_tracer.py"],
        capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        print(f"[ERROR] Injection failed:\n{result.stderr}")
        sys.exit(1)
    
    # Parse tracer ID from output
    for line in result.stdout.strip().split("\n"):
        print(f"  {line}")
    
    return time.time()


async def listen_for_tracer():
    """Connect to relay WS and wait for the tracer event."""
    print(f"[2/3] Listening on {RELAY_WS_URL} for tracer...")
    
    try:
        async with websockets.connect(RELAY_WS_URL, open_timeout=10) as ws:
            start = time.time()
            while time.time() - start < TIMEOUT_SECONDS:
                try:
                    message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                    data = json.loads(message)
                    if data.get("_tracer") and data.get("alert_sig") == TRACER_SIG:
                        data["_browser_recv_ts"] = time.time()
                        return data
                except asyncio.TimeoutError:
                    elapsed = time.time() - start
                    print(f"  Waiting... ({elapsed:.0f}s / {TIMEOUT_SECONDS}s)")
                    continue
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[ERROR] Could not connect to relay: {e}")
        sys.exit(1)
    
    print(f"[ERROR] Tracer not received within {TIMEOUT_SECONDS}s timeout")
    return None


def print_report(data):
    """Print the formatted latency breakdown."""
    T0 = data.get("_tracer_inject_ts")
    T1 = data.get("_watcher_read_ts")
    T2 = data.get("_redis_push_ts")
    T3a = data.get("_worker_pop_ts")
    T3b = data.get("_worker_done_ts")
    T4 = data.get("_ws_send_ts")
    T5a = data.get("_relay_recv_ts")
    T5b = data.get("_relay_fwd_ts")
    T6 = data.get("_browser_recv_ts")
    
    def ms(a, b):
        if a and b:
            return f"{(b - a) * 1000:.1f}"
        return "-"
    
    def cum(t):
        if t and T0:
            return f"{(t - T0) * 1000:.1f}"
        return "-"
    
    total = f"{(T6 - T0) * 1000:.1f}" if T6 and T0 else "-"
    tracer_id = data.get("_tracer_id", "unknown")
    
    print()
    print("+--------------------------------------------------------------+")
    print("|       SENTINEL CORE - PIPELINE LATENCY REPORT              |")
    print(f"|       Tracer ID: {tracer_id:<42} |")
    print("+--------------------------------------------------------------+")
    print("|  Hop                        | Delta (ms)| Cumulative (ms)  |")
    print("|-----------------------------+-----------+------------------|")
    print(f"|  T0->T1: File Read           | {ms(T0,T1):>8}  | {cum(T1):>15}  |")
    print(f"|  T1->T2: Redis Push          | {ms(T1,T2):>8}  | {cum(T2):>15}  |")
    print(f"|  T2->T3a: Worker Pop         | {ms(T2,T3a):>8}  | {cum(T3a):>15}  |")
    print(f"|  T3a->T3b: ML Inference      | {ms(T3a,T3b):>8}  | {cum(T3b):>15}  |")
    print(f"|  T3b->T4: WS Queue+Send      | {ms(T3b,T4):>8}  | {cum(T4):>15}  |")
    print(f"|  T4->T5a: WSL->Win Bridge     | {ms(T4,T5a):>8}  | {cum(T5a):>15}  |")
    print(f"|  T5a->T5b: Relay Forward     | {ms(T5a,T5b):>8}  | {cum(T5b):>15}  |")
    print(f"|  T5b->T6: Script Receive     | {ms(T5b,T6):>8}  | {cum(T6):>15}  |")
    print("+--------------------------------------------------------------+")
    print(f"|  TOTAL END-TO-END           |           | {total:>13} ms |")
    print("+--------------------------------------------------------------+")
    print()
    
    # Summary
    if T6 and T0:
        total_ms = (T6 - T0) * 1000
        if total_ms < 100: verdict = "EXCELLENT (<100ms)"
        elif total_ms < 300: verdict = "GOOD (<300ms)"
        else: verdict = "SLOW (>1s)"
        print(f"  Verdict: {verdict}")
    
    # Identify bottleneck
    hops = [
        ("File Read (T0->T1)", T0, T1),
        ("Redis Push (T1->T2)", T1, T2),
        ("Worker Pop (T2->T3a)", T2, T3a),
        ("ML Inference (T3a->T3b)", T3a, T3b),
        ("WS Queue+Send (T3b->T4)", T3b, T4),
        ("WSL->Win Bridge (T4->T5a)", T4, T5a),
        ("Relay Forward (T5a->T5b)", T5a, T5b),
        ("Script Receive (T5b->T6)", T5b, T6),
    ]
    valid_hops = [(name, (b - a) * 1000) for name, a, b in hops if a and b]
    if valid_hops:
        bottleneck = max(valid_hops, key=lambda x: x[1])
        print(f"  Bottleneck: {bottleneck[0]} ({bottleneck[1]:.1f}ms)")


async def main():
    print("=" * 62)
    print("  SENTINEL CORE - End-to-End Pipeline Latency Test")
    print("=" * 62)
    print()
    
    inject_tracer()
    print()
    
    tracer_data = await listen_for_tracer()
    
    if tracer_data:
        print("[3/3] Tracer received! Computing latency breakdown...")
        print_report(tracer_data)
    else:
        print("[3/3] FAILED - tracer was not received.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
