import asyncio
import ipaddress
import time
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Depends
import structlog

from relay.middleware.auth import require_api_key

logger = structlog.get_logger("relay.routes.lab")

router = APIRouter(prefix="/api", tags=["Lab"])


def _validate_ip(target: str) -> str:
    """Raises HTTP 422 if target is not a valid IP address."""
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid target: '{target}' is not a valid IP address."
        )

@router.post("/nmap/scan", dependencies=[Depends(require_api_key)])
async def run_nmap_scan(request: Dict[str, Any]):
    target = _validate_ip(request.get("target", ""))
    profile = request.get("profile", "quick")

    allowed_profiles = {"ping", "quick", "service", "os_detect", "aggressive", "vuln"}
    if profile not in allowed_profiles:
        raise HTTPException(status_code=400, detail=f"Unknown profile '{profile}'.")
    
    # Map profiles to nmap flags
    flags = {
        "ping": "-sn",
        "quick": "-F",
        "service": "-sV",
        "os_detect": "-O",
        "aggressive": "-A",
        "vuln": "--script=vuln"
    }.get(profile, "-F")
    
    logger.info("Starting Nmap scan", target=target, profile=profile)
    start_time = time.time()
    
    try:
        # 1. Verify nmap exists
        import shutil
        if not shutil.which("nmap"):
            return {"success": False, "error": "Nmap is not installed on the system path."}

        # 2. Build command
        # Use -T4 for speed, but avoid -O without root
        cmd = ["nmap", flags, "-T4"]
        
        if profile in ["os_detect", "aggressive", "vuln"]:
            # These often need root
            cmd = ["sudo"] + cmd
        else:
            # Add unprivileged flag for non-root quick scans to avoid some errors
            cmd.append("--unprivileged")
        
        cmd.append(target)
            
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        duration = round(time.time() - start_time, 2)
        
        if process.returncode == 0:
            return {
                "success": True,
                "target": target,
                "duration_sec": duration,
                "raw_output": stdout.decode()
            }
        else:
            err_msg = stderr.decode() or stdout.decode() or "Unknown nmap error"
            logger.error("Nmap scan failed", target=target, code=process.returncode, error=err_msg)
            return {
                "success": False,
                "target": target,
                "error": err_msg
            }
    except Exception as e:
        logger.error("Nmap scan failed", error=str(e))
        return {"success": False, "error": str(e)}

@router.post("/attack/ddos", dependencies=[Depends(require_api_key)])
async def run_ddos_simulation(request: Dict[str, Any]):
    target = _validate_ip(request.get("target", ""))
    logger.info("Simulating DDoS attack", target=target)
    
    def _send_packets():
        import socket
        import random
        import time
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes_payload = random._urandom(1024)
        # Send in bursts to trigger threshold rules
        for _ in range(5):
            for _ in range(500):
                port = random.randint(1, 65535)
                try:
                    sock.sendto(bytes_payload, (target, port))
                except Exception as e:
                    logger.debug("Failed to send UDP packet in simulation", error=str(e))
            time.sleep(0.1)
        sock.close()

    try:
        await asyncio.to_thread(_send_packets)
        return {"success": True, "message": f"DDoS simulation flood (2500 pkts) sent to {target}"}
    except Exception as e:
        logger.error("DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}

@router.post("/attack/payload", dependencies=[Depends(require_api_key)])
async def run_payload_simulation(request: Dict[str, Any]):
    target = _validate_ip(request.get("target", "127.0.0.1"))
    # SSRF guard — only allow loopback/private targets for payload injection
    addr = ipaddress.ip_address(target)
    if not addr.is_loopback and not addr.is_private:
        raise HTTPException(
            status_code=422,
            detail="Payload simulation only permitted against loopback or private network addresses."
        )
    logger.info("Simulating Payload Injection", target=target)
    
    try:
        import requests
        # Send multiple patterns to trigger SQLi regex
        payloads = [
            "' OR '1'='1' --",
            "admin' --",
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>"
        ]
        
        def _send_payloads():
            from common.config import API_PORT
            for p in payloads:
                try:
                    # We send it to port 5000 (ourselves)
                    requests.get(f"http://{target}:{API_PORT}/api/health?id={p}", timeout=1.0)
                except Exception as e:
                    logger.debug("Failed to send HTTP payload in simulation", error=str(e))
        
        await asyncio.to_thread(_send_payloads)
                
        return {"success": True, "message": f"Malicious payloads ({len(payloads)}) injected towards {target}"}
    except Exception as e:
        logger.error("Payload simulation failed", error=str(e))
        return {"success": False, "error": str(e)}
