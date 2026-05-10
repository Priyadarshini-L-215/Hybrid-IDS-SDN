import os
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from common.config import BASE_DIR, PCAP_ENABLED
import structlog

logger = structlog.get_logger("relay.routes.pcap")

router = APIRouter(prefix="/api/pcap", tags=["Forensics"])

PCAP_DIR = BASE_DIR / "data" / "pcaps"

@router.get("/download/{event_id}")
async def download_pcap(event_id: str):
    """
    Extracts and downloads a PCAP snippet for a specific event using tcpdump.
    """
    if not PCAP_ENABLED:
        raise HTTPException(status_code=403, detail="PCAP capture is currently disabled in configuration.")

    from common.database import db
    import subprocess

    # 1. Get alert metadata for extraction
    try:
        conn = db._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT src_ip FROM alerts WHERE id = ?", (event_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found in database.")
        
        ip = row['src_ip']
    except Exception as e:
        logger.error("Database query failed for PCAP extraction", error=str(e))
        raise HTTPException(status_code=500, detail="Internal database error.")

    import ipaddress
    try:
        # Validate that the extracted IP is a legitimate IP address to prevent injection or invalid queries
        ipaddress.ip_address(ip)
    except ValueError:
        logger.error("Invalid IP address retrieved from database", ip=ip)
        raise HTTPException(status_code=400, detail="Invalid IP address format.")

    # 2. Path to master capture (assuming Suricata or system capture)
    # Search for any .pcap in the PCAP_DIR that could be the source
    pcaps = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap") and not f.startswith("snippet_")]
    if not pcaps:
        raise HTTPException(status_code=404, detail="No master PCAP capture found to extract from.")

    master_pcap = PCAP_DIR / pcaps[0] # Use the first available capture
    snippet_path = PCAP_DIR / f"snippet_{event_id}.pcap"

    # 3. Extract using tcpdump
    try:
        # Run tcpdump to filter by the source IP
        # We use -r to read and -w to write the snippet
        # sudo might be required depending on file permissions
        cmd = ["tcpdump", "-r", str(master_pcap), f"host {ip}", "-w", str(snippet_path)]
        
        # Check if we need sudo (if first attempt fails with permission error)
        try:
            subprocess.run(cmd, check=True, timeout=10, capture_output=True)
        except subprocess.CalledProcessError:
            subprocess.run(["sudo"] + cmd, check=True, timeout=10)

        if not snippet_path.exists() or snippet_path.stat().st_size == 0:
             raise HTTPException(status_code=404, detail="No packets found for this IP in the capture.")

        return FileResponse(
            path=snippet_path,
            filename=f"forensic_event_{event_id}.pcap",
            media_type="application/vnd.tcpdump.pcap"
        )
    except Exception as e:
        logger.error("tcpdump extraction failed", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to extract PCAP snippet.")

@router.get("/status")
async def get_pcap_status():
    return {
        "enabled": PCAP_ENABLED,
        "storage_used_mb": sum(f.stat().st_size for f in PCAP_DIR.glob('**/*') if f.is_file()) / (1024*1024) if PCAP_DIR.exists() else 0
    }
