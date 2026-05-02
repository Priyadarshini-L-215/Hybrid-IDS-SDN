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
    Extracts and downloads a PCAP snippet for a specific event.
    Note: Requires forensics.pcap_enabled to be true in config.
    """
    if not PCAP_ENABLED:
        raise HTTPException(status_code=403, detail="PCAP capture is currently disabled in configuration.")

    # In a real implementation, we would use the event_id to find the flow
    # and extract it from the master PCAP using tcpdump or tshark.
    # For now, we look for a file matching the event_id or the latest capture.
    
    # 1. Ensure directory exists
    if not PCAP_DIR.exists():
        os.makedirs(PCAP_DIR, exist_ok=True)
        raise HTTPException(status_code=404, detail="No PCAP captures found.")

    # 2. Search for the PCAP (Simulation: look for any pcap in the dir)
    pcaps = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
    if not pcaps:
        raise HTTPException(status_code=404, detail="PCAP file not yet generated for this event.")

    # Return the first one found for demonstration
    target_path = PCAP_DIR / pcaps[0]
    
    return FileResponse(
        path=target_path,
        filename=f"forensic_event_{event_id}.pcap",
        media_type="application/vnd.tcpdump.pcap"
    )

@router.get("/status")
async def get_pcap_status():
    return {
        "enabled": PCAP_ENABLED,
        "storage_used_mb": sum(f.stat().st_size for f in PCAP_DIR.glob('**/*') if f.is_file()) / (1024*1024) if PCAP_DIR.exists() else 0
    }
