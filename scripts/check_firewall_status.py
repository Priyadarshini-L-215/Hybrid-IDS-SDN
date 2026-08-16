import asyncio
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ml_engine.firewall import ActiveFirewall

async def main():
    await ActiveFirewall._initialize()
    status = await ActiveFirewall.get_detailed_status()
    print("Firewall backend:", status.get("backend"))
    print("Banning disabled:", await ActiveFirewall.is_banning_disabled())
    print("Permanent IPs:", status.get("permanent_ips"))
    print("Temporary IPs:", status.get("temporary_ips"))
    print("Reputation entries:", status.get("reputation"))

if __name__ == "__main__":
    asyncio.run(main())
