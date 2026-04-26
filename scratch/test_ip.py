import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from common.wsl_utils import get_wsl_ip, get_gateway_ip

print(f"WSL IP: {get_wsl_ip()}")
print(f"Gateway IP: {get_gateway_ip()}")
