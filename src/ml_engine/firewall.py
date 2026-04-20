import subprocess
import logging
import threading

logger = logging.getLogger(__name__)

class ActiveFirewall:
    """Manages WSL-based IP blocking via iptables."""
    _blocked_ips = set()
    _lock = threading.Lock()

    @classmethod
    def block(cls, src_ip):
        """Block an IP address if not already blocked."""
        if not src_ip or src_ip in ["127.0.0.1", "::1", "172.25.16.1"]:
            return

        with cls._lock:
            if src_ip in cls._blocked_ips:
                return
            
            try:
                logger.warning(f"[IPS] Block request for high-threat IP: {src_ip}")
                # Use -I (Insert) to push to top of chain
                # Note: Requires 'sudo' privileges managed in start_ids.sh or sudoers
                cmd = ["sudo", "iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, capture_output=True)
                
                cls._blocked_ips.add(src_ip)
                logger.info(f"[IPS] Successfully blocked {src_ip}")
            except Exception as e:
                logger.error(f"[IPS] Failed to block {src_ip}: {e}")

    @classmethod
    def get_blocked_count(cls):
        return len(cls._blocked_ips)
