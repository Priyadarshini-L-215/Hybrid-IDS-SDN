import subprocess
import logging
import threading
import ipaddress
import socket

logger = logging.getLogger(__name__)

class ActiveFirewall:
    """Manages WSL-based IP blocking via iptables."""
    _blocked_ips = set()
    _lock = threading.Lock()
    _protected_ips = {"127.0.0.1", "::1", "172.25.16.1", "0.0.0.0"}
    _protected_ips_loaded = False

    @classmethod
    def _load_local_ips(cls):
        if cls._protected_ips_loaded:
            return
        cls._protected_ips_loaded = True

        try:
            hostname_ips = subprocess.check_output(["hostname", "-I"], text=True).strip().split()
            cls._protected_ips.update(ip for ip in hostname_ips if ip)
        except (OSError, subprocess.SubprocessError, ValueError):
            pass

        try:
            # Add primary hostname-resolved addresses as extra safety.
            _, _, resolved_ips = socket.gethostbyname_ex(socket.gethostname())
            cls._protected_ips.update(ip for ip in resolved_ips if ip)
        except OSError:
            pass

    @classmethod
    def _should_skip_block(cls, src_ip):
        if not src_ip:
            return True

        cls._load_local_ips()

        try:
            parsed = ipaddress.ip_address(src_ip)
        except ValueError:
            logger.warning(f"[IPS] Skip block for invalid IP: {src_ip}")
            return True

        if src_ip in cls._protected_ips:
            return True

        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return True

        # Never block private/local infrastructure ranges from the sensor itself.
        # This avoids self-inflicted outages when bridge/host traffic is classified as attack.
        if parsed.is_private or parsed.is_link_local or parsed.is_reserved:
            return True

        return False

    @classmethod
    def block(cls, src_ip):
        """Block an IP address if not already blocked."""
        if cls._should_skip_block(src_ip):
            logger.info(f"[IPS] Skipping block for protected/local IP: {src_ip}")
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
