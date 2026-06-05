# ebpf_mitigation.py - eBPF/XDP mitigation backend for Sentinel
import socket
import struct
import structlog

logger = structlog.get_logger(__name__)

# Dynamic import to support hosts without BCC or testing environments
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    BPF = None

# C code program for XDP packet filter
XDP_CODE = """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

// BPF map to store blocked IPv4 addresses
BPF_HASH(blocked_ips, uint32_t, uint8_t);

int xdp_drop_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Filter for IPv4 traffic only
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    uint32_t src_ip = ip->saddr;
    uint8_t *blocked = blocked_ips.lookup(&src_ip);
    if (blocked) {
        return XDP_DROP; // Drop the packet at network driver level
    }

    return XDP_PASS;
}
"""

class EBPFMitigationManager:
    """Manages the compilation, loading, and map administration of the Sentinel XDP filter."""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, interface: str = "eth0"):
        if self._initialized:
            return
        self.interface = interface
        self.bpf = None
        self.blocked_ips_map = None
        self._initialized = True

    def load_xdp(self) -> bool:
        """Compiles the inline C code and attaches the XDP program to the configured interface."""
        if not BCC_AVAILABLE:
            logger.warning("BCC library is not installed or loaded. eBPF/XDP is unavailable.")
            return False
        
        if self.bpf is not None:
            return True

        try:
            logger.info("Compiling and loading inline XDP program", interface=self.interface)
            # Compile and load BPF
            self.bpf = BPF(text=XDP_CODE)
            fn = self.bpf.load_func("xdp_drop_prog", BPF.XDP)
            
            # Attach to interface (0 means default mode: driver/generic fallback)
            self.bpf.attach_xdp(self.interface, fn, 0)
            self.blocked_ips_map = self.bpf.get_table("blocked_ips")
            logger.info("eBPF/XDP program attached successfully", interface=self.interface)
            return True
        except Exception as e:
            logger.error("Failed to load eBPF/XDP program on interface", interface=self.interface, error=str(e))
            self.bpf = None
            self.blocked_ips_map = None
            return False

    def unload_xdp(self):
        """Detaches the XDP filter from the interface and cleans up the compiler resources."""
        if self.bpf is not None:
            try:
                logger.info("Unloading and detaching XDP program", interface=self.interface)
                self.bpf.remove_xdp(self.interface, 0)
            except Exception as e:
                logger.error("Error while removing XDP program", interface=self.interface, error=str(e))
            finally:
                self.bpf = None
                self.blocked_ips_map = None

    def block_ip(self, ip: str) -> bool:
        """Adds an IPv4 address to the dynamic BPF map."""
        if self.blocked_ips_map is None:
            if not self.load_xdp():
                return False

        try:
            # Parse IP to its raw memory representation (network byte order format)
            ip_bytes = socket.inet_aton(ip)
            ip_val = struct.unpack("I", ip_bytes)[0]
            
            import ctypes
            key = ctypes.c_uint32(ip_val)
            value = ctypes.c_uint8(1)
            
            self.blocked_ips_map[key] = value
            logger.info("eBPF/XDP: Successfully added block rule", ip=ip)
            return True
        except Exception as e:
            logger.error("eBPF/XDP: Failed to add block rule", ip=ip, error=str(e))
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Removes an IPv4 address from the dynamic BPF map."""
        if self.blocked_ips_map is None:
            return False

        try:
            ip_bytes = socket.inet_aton(ip)
            ip_val = struct.unpack("I", ip_bytes)[0]
            
            import ctypes
            key = ctypes.c_uint32(ip_val)
            
            if key in self.blocked_ips_map:
                del self.blocked_ips_map[key]
                logger.info("eBPF/XDP: Successfully deleted block rule", ip=ip)
                return True
            else:
                logger.warning("eBPF/XDP: IP block rule not found in BPF map", ip=ip)
                return False
        except Exception as e:
            logger.error("eBPF/XDP: Failed to delete block rule", ip=ip, error=str(e))
            return False

    def is_blocked(self, ip: str) -> bool:
        """Checks if an IPv4 address exists in the active BPF map."""
        if self.blocked_ips_map is None:
            return False

        try:
            ip_bytes = socket.inet_aton(ip)
            ip_val = struct.unpack("I", ip_bytes)[0]
            
            import ctypes
            key = ctypes.c_uint32(ip_val)
            return key in self.blocked_ips_map
        except Exception:
            return False
