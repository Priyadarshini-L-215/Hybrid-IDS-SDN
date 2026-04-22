"""
nmap_runner.py – Wraps nmap execution and Gemini CLI AI analysis.
Nmap must be installed and on PATH (or in common Windows locations).
Gemini CLI must be available as `gemini` on PATH.
"""

import subprocess
import shutil
import os
import re
import textwrap
import time
from typing import Optional

# ------------------------------------------------------------------ #
#  Configuration                                                       #
# ------------------------------------------------------------------ #
NMAP_BIN   = os.environ.get("NMAP_PATH", "nmap")
GEMINI_BIN = os.environ.get("GEMINI_BIN", "gemini")
NMAP_INSTALL_URL = "https://nmap.org/download.html"

# Scan profiles exposed to the UI
# We optimize these to be more likely to trigger IDS alerts for testing
SCAN_PROFILES = {
    "ping":          {"flags": ["-sn", "-Pn", "--unprivileged"],                 "label": "Ping Sweep",         "danger": "low",    "requires_root": False},
    "quick":         {"flags": ["-T4", "-F", "-Pn", "--unprivileged"],           "label": "Quick Scan",         "danger": "low",    "requires_root": False},
    "service":       {"flags": ["-sV", "-T4", "-Pn", "--unprivileged"],          "label": "Service Detection",  "danger": "medium", "requires_root": False},
    "os_detect":     {"flags": ["-O", "-T4", "-Pn"],                             "label": "OS Detection",       "danger": "medium", "requires_root": True},
    "vuln":          {"flags": ["--script=vuln", "-T4", "-Pn", "--unprivileged"], "label": "Vuln Scripts",      "danger": "high",   "requires_root": False},
    "aggressive":    {"flags": ["-A", "-T4", "-Pn", "--unprivileged"],           "label": "Aggressive (-A)",    "danger": "high",   "requires_root": False},
    "stealth_syn":   {"flags": ["-sS", "-T2"],                                   "label": "Stealth SYN",        "danger": "medium", "requires_root": True},
    "udp":           {"flags": ["-sU", "-T3", "--top-ports=50"],                 "label": "UDP Top-50",         "danger": "medium", "requires_root": True},
    "full_ports":    {"flags": ["-p-", "-T4", "--unprivileged"],                 "label": "Full Port Scan",     "danger": "medium", "requires_root": False},
    "custom":        {"flags": ["--unprivileged"],                               "label": "Custom Flags",       "danger": "custom", "requires_root": False},
}

# Hard cap – prevent runaway scans
MAX_RUNTIME_SECONDS = 300   # 5 min

# ------------------------------------------------------------------ #
#  Path Resolution                                                     #
# ------------------------------------------------------------------ #
def get_nmap_path() -> str:
    """Find the nmap executable on Windows/Linux."""
    # 1. Check if configured NMAP_BIN is already valid in PATH
    if shutil.which(NMAP_BIN):
        return NMAP_BIN
    
    # 2. Check common Windows installation paths
    common_windows_paths = [
        "nmap",
        "nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        # Check relative to AppData if installed for current user
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe")
    ]
    
    for path in common_windows_paths:
        if shutil.which(path) or os.path.exists(path):
            return path
            
    return NMAP_BIN # Fallback to default

def get_wsl_ip() -> Optional[str]:
    """
    Retrieves the IP address of the WSL environment.
    This is necessary because Nmap scanning Windows 'localhost' bypasses WSL's virtual network interface,
    preventing Suricata (running in WSL) from detecting the traffic.
    """
    try:
        result = subprocess.run(["wsl", "hostname", "-I"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            # Usually returns a space-separated list of IPs, take the first one
            return result.stdout.split()[0].strip()
    except Exception:
        pass
    return None


def get_nmap_status() -> dict:
    """Return a lightweight availability summary for UI health checks."""
    path = get_nmap_path()
    found = os.path.exists(path) or shutil.which(path) is not None
    version = ""

    if found:
        try:
            result = subprocess.run(
                [path, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-8",
                errors="ignore",
            )
            first_line = next(
                (line.strip() for line in result.stdout.splitlines() if line.strip()),
                "",
            )
            version = first_line or "Nmap detected"
        except Exception:
            version = "Nmap detected"

    return {
        "available": found,
        "path": str(path),
        "version": version,
        "install_url": NMAP_INSTALL_URL,
    }

# ------------------------------------------------------------------ #
#  Core runner                                                         #
# ------------------------------------------------------------------ #
def run_nmap(
    target: str,
    profile: str = "quick",
    extra_flags: Optional[str] = None,
    timeout: int = MAX_RUNTIME_SECONDS,
) -> dict:
    """
    Execute nmap and return a structured result dict.
    """
    # Validate target (basic sanity check – refuse shell metacharacters)
    if not _safe_target(target):
        return _err(target, profile, "Invalid target. Use IP, hostname, or CIDR range.")

    if profile not in SCAN_PROFILES:
        return _err(target, profile, f"Unknown profile '{profile}'.")

    flags = list(SCAN_PROFILES[profile]["flags"])

    # Append extra custom flags (split safely, strip dangerous chars)
    if extra_flags:
        safe_extras = _sanitise_flags(extra_flags)
        flags.extend(safe_extras)

    # When running Nmap on Windows against localhost, traffic doesn't traverse the WSL virtual switch,
    # so Suricata (inside WSL) won't see it. We dynamically map localhost to the WSL IP to force traffic over the bridge.
    if target in ["127.0.0.1", "localhost"]:
        wsl_ip = get_wsl_ip()
        if wsl_ip:
            target = wsl_ip

    # Use the resolved path
    nmap_path = get_nmap_path()
    cmd = [nmap_path] + flags + [target]

    start_time = time.time()
    try:
        # We use subprocess.run with manual text decoding to ensure raw output
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding='utf-8',
            errors='ignore'
        )
        duration = round(time.time() - start_time, 2)
        
        # Combine stdout and stderr properly
        output = result.stdout
        if result.stderr:
            output += "\n--- STDERR ---\n" + result.stderr
            
        return {
            "success": result.returncode == 0,
            "target": target,
            "profile": profile,
            "flags_used": cmd[1:],
            "raw_output": output.strip(),
            "error": result.stderr.strip() if result.returncode != 0 else None,
            "duration_sec": duration,
        }
    except FileNotFoundError:
        return _err(target, profile, f"nmap binary not found at '{nmap_path}'. Please install Nmap.")
    except subprocess.TimeoutExpired:
        return _err(target, profile, f"Scan timed out after {timeout}s.")
    except Exception as exc:
        return _err(target, profile, f"Execution failed: {exc}")


# ------------------------------------------------------------------ #
#  Gemini CLI AI analysis                                              #
# ------------------------------------------------------------------ #
def analyse_with_gemini(nmap_output: str, target: str) -> str:
    """
    Pipe nmap output to `gemini` CLI with a structured security prompt.
    """
    prompt = textwrap.dedent(f"""
        You are a cybersecurity expert analysing an Nmap scan result.
        Target: {target}

        Analyse the following Nmap scan output and provide:
        1. **Open Ports & Services Summary** – table of port | service | risk level
        2. **Key Findings** – notable open ports, unexpected services, version risks
        3. **Threat Indicators** – any patterns suggesting vulnerability or misconfiguration
        4. **Recommended Mitigations** – concise, prioritised action items
        5. **Overall Risk Score** – Low / Medium / High / Critical with a one-sentence rationale

        Keep the response concise and structured. Use markdown.

        --- NMAP OUTPUT ---
        {nmap_output}
        --- END ---
    """).strip()

    try:
        result = subprocess.run(
            [GEMINI_BIN, "-p", prompt],
            capture_output=True,
            text=True,
            timeout=60,
        )
        ai_text = result.stdout.strip()
        if not ai_text and result.stderr:
            ai_text = f"[Gemini CLI error]: {result.stderr.strip()}"
        return ai_text or "[No response from Gemini CLI]"
    except FileNotFoundError:
        return "[Gemini CLI not found. AI Analysis unavailable.]"
    except subprocess.TimeoutExpired:
        return "[Gemini CLI timed out after 60s]"
    except Exception as exc:
        return f"[Gemini CLI exception: {exc}]"


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #
_SAFE_TARGET_RE = re.compile(r'^[a-zA-Z0-9._/:\-]+$')

def _safe_target(t: str) -> bool:
    t = t.strip()
    return bool(t) and bool(_SAFE_TARGET_RE.match(t)) and len(t) < 256

_DANGEROUS_CHARS = re.compile(r'[;&|$`\(\)\{\}!<> \t\n]')

def _sanitise_flags(raw: str) -> list:
    parts = raw.split()
    clean = []
    for p in parts:
        if not _DANGEROUS_CHARS.search(p):
            clean.append(p)
    return clean

def _err(target, profile, msg) -> dict:
    return {
        "success": False,
        "target": target,
        "profile": profile,
        "flags_used": [],
        "raw_output": "",
        "error": msg,
        "duration_sec": 0,
    }
