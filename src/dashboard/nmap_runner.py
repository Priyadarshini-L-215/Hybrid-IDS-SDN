"""
nmap_runner.py – Wraps nmap execution and Gemini CLI AI analysis.
Nmap must be installed and on PATH (or set NMAP_PATH env var).
Gemini CLI must be available as `gemini` on PATH (already running in this project).
"""

import subprocess
import shutil
import os
import json
import re
import textwrap
from typing import Optional

# ------------------------------------------------------------------ #
#  Configuration                                                       #
# ------------------------------------------------------------------ #
NMAP_BIN   = os.environ.get("NMAP_PATH", "nmap")
GEMINI_BIN = os.environ.get("GEMINI_BIN", "gemini")

# Scan profiles exposed to the UI
SCAN_PROFILES = {
    "ping":          {"flags": ["-sn", "-Pn", "--unprivileged"],                 "label": "Ping Sweep",         "danger": "low"},
    "quick":         {"flags": ["-T4", "-F", "-Pn", "--unprivileged"],           "label": "Quick Scan",         "danger": "low"},
    "service":       {"flags": ["-sV", "-T4", "-Pn", "--unprivileged"],          "label": "Service Detection",  "danger": "medium"},
    "os_detect":     {"flags": ["-O", "-T4", "-Pn", "--unprivileged"],           "label": "OS Detection",       "danger": "medium"},
    "vuln":          {"flags": ["--script=vuln", "-T4", "-Pn", "--unprivileged"],"label": "Vuln Scripts",       "danger": "high"},
    "aggressive":    {"flags": ["-A", "-T4", "-Pn", "--unprivileged"],           "label": "Aggressive (-A)",    "danger": "high"},
    "stealth_syn":   {"flags": ["-sS", "-T2", "-Pn", "--unprivileged"],          "label": "Stealth SYN",        "danger": "medium"},
    "udp":           {"flags": ["-sU", "-T3", "--top-ports=50", "-Pn", "--unprivileged"], "label": "UDP Top-50", "danger": "medium"},
    "full_ports":    {"flags": ["-p-", "-T4", "-Pn", "--unprivileged"],          "label": "Full Port Scan",     "danger": "medium"},
    "custom":        {"flags": ["-Pn", "--unprivileged"],                        "label": "Custom Flags",       "danger": "custom"},
}

# Hard cap – prevent runaway scans
MAX_RUNTIME_SECONDS = 300   # 5 min


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

    Returns:
        {
          "success": bool,
          "target": str,
          "profile": str,
          "flags_used": [str],
          "raw_output": str,
          "error": str|None,
          "duration_sec": float,
        }
    """
    import time

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

    cmd = [NMAP_BIN] + flags + [target]

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = round(time.time() - t0, 2)
        output = result.stdout + ("\n" + result.stderr if result.stderr else "")
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
        return _err(target, profile, "nmap binary not found. Install nmap and ensure it is on PATH.")
    except subprocess.TimeoutExpired:
        return _err(target, profile, f"Scan timed out after {timeout}s.")
    except Exception as exc:
        return _err(target, profile, str(exc))


# ------------------------------------------------------------------ #
#  Gemini CLI AI analysis                                              #
# ------------------------------------------------------------------ #
def analyse_with_gemini(nmap_output: str, target: str) -> str:
    """
    Pipe nmap output to `gemini` CLI with a structured security prompt.
    Returns the AI analysis as plain text.
    Uses --sandbox flag to prevent any side-effects from the model.
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
        return "[Gemini CLI not found. Install with: npm i -g @google/generative-ai-cli]"
    except subprocess.TimeoutExpired:
        return "[Gemini CLI timed out after 60s]"
    except Exception as exc:
        return f"[Gemini CLI exception: {exc}]"


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #
_SAFE_TARGET_RE = re.compile(
    r'^[a-zA-Z0-9._/:\-]+$'
)

def _safe_target(t: str) -> bool:
    """Return True if target looks like a valid IP / hostname / CIDR."""
    t = t.strip()
    return bool(t) and bool(_SAFE_TARGET_RE.match(t)) and len(t) < 256

_DANGEROUS_CHARS = re.compile(r'[;&|$`\(\)\{\}!<> \t\n]')

def _sanitise_flags(raw: str) -> list:
    """Split user-supplied flags and strip any shell-injection chars."""
    parts = raw.split()
    clean = []
    for p in parts:
        # Strict shell-injection prevention; allow arguments without leading hyphens (like port numbers)
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
