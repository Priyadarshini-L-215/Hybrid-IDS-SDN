"""
Maps alert signatures and event types to MITRE ATT&CK techniques.
Partial map — extend as needed.
"""

MITRE_MAP = {
    # Nmap/Scanning
    "Nmap Scan Detected":             ("T1046", "Network Service Discovery"),
    "Potential Dashboard API Probe":  ("T1046", "Network Service Discovery"),
    "Port Scan":                      ("T1046", "Network Service Discovery"),
    
    # Brute Force
    "Potential SSH Brute Force":      ("T1110", "Brute Force"),
    "SSH Brute Force":                ("T1110", "Brute Force"),
    
    # DDoS
    "UDP Flood/DDoS Simulation":      ("T1498", "Network Denial of Service"),
    "DDoS":                           ("T1498", "Network Denial of Service"),
    "ICMP Ping":                      ("T1498", "Network Denial of Service"),
    
    # Injection
    "SQL Injection Attempt":          ("T1190", "Exploit Public-Facing Application"),
    "Malformed HTTP Header":          ("T1190", "Exploit Public-Facing Application"),
    "Remote Code Execution":          ("T1190", "Exploit Public-Facing Application"),
    
    # Web Attack
    "XSS":                            ("T1190", "Exploit Public-Facing Application"),
    "Web Attack":                     ("T1190", "Exploit Public-Facing Application"),
    
    # Exfil / C2
    "DNS Query":                      ("T1071.004", "Application Layer Protocol: DNS"),
    "Data Exfiltration":              ("T1041", "Exfiltration Over C2 Channel"),
    
    # Default
    "default":                        ("T1059", "Command and Scripting Interpreter"),
}

def get_mitre(signature: str) -> dict:
    """Returns the best-matching MITRE technique for a signature string."""
    sig_lower = (signature or "").lower()
    for key, (tid, tname) in MITRE_MAP.items():
        if key.lower() in sig_lower:
            return {"id": tid, "name": tname}
    return {"id": MITRE_MAP["default"][0], "name": MITRE_MAP["default"][1]}
