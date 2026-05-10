"""
MITRE ATT&CK Mapper: Maps Sentinel detections to MITRE Tactics and Techniques.
Used to enhance forensic reports and dashboard visibility.
"""

MITRE_MAPPING = {
    # ML Prediction Mappings
    "predictions": {
        "DDoS": {
            "tactic": "Impact",
            "technique": "Network Denial of Service",
            "id": "T1498",
            "description": "Attacker attempts to exhaust network resources to deny service to users."
        },
        "DoS": {
            "tactic": "Impact",
            "technique": "Endpoint Denial of Service",
            "id": "T1499",
            "description": "Attacker attempts to exhaust endpoint resources (CPU/RAM)."
        },
        "PortScan": {
            "tactic": "Discovery",
            "technique": "Network Service Scanning",
            "id": "T1046",
            "description": "Attacker attempts to map active services on the network."
        },
        "BruteForce": {
            "tactic": "Credential Access",
            "technique": "Brute Force",
            "id": "T1110",
            "description": "Attacker attempts to gain access via repetitive login attempts."
        },
        "Botnet": {
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol",
            "id": "T1071",
            "description": "Infected host communicating with a C2 server."
        },
        "Infiltration": {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application",
            "id": "T1190",
            "description": "Attacker exploited a vulnerability to gain entry."
        },
        "Web Attack": {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application",
            "id": "T1190",
            "description": "Common web-based attack pattern detected."
        }
    },
    
    # Suricata Signature Keyword Mappings
    "signatures": {
        "ET SCAN": {
            "tactic": "Discovery",
            "technique": "Network Service Scanning",
            "id": "T1046"
        },
        "ET EXPLOIT": {
            "tactic": "Initial Access",
            "technique": "Exploit Public-Facing Application",
            "id": "T1190"
        },
        "ET ATTACK_RESPONSE": {
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter",
            "id": "T1059"
        },
        "ET POLICY": {
            "tactic": "Discovery",
            "technique": "Network Sniffing",
            "id": "T1040"
        },
        "ET SHELLCODE": {
            "tactic": "Execution",
            "technique": "User Execution",
            "id": "T1204"
        },
        "ET TROJAN": {
            "tactic": "Command and Control",
            "technique": "Application Layer Protocol",
            "id": "T1071"
        }
    }
}

def get_mitre_info(prediction: str, signature: str = None) -> dict:
    """
    Returns MITRE ATT&CK information based on the prediction or signature.
    """
    # 1. Check Prediction first (as it's often more specific in Sentinel)
    pred_info = MITRE_MAPPING["predictions"].get(prediction)
    if pred_info:
        return pred_info
        
    # 2. Check Signature keywords
    if signature:
        sig_upper = signature.upper()
        for key, info in MITRE_MAPPING["signatures"].items():
            if key in sig_upper:
                return info
                
    # 3. Default fallback
    return {
        "tactic": "Discovery",
        "technique": "Network Traffic Analysis",
        "id": "T1040",
        "description": "General network activity monitored for forensics."
    }
