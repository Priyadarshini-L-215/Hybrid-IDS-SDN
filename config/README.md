# Config

This directory contains configuration files for the Hybrid-IDS-SDN project, including global settings, MITRE ATT&CK mappings, Redis schema definitions, and validation rules.

## Detailed Directory Contents

*   **`sentinel_config.yaml`**: The primary, centralized configuration file for the Sentinel Core. It defines service addresses (Redis, Relay), ML confidence thresholds, feature schemas, file paths, and general environment parameters.
*   **`suricata/`**:
    *   **`signatures.rules`**: Custom IPS/IDS signature rules tailored for the environment. These rules define specific match conditions for detecting known malicious traffic or anomalous behaviors on the network at the packet level.
    *   **`suricata.yaml`**: The core configuration file for the Suricata daemon, defining network interfaces, rule paths, output logs (like `eve.json`), and packet capture settings.
    *   **`suricata.yaml.active`**: The currently active or compiled version of the suricata configuration being used by the running engine.
