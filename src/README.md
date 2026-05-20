# Source Code (src)

This directory contains the core source code for the Hybrid-IDS-SDN backend, divided into distinct components.

## Detailed Directory Contents

*   **`common/`** (Shared utilities and schemas):
    *   `config.py`, `config_schema.py`, `config_validator.py`: Handles loading, validating, and exposing the system configuration from `sentinel_config.yaml`.
    *   `database.py` & `db_writer.py`: Handles SQLite connections and asynchronous writes of security alerts to the disk.
    *   `feature_extractor.py`: The single source of truth for converting Suricata JSON events into the exact numerical arrays expected by the ML models.
    *   `fp_store.py`: A False Positive store that manages whitelisting or ignoring specific noisy alerts.
    *   `mitre_map.py` & `mitre_mapper.py`: Maps specific attack signatures or ML classifications to standard MITRE ATT&CK tactics and techniques.
    *   `alert_builder.py`: A factory that constructs structured JSON alert objects from raw ML engine outputs.
    *   `xai_translator.py`: Explainable AI utility that translates numerical feature impacts (like SHAP values) into human-readable SOC summaries.
*   **`ml_engine/`** (Machine learning pipeline and detection logic):
    *   `consumer.py`: The main loop that pulls events off the Redis queue (ingested from Suricata) and passes them to the ML pipeline.
    *   `decision_engine.py`: The core brain that takes inputs from rule-based alerts (Suricata) and ML predictions, correlates them, and makes a final block/allow decision.
    *   `deep_models.py` & `vae_detector.py`: Handlers for the deep learning components, primarily the Variational Autoencoder.
    *   `adversarial_guard.py`: A component designed to detect and block adversarial machine learning attacks (e.g., evasion packets) before they reach the main classifier.
    *   `anomaly_scorer.py` & `drift_detector.py`: Tracks statistical drift in the network traffic to detect when the models might be becoming stale or when a zero-day attack is occurring.
    *   `federated_broker.py`: Handles federated learning updates, allowing the node to share or receive model weights from other nodes.
    *   `engine.py` & `evaluator.py`: Wrapper classes and evaluation loops for the ML logic.
    *   `firewall.py` & `sdn_client.py`: The active response mechanisms. `firewall.py` interacts with local `iptables`/`ipset`, while `sdn_client.py` sends OpenFlow blocking rules to the Ryu controller.
*   **`relay/`** (API layer and WebSocket server):
    *   `app.py`: The main FastAPI application that exposes the REST API and serves the static UI assets.
    *   `ws_manager.py`: Manages high-performance WebSockets to push live alerts to the UI instantaneously.
    *   `routes/`: Directory containing specific API route definitions (health, config, mitigation).
*   **`sdn/`** (Software-Defined Networking integrations):
    *   `sentinel_controller.py`: A Ryu SDN controller application that implements a Learning Switch and exposes a REST API for the ML engine to inject network blocking rules.
    *   `honeypot.py`: A Dionaea-inspired simple TCP honeypot that listens on common ports (22, 23, 80) to capture malicious payloads and port scans.
