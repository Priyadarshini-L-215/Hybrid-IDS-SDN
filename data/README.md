# Data

This directory is used for storing datasets, network captures (PCAPs), and logs used by the intrusion detection system.

## Detailed Directory Contents

*   **`alerts_fresh.db`**: A SQLite database acting as the persistent store for active security alerts. It holds the schema for correlated incidents and is queried by the Relay API.
*   **`alerts_fresh.db-shm` / `-wal`**: SQLite Write-Ahead Log and Shared Memory files, indicating the database is operating in WAL mode to support high-concurrency writes from the ML engine.
*   **`logs/`**: Contains crucial diagnostic and runtime logs for the entire pipeline:
    *   `consumer.log`: Logs from the Redis event consumer daemon.
    *   `errors.log`: A centralized sink for application-level errors.
    *   `suricata.log` & `suricata-start.log`: Output from the Suricata engine and its initialization script.
    *   `eve.json`: The raw JSON event output stream from Suricata (before ML processing).
    *   `heartbeat.jsonl`: Logs related to system health and stabilization checks.
    *   `ui.log`, `relay.log`, `ingestion.log`, `setup.log`: Service-specific operational logs.
*   **`eval_results.json` & `model_comparison.json`**: Artifacts generated during offline evaluation of the models, containing metrics like accuracy, F1 score, feature impact, and comparative benchmarks.
*   **`pcap_conv/` & `pcap_eval/`**: Work directories that temporarily hold configuration and state (`suricata_temp.yaml`, `eve.json`) when converting raw PCAPs into training/evaluation datasets using Suricata offline mode.
*   **`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.zip`**: A raw training/evaluation dataset representing a specific attack scenario (Port Scan).
*   **`UNSW-NB15_c/`**: Documentation (PDFs) and metadata related to the UNSW-NB15 threat dataset used for model training and evaluation.
