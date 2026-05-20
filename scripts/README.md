# Scripts

This directory contains various utility scripts for setup, teardown, diagnostics, and running tests for the project.

## Detailed Directory Contents

*   **Evaluation & Testing**:
    *   `compare_models.py`: Runs a comparative benchmark between multiple models (e.g., current vs. new) using test datasets, outputting performance metrics.
    *   `evaluate_locally.py` & `evaluate_pcap.py` & `evaluate_unseen.py` & `run_eval.py`: A suite of scripts to run the ML models against datasets or raw PCAPs, evaluating precision, recall, and robustness against unseen data.
*   **Data Utilities**:
    *   `capture_local_normal.py`: Reads confirmed-normal events from the database and exports them to a CSV to allow for retraining the VAE baseline.
    *   `download_dataset.py`: A utility to interface with the Kaggle API and fetch datasets like UNSW-NB15.
    *   `pcap_to_csv.py` & `prepare_training_data.py`: Data ingestion tools that run Suricata over PCAPs in offline mode, extract network features, and align them into Pandas-compatible CSVs for model training.
    *   `generate_mocks.py`: Utility to generate dummy models/scalers, usually for testing the CI/CD pipeline without loading massive real models.
*   **System & Operations**:
    *   `audit_system.py`: A diagnostic script that connects to Redis, SQLite, and the Relay API to check the health and connectivity of the entire pipeline.
    *   `run_sdn_demo.py`: A Mininet topology script that spins up an OVS Switch, an attacker host, a target, and a honeypot sink to demonstrate the SDN mitigation capabilities locally.
    *   `wait_for_pipeline.py`: A boot sequence helper that polls TCP/HTTP ports (like Redis or FastAPI) until they are ready before launching dependent services.
    *   `sentinel.service`: A Systemd service template for running the Sentinel core continuously in production.
*   **Exporting**:
    *   `export_onnx.py` & `export_vae_onnx.py`: Converts scikit-learn or Keras models into ONNX format for highly optimized, framework-agnostic serving.
    *   `export_feature_schema.py`: Auto-generates the strict `feature_order.json` directly from the `feature_extractor.py` source of truth.
