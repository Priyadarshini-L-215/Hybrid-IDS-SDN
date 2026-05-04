# Sentinel Core: Hybrid ML-Powered IPS/IDS (V4)

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/Framework-FastAPI-black?logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Redis](https://img.shields.io/badge/Pipeline-Redis-red?logo=redis)

## Project Overview

**Sentinel Core V4** is an enterprise-grade, high-performance **Hybrid Intrusion Prevention System (IPS)**. It combines the reliability of **Suricata**'s signature-based detection with a multi-stage **Machine Learning (ML)** inference engine for advanced behavioral threat classification.

Unlike traditional IDS, Sentinel Core implements **Active Mitigation**—automatically triggering system firewall rules (ipset/iptables) to block high-confidence threats in real-time.

---

## 💻 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Security Engine** | Suricata 7.0+ (IDS/IPS), `nftables`/`iptables`/`ipset` (Mitigation) |
| **Data Pipeline** | Redis 7.0+ (Queueing), **Ingestion Bridge** (Unix Socket) |
| **Machine Learning** | Scikit-Learn (Random Forest), PyTorch (VAE Anomaly Detection), ONNX Runtime |
| **Backend Integration** | Python 3.12, FastAPI, Uvicorn |
| **Frontend UI** | React 19, Vite, Lucide React (Sentinel Core Design) |
| **Communication** | Native WebSockets (`asyncio`/`websockets`) |
| **Data Persistence** | SQLite3 (WAL Mode, High-performance batch logging) |
| **Analysis AI** | Google Gemini (External Scan Analysis), SHAP (XAI Forensics) |
| **Drift Detection** | River (ADWIN Algorithm) |

---

## 🏗️ Architecture

The system utilizes a high-performance, asynchronous Linux architecture:

1.  **Detection & Mitigation Sensor**: 
    *   **Suricata**: Signature-based packet inspection streaming to a Unix Socket.
    *   **Ingestion Bridge**: A high-concurrency normalizer that pipes telemetry to Redis.
    *   **Redis-Backed Pipeline**: A multi-worker pool performing **49-feature extraction** (UNSW-NB15 compatible) and Random Forest classification.
    *   **Active IPS Module**: Interfaces with `ipset` and `iptables` to block malicious actors instantly.
2.  **Telemetry & Management Layer**:
    *   **FastAPI Relay**: An asynchronous bridge piping telemetry from Redis to browser clients via WebSockets.
    *   **Security Dashboard**: A unified React 19 interface (Port 3000) for professional SOC monitoring.
3.  **Data Layer**:
    *   **SQLite (Persistent)**: Optimized batch-write architecture using **WAL mode** for concurrent access.

### Alert Sources

*   **Real IDS Alerts** come from Suricata -> Ingestion Bridge -> Redis -> Worker Pool -> SQLite -> Dashboard.
*   **Attack Lab Alerts** are synthetic scan events generated for visibility testing and labeled as simulation data.

---

## 🚀 Key Features

*   **High-Throughput Pipeline**: Redis-backed parallel processing handling 1000+ events/sec.
*   **Tri-Layer ML Pipeline**: Scaler -> Random Forest (Known Attacks) -> VAE (Zero-Day Anomalies).
*   **49-Feature Deep Extraction**: Comprehensive flow-based feature set based on the UNSW-NB15 schema.
*   **Zero-Day Detection**: Stage 3 PyTorch VAE identifies novel threats through reconstruction loss (Threshold: 0.3).
*   **Active Mitigation**: High-confidence threats are automatically blocked using kernel-level `ipset` rules.
*   **Stateful Feature Tracking**: Efficient temporal correlation (e.g., `ct_srv_src`, `ct_dst_src_ltm`) using in-memory deques.
*   **Explainable AI (XAI)**: SHAP TreeExplainer provides feature-level evidence for attack classifications.
*   **MITRE ATT&CK Mapping**: Automatic context enrichment for signature-based alerts.
*   **Unified Infrastructure**: Single-port architecture (3000) for both API and UI services.
*   **System Observability**: Integrated `./diag.sh` and `/api/pipeline/status` for real-time health monitoring.

---

## 🚀 Fast Track (Recommended)

To install and start the system:

```bash
chmod +x *.sh
./preflight.sh
./setup.sh
./start.sh
```

**What this does automatically:**
1.  Runs **Pre-flight checks** to verify system readiness (Python 3.12, Node 20+, etc.).
2.  Installs **Suricata**, **Redis**, and system dependencies via apt.
3.  Initializes the **Python venv** and **Node.js** UI.
4.  Launches all components in the background with health validation.

---

## 🛡️ ML Engine Calibration

The system uses a **VAE (Variational Autoencoder)** for behavioral anomaly detection. The default threshold is **0.3**.

To adjust sensitivity:
- Modify the `threshold` value in `models/vae_config.json`.
- Restart the engine or trigger a reload.

---

## 🛠️ Project Maintenance

*   **`src/`**: Core logic (ML Engine, Dashboard, Shared).
*   **`config/`**: System and Suricata configurations.
*   **`models/`**: ML model assets and scalers.
*   **`tests/`**: Validation suite.
*   **`data/logs/`**: Centralized logging and heartbeats.

---

## 🛡️ Management

| Action | Command |
| :--- | :--- |
| **Stop System** | `./stop.sh` |
| **Run Tests** | `pytest tests/` |
| **Health Check** | `./diag.sh` |
| **Dashboard** | `http://localhost:3000` |
| **API Status** | `http://localhost:3000/api/pipeline/status` |


## 🏗️ Research & Roadmap

### Experimental: GNN Integration
A feasibility study is underway to evaluate the integration of **Graph Neural Networks (GNNs)**. This exploration aims to leverage topological network features for enhanced threat detection.

### Architecture Reference
For a detailed breakdown of system components, data flow, and ML pipeline stages, see [project_architecture.md](./project_architecture.md).  
For dependency ordering and resiliency plans, see [STARTUP_OPTIMIZATION_PLAN.md](./STARTUP_OPTIMIZATION_PLAN.md).
