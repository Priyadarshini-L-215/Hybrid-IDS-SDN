# Sentinel Core: Hybrid ML-Powered IPS/IDS (V4)

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![FastAPI](https://img.shields.io/badge/Framework-FastAPI-black?logo=fastapi)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Redis](https://img.shields.io/badge/Pipeline-Redis-red?logo=redis)

## Project Overview

**Sentinel Core V4** is an enterprise-grade, high-performance **Hybrid Intrusion Prevention System (IPS)**. It combines the reliability of **Suricata**'s signature-based detection with a multi-stage **Machine Learning (ML)** inference engine for advanced behavioral threat classification.

Unlike traditional IDS, Sentinel Core implements **Active Mitigation**—automatically triggering system firewall rules (`ipset`/`iptables`) or SDN flow rules to block high-confidence threats in real-time.

---

## 🏗️ Architecture & Pipeline

The system utilizes a high-performance, asynchronous Linux architecture designed for sub-millisecond inference latency:

1.  **Sensors & Ingestion**:
    *   **Suricata**: Signature-based packet inspection streaming EVE JSON to a Unix Socket.
    *   **Ingestion Bridge**: A high-concurrency normalizer that pipes telemetry to Redis.
2.  **ML Inference Engine (Tri-Layer)**:
    *   **Layer 1 (Signature)**: MITRE-mapped signature matching.
    *   **Layer 2 (Behavioral)**: Random Forest (ONNX) classifying 49 UNSW-NB15 features.
    *   **Layer 3 (Anomaly)**: Variational Autoencoder (VAE) detecting Zero-Day patterns via reconstruction loss.
3.  **Active IPS Module**:
    *   Interfaces with `ipset`/`iptables` (Legacy) or **Ryu SDN Controllers** (Modern).
    *   **Shared Reputation**: Redis-backed global reputation scoring with dynamic decay.
4.  **Telemetry & UI**:
    *   **FastAPI Relay**: Unified async bridge for REST API and WebSockets.
    *   **Security Dashboard**: React 19 SOC interface with real-time Force Graphs and GeoIP mapping.

---

## 💻 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Security Engine** | Suricata 7.0+ (IDS/IPS), `nftables`/`iptables`/`ipset` (Mitigation) |
| **Data Pipeline** | Redis 7.0+ (Streams/Queueing), **Ingestion Bridge** (Unix Socket) |
| **Machine Learning** | Keras/PyTorch (VAE), ONNX Runtime (Random Forest), SHAP (XAI) |
| **Observability** | **Structlog** (Unified JSON Logging), `diag.sh` |
| **Backend** | Python 3.12, FastAPI, Uvicorn (Async Core) |
| **Frontend UI** | React 19, Vite, Lucide React, Framer Motion, Recharts |
| **Data Persistence** | SQLite3 (WAL Mode), Async Batch Writing |

---

## 🚀 Key Features

*   **Standardized Observability**: Unified `structlog` architecture across all modules for zero-error ingestion.
*   **Explainable AI (XAI)**: Integrated SHAP analysis for forensic transparency on ML decisions.
*   **Adaptive Thresholding**: Automatic VAE threshold recalibration based on local baseline drift.
*   **Zero-Day Detection**: Stage 3 VAE identifies novel threats (Threshold: Dynamic/0.3).
*   **Active Mitigation**: Automatic blocking of high-confidence threats via kernel-level `ipset`.
*   **MITRE ATT&CK Mapping**: Automatic context enrichment for signature-based alerts.
*   **GeoIP Enrichment**: Real-time geographic mapping and flag visualization in the dashboard.
*   **Unified Infrastructure**: Single-port architecture (3000) for both API and UI services.

---

## 🚀 Getting Started

To install and start the system:

```bash
chmod +x *.sh
./preflight.sh
./setup.sh
./start.sh
```

**What this does automatically:**
1.  Runs **Pre-flight checks** to verify system readiness (Python 3.12, Node 20+, etc.).
2.  Installs **Suricata**, **Redis**, and system dependencies.
3.  Initializes the **Python venv** and **Node.js** dependencies.
4.  Launches the **Relay API**, **ML Consumer**, and **Ingestion Bridge**.

---

## 🛡️ Management & Monitoring

| Action | Command |
| :--- | :--- |
| **Stop System** | `./stop.sh` |
| **Run Tests** | `pytest tests/` |
| **Health Check** | `./diag.sh` |
| **Live Dashboard** | `http://localhost:3000` |
| **Pipeline Status** | `http://localhost:3000/api/pipeline/status` |

---

## 🏗️ Research & Roadmap

### Experimental: GNN Integration
A feasibility study is underway to evaluate the integration of **Graph Neural Networks (GNNs)** for topological threat detection.

### Architecture Reference
For a detailed breakdown, see:
*   [DASHBOARD_ARCHITECTURE.md](./DASHBOARD_ARCHITECTURE.md) - UI state and visualization logic.
*   [project_architecture.md](./project_architecture.md) - Core system and ML pipeline stages.
*   [STARTUP_OPTIMIZATION_PLAN.md](./STARTUP_OPTIMIZATION_PLAN.md) - Resiliency and startup ordering.
