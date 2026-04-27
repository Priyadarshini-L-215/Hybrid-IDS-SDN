# Sentinel Core: Hybrid ML-Powered IPS/IDS

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black?logo=flask)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Redis](https://img.shields.io/badge/Pipeline-Redis-red?logo=redis)

## Project Overview

**Sentinel Core** is an enterprise-grade, high-performance **Hybrid Intrusion Prevention System (IPS)**. It combines the reliability of **Suricata**'s signature-based detection with the agility of a **Machine Learning (ML)** inference engine for behavioral threat classification.

Unlike traditional IDS, Sentinel Core implements **Active Mitigation**—automatically triggering firewall rules to block high-confidence threats in real-time.

---

## 💻 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Security Engine** | Suricata (IDS/IPS), `nftables`/`iptables` (Mitigation) |
| **Data Pipeline** | Redis (Queueing), `AsyncFileWatcher` (Low-latency ingestion) |
| **Machine Learning** | Scikit-Learn (Random Forest + StandardScaler), PyTorch (Dense Autoencoder), Pandas, NumPy |
| **Backend Integration** | Python 3.12, Flask, Flask-Sock |
| **Frontend UI** | React 19, Vite, Lucide React (Sentinel Core Design) |
| **Communication** | Native WebSockets (`asyncio`/`websockets`) |
| **Data Persistence** | SQLite3 (WAL Mode, High-performance batch logging) |
| **Analysis AI** | Google Gemini (External Scan Analysis) |

---

## 🏗️ Architecture

The system utilizes a high-performance native Linux architecture:

1.  **Detection & Mitigation Sensor**: 
    *   **Suricata**: Signature-based packet inspection generating EVE JSON telemetry.
    *   **Redis-Backed Pipeline**: A high-concurrency 4-worker pool that performs 77-feature extraction and Random Forest classification.
    *   **Stateful Flow Correlator**: Tracks connection patterns to detect DoS and stealthy reconnaissance.
    *   **Active IPS Module**: Interfaces with the system firewall to block malicious actors instantly.
2.  **Telemetry & Management Layer**:
    *   **Flask API**: An asynchronous bridge that pipes telemetry from the consumer to browser clients.
    *   **Security Dashboard**: A glassmorphic React interface for professional SOC monitoring.
3.  **Data Layer**:
    *   **SQLite (Persistent)**: Optimized batch-write architecture using **WAL mode** for concurrent access.

---

## 🚀 Key Features

*   **High-Throughput Pipeline**: Redis-backed parallel processing handling 1000+ events/sec.
*   **Tri-Layer ML Pipeline**: Scaler -> Random Forest (known attacks) -> Autoencoder (zero-day anomalies).
*   **Zero-Day Detection**: Autoencoder reconstruction loss identifies novel threats that bypass signature rules.
*   **Active Mitigation**: High-confidence threats (>95%) are automatically blocked by the IPS module.
*   **Volumetric Analysis**: Detects DoS/DDoS patterns and aggressive port scans through stateful correlation.
*   **Neural Telemetery**: Native WebSocket stream ensures sub-10ms alert visibility.
*   **Integrated Diagnostics**: Built-in tools for pipeline health, tracer probes, and connection testing.

---

## 🚀 Fast Track (Recommended)

To install everything and start the system for the first time, simply run the unified setup and launcher:

```bash
chmod +x setup.sh start.sh
./setup.sh
./start.sh
```

**What this does automatically:**
1.  Installs **Suricata**, **Redis**, and system dependencies via apt.
2.  Initializes the **Python venv** and **Node.js** UI.
3.  Launches all components (Sensor, Backend, and Dashboard) in the background.

---

## 🛠️ Project Maintenance

*   **`src/`**: Core logic (ML Engine, Dashboard, Shared).
*   **`tests/`**: Consolidated validation suite.
*   **`data/logs/`**: Centralized logging and heartbeats.

---

## 🛡️ Management

| Action | Command |
| :--- | :--- |
| **Stop System** | `./stop.sh` |
| **Run Tests** | `pytest tests/` |
| **Health Check** | `./diag.sh` |
| **Dashboard** | `http://localhost:3000` |

## 🏗️ Technical Deep Dive
For architecture diagrams and module details, see [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md).
