# Sentinel Core: Hybrid ML-Powered IPS/IDS

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black?logo=flask)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E?logo=scikit-learn)

## Project Overview

**Sentinel Core** is an enterprise-grade, high-performance **Hybrid Intrusion Prevention System (IPS)**. It combines the reliability of **Suricata**'s signature-based detection with the agility of a **Machine Learning (ML)** inference engine for behavioral threat classification.

Unlike traditional IDS, Sentinel Core implements **Active Mitigation**—automatically triggering firewall rules to block high-confidence threats in real-time.

---

## 💻 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Security Engine** | Suricata (IDS/IPS), `nftables`/`iptables` (Mitigation) |
| **Machine Learning** | Scikit-Learn (Random Forest), Pandas, NumPy |
| **Backend Integration** | Python 3.12, Flask, Flask-Sock |
| **Frontend UI** | React, Vite, Lucide React (Sentinel Core Design) |
| **Communication** | Native WebSockets (`asyncio`/`websockets`) |
| **Data Persistence** | SQLite3 (High-performance batch logging) |
| **Analysis AI** | Google Gemini (External Scan Analysis) |

---

## 🏗️ Architecture

The system utilizes a high-performance split-host architecture:

1.  **Detection & Mitigation Sensor (WSL - Ubuntu)**: 
    *   **Suricata**: Signature-based packet inspection generating EVE JSON telemetry.
    *   **ML Inference Engine**: A high-concurrency Python consumer that performs 57-feature extraction and Random Forest classification.
    *   **Stateful Flow Correlator**: Tracks connection patterns to detect DoS and stealthy reconnaissance.
    *   **Active IPS Module**: Interfaces with the system firewall to block malicious actors instantly.
2.  **Telemetry & Management Layer (Windows)**:
    *   **Flask Relay**: An asynchronous bridge that pipes telemetry from the Linux sensor to browser clients via WebSockets.
    *   **Security Dashboard**: A "Sentinel Core" glassmorphic React interface for professional SOC monitoring.
3.  **Data Layer**:
    *   **SQLite (Persistent)**: Optimized batch-write architecture handling thousands of events per second.

---

## 🚀 Key Features

*   **Zero-Day Detection**: ML behavioral analysis identifies novel threats that bypass signature rules.
*   **Active Mitigation**: High-confidence threats (>95%) are automatically blocked by the IPS module.
*   **Volumetric Analysis**: Detects DoS/DDoS patterns and aggressive port scans through stateful correlation.
*   **Neural Telemetery**: Native WebSocket stream ensures sub-millisecond alert visibility.
*   **Attack Simulation**: Integrated Lab with Nmap and **Gemini AI** for automated scan analysis.

---

## 🚀 Fast Track (Recommended)

To install everything and start the system for the first time, simply run the unified launcher from Windows:

```cmd
start.bat
```

**What this does automatically:**
1.  Detects and prepares your **WSL** (Linux) environment.
2.  Installs **Suricata** and ML dependencies.
3.  Initializes the **Python venv** and **Node.js** UI.
4.  Launches all components (Sensor, Backend, and Dashboard).

---

## 🛠️ Manual Preparation (If needed)

### Prerequisites
*   **Windows 11** with **WSL2** (Ubuntu 22.04+).
*   **Node.js** and **Python 3.12+**.
*   **Nmap** (for the Attack Simulation Lab).

### Custom Setup Scripts
If you prefer to run setup steps manually:
- `setup.bat`: Prepares the Windows backend and UI.
- `setup_wsl.sh`: Run this inside WSL to prepare the Suricata sensor.

---

## 🛡️ Management

| Action | Command |
| :--- | :--- |
| **Stop System** | `stop.bat` |
| **View Logs** | `data/logs/consumer.log` |
| **Dashboard** | `http://localhost:5173` |

hi 

## 🏗️ Technical Deep Dive
For architecture diagrams and module details, see [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md).

