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

## 🛠️ Getting Started

### Prerequisites

*   **Windows 11** with **WSL2** (Ubuntu recommended).
*   **Python 3.12+** installed on both Windows and WSL.
*   **Suricata** installed in the WSL environment.
*   **Node.js 18+** for the React Dashboard.

### Setup & Installation

1.  **Initialize Windows Backend**:
    ```cmd
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    ```

2.  **Environment Sync**:
    Ensure `.venv_wsl` is initialized or required packages are available in WSL:
    ```bash
    pip3 install websockets pandas scikit-learn requests
    ```

3.  **Frontend Build**:
    ```cmd
    cd ui
    npm install
    ```

### Execution

Launch the entire ecosystem with the unified controller:
```cmd
start.bat
```
This script automates the orchestration of the Suricata sensor, ML worker, Flask relay, and Vite frontend.

---

## 🛡️ Cleanup
To cleanly terminate all processes across both Windows and WSL hosts:
```cmd
stop.bat
```

