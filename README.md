# Anti-Gravity Hybrid Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black?logo=flask)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E?logo=scikit-learn)

## Project Overview

Anti-Gravity IDS is a high-performance, real-time Network Intrusion Detection System (NIDS). It integrates **Suricata** for standard signature-based detection with a **Machine Learning (ML)** inference engine for automated behavioral threat classification, providing zero-day detection capabilities.

This project features a modern **WebSocket-based architecture**, enabling instantaneous threat visualization on a React dashboard with sub-millisecond relay latency.

---

## 🏗️ Architecture

The system utilizes a split-host architecture to maximize performance and compatibility:

1.  **Core Sensor (WSL - Ubuntu/Linux)**: 
    *   **Suricata**: Monitors raw network packets and generates EVE JSON logs.
    *   **ML Consumer**: A high-performance Python service that tails logs, extracts 57 features, and executes inference. It broadcasts processed alerts via a native WebSocket server.
2.  **Management Layer (Windows)**:
    *   **Flask Backend**: Serves as a WebSocket relay and REST API. It maintains a persistent connection to the WSL sensor.
    *   **React Dashboard**: A modern, glassmorphic UI that subscribes to the alert stream for real-time visualization.
3.  **Data Layer**:
    *   **SQLite (Persistent)**: Optimized database handler using batch-write logic to handle high-traffic bursts without locking.

---

## 🚀 Getting Started

### Prerequisites

*   **Windows 10/11** with **WSL2** installed.
*   **Suricata** installed within the WSL distribution.
*   **Python 3.12+** (Windows & WSL)
*   **Node.js 18+** & NPM

### Setup & Installation

1.  **Initialize the Environment**:
    ```cmd
    :: On Windows
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    ```

2.  **WSL Setup**:
    Ensure your WSL environment has the necessary libraries:
    ```bash
    sudo apt update && sudo apt install suricata python3-pip
    pip3 install websockets pandas scikit-learn
    ```

3.  **Frontend Setup**:
    ```cmd
    cd ui
    npm install
    ```

### Operation

**Quick Start**:
Run the unified launcher from your Windows terminal:
```cmd
start.bat
```
This script orchestrates the entire pipeline:
*   Starts Suricata and the ML Engine in **WSL**.
*   Starts the Flask Relay in **Windows**.
*   Starts the Vite Dev Server for the **React UI**.

---

## 📂 Key Components

*   **`src/ml_engine/consumer.py`**: The "Heart" of the system. Handles feature extraction, ML prediction, and WebSocket broadcasting.
*   **`src/dashboard/app.py`**: The "Bridge". Relays data from the Linux sensor to the Windows browser.
*   **`ui/src/App.jsx`**: The "Eyes". Real-time visualization with integrated attack simulation tools.
*   **`src/common/database.py`**: High-performance logging subsystem.

---

## 🛠️ Simulation & Testing

The dashboard includes an **Attack Lab** (Nmap Integration) to test the system's responsiveness:
1.  Navigate to the "Attack Lab" tab in the UI.
2.  Enter a target IP and select a scan profile.
3.  Monitor the "Monitor" tab to see real-time ML-classified alerts as the scan progresses.

---

## 🛡️ Shutdown
To cleanly close all project components (including background WSL processes):
```cmd
stop.bat
```
