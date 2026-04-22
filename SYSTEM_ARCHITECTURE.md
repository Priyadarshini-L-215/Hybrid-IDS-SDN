# Sentinel Core: System Architecture & Data Flow

This document provides a comprehensive overview of the **Sentinel Core Hybrid Intrusion Prevention System (IPS)**, detailing the multi-layer components, their interconnections, and the lifecycle of a network event from raw capture to active mitigation and visualization.

## 🗺️ High-Level Architecture

The system follows a **split-host architecture**, leveraging Linux's superior packet processing and firewall capabilities (WSL) and Windows' robust dashboard visualization (Flask/React).

```mermaid
graph TD
    subgraph "Detection & Mitigation Engine (WSL - Linux)"
        NIC["NIC (eth0)"] -- "Raw Traffic" --> Suricata["Suricata IDS/IPS"]
        Suricata -- "EVE JSON Logs" --> Consumer["ML Consumer (consumer.py)"]

        subgraph "Intelligence Pipeline"
            FE["Feature Extractor"] -- "57-Dimension Vector" --> RF["Random Forest Model"]
            RF -- "Probabilistic Analysis" --> SC["Stateful Correlator"]
            SC -- "Active Mitigation" --> IPS["IPS Module (ActiveFirewall)"]
        end

        Consumer --> FE
        IPS -- "Block Rule" --> FW["Linux Firewall (nftables)"]
        SC -- "Persistent Logging" --> SQLite[("SQLite (alerts.db)")]
        SC -- "Real-time Stream" --> WS_Server["WSL WebSocket Server"]
    end

    subgraph "Telemetry Relay (Windows - Flask)"
        Flask["Flask Backend (app.py)"]
        Relay["WS-Relay-Thread"]

        WS_Server -- "Secure Bridge" --> Relay
        Relay -- "Broadcast" --> Dash_WS["Dashboard WebSocket"]
    end

    subgraph "Security Operations Center (Windows - React)"
        UI["Sentinel Core Dashboard"]
        UI -- "Initial State Seed" --> Flask
        Dash_WS -- "Neural Stream" --> UI
    end

    SQLite -.-> Flask
```

---

## 💻 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Security Engine** | Suricata (IDS/IPS), `nftables`/`iptables` (Mitigation) |
| **Machine Learning** | Scikit-Learn (Random Forest), Pandas, NumPy |
| **Backend Integration** | Python 3.12, Flask, Flask-Sock |
| **Frontend UI** | React, Vite, Lucide React (Sentinel Core Design System) |
| **Communication** | Native WebSockets (`asyncio`/`websockets`) for <1ms latency |
| **Data Persistence** | SQLite3 (High-performance batch logging) |
| **Analysis AI** | Google Gemini (Automated Security Simulation Analysis) |

---

## 🔄 Detailed Data Flow

### 1. The Sensor Phase (WSL)
1.  **Suricata** monitors the virtual network interface and generates high-fidelity logs in the `eve.json` format.    
2.  The **ML Consumer** (`src/ml_engine/consumer.py`) tails this file, now supporting both optimized Redis pipeline (for high-volume) and legacy polling modes.

### 2. The Intelligence Phase (ML & Correlation)
1.  **Feature Extraction**: The system extracts **57 behavioral features**.
2.  **Inference**: A **Scikit-learn Random Forest** model classifies the traffic.
3.  **Stateful Correlation**: The system tracks connection history per IP to detect **Volumetric (DoS)** and **Reconnaissance (Port Scan)** patterns.

### 3. The Mitigation Phase (IPS)
1.  **Evaluation**: If a threat reaches **>95% confidence** (via ML or Stateful rules), the IPS module is triggered.  
2.  **Blocking**: The `ActiveFirewall` module issues a dynamic block rule to the Linux host.

### 4. The Telemetry Phase (Windows Bridge)
1.  The **Flask Relay** maintains a persistent **Relay Thread** connected to the WSL sensor.
2.  New alerts and mitigation statuses are instantly broadcasted to the dashboard.

### 5. The UI Phase (React)
1.  **Seed & Stream Architecture**: On load, the dashboard performs an **Initial Seed** of historical data, then pivots to the **Neural Stream (WebSocket)** for instantaneous updates.
2.  **Visualization**: Dynamic charts and the "Live Event Stream" provide sub-second visibility into the network perimeter.

---

## 📁 Module Organization & Cleanup

The project structure has been streamlined for maintainability:

| Location | Role | Status |
| :--- | :--- | :--- |
| `src/ml_engine/` | Core ML Inference & IPS | Active |
| `src/dashboard/` | Flask Relay & API | Active |
| `src/common/` | Shared utilities & config | Active |
| `tests/` | Consolidated test suite | **New (Consolidated)** |
| `scratch/` | Temporary/Diagnostic scripts | **Trimmed** |

---

## 🌐 Network Configuration

- **8765**: Internal WSL Sensor WebSocket (Telemetry Out).
- **5001**: WSL Data Service (Database Bridge).
- **5000**: Windows Backend (API & WebSocket Relay).
- **5173**: React UI Development Server.

---

## 🧠 Analysis Strategy
The **Sentinel Core** uses a **Tri-Layer Behavioral Analysis**:
- **Layer 1 (Signature)**: Suricata catches known exploit patterns.
- **Layer 2 (Probabilistic)**: ML Engine identifies atypical packet behaviors.
- **Layer 3 (Stateful)**: Flow correlator identifies multi-packet attack lifecycles.
