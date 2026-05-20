# Sentinel Core: V4 Hybrid Project Architecture

This document provides a comprehensive technical overview of the Sentinel Core V4 architecture. Sentinel is a hybrid Intrusion Detection and Prevention System (IDS/IPS) that combines signature-based detection with advanced machine learning and Software Defined Networking (SDN) capabilities.

## 🏗️ System Architecture Map

The following diagram illustrates the multi-layered data pipeline, from raw packet ingestion to machine learning inference, real-time visualization, and automated mitigation.

```mermaid
graph TD
    subgraph External_Sources [External Intelligence & Traffic]
        NT[Network Traffic]
        CTI[AlienVault OTX / CTI]
        GEO[GeoIP Database]
    end

    subgraph Ingestion_Layer [Data Acquisition Layer]
        NT --> SIDS[Suricata IDS/IPS Mode]
        SIDS -- "EVE JSON (Unix Socket)" --> ING[Ingestion Bridge]
        ING -- "Stream Buffer" --> REDIS_BUF[(Redis Streams)]
    end

    subgraph ML_Inference_Core [Sentinel ML Engine V4]
        direction TB
        REDIS_BUF -- "Fetch Event" --> CNS[Worker Pool / Consumers]
        CNS --> FLOW[Flow Aggregator]
        FLOW --> FE[Feature Extractor - 49 Features]
        
        subgraph Pipeline [Inference Pipeline]
            FE --> RF[RF Model - Known Attacks]
            FE --> VAE[VAE - Anomaly Detection]
            RF --> SCO[Fusion & Scoring]
            VAE --> SCO
        end
        
        SCO --> DE[Decision Engine]
        CTI -. "Reputation" .-> DE
        GEO -. "Location" .-> DE
        
        DE --> MITRE[MITRE ATT&CK Mapper]
        DE --> SHAP[SHAP Explainer - XAI]
    end

    subgraph Response_Mitigation [Defense & Response]
        DE -- "Block List" --> FW[Firewall Module - IPSet/IPv6]
        DE -- "OpenFlow" --> SDN[SDN Connector - Traffic Steering]
    end

    subgraph Persistence_Monitoring [Storage & Observability]
        DE -- "Store" --> DB[(Forensics Database - SQLite/PG)]
        CNS -- "Heartbeat" --> REDIS_HB[(Redis Health Registry)]
        
        subgraph Monitoring [System Health]
            MET[Prometheus Metrics]
            LOG[Structlog Centralized Logging]
            DRIFT[Drift Detection & Baseline]
        end
    end

    subgraph Delivery_Visualization [Real-time UI & API]
        DB -.-> RELAY[FastAPI Relay API]
        REDIS_BUF -- "Alert Stream" --> RELAY
        RELAY -- "WebSocket" --> UI[React Dashboard UI]
    end

    %% Styling
    classDef ingestion fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#fff
    classDef engine fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#fff
    classDef visual fill:#1e293b,stroke:#10b981,stroke-width:2px,color:#fff
    classDef decision fill:#312e81,stroke:#4f46e5,stroke-width:2px,color:#fff
    classDef critical fill:#450a0a,stroke:#dc2626,stroke-width:2px,color:#fff
    classDef storage fill:#334155,stroke:#94a3b8,stroke-width:2px,color:#fff

    class NT,CTI,GEO,SIDS,ING ingestion
    class CNS,FLOW,FE,RF,VAE,SCO,MITRE,SHAP,MET,LOG,DRIFT engine
    class DE decision
    class FW,SDN critical
    class DB,REDIS_BUF,REDIS_HB storage
    class RELAY,UI visual
```

## 🛠️ Detailed Component Breakdown

### 1. Data Acquisition Layer
*   **Suricata (IPS Mode)**: Performs deep packet inspection (DPI) and signature matching. It runs in inline mode to allow active traffic blocking.
*   **Ingestion Bridge**: A high-performance component that monitors Suricata's Unix socket, normalizes EVE JSON events, and buffers them into Redis Streams to prevent data loss during traffic spikes.

### 2. ML Inference Engine V4
*   **Flow Aggregator & Feature Extractor**: Converts raw packet events into stateful network flows, extracting 49 complex features (e.g., protocol ratios, load metrics, flow duration).
*   **Dual-Model Pipeline**:
    *   **Random Forest (ONNX)**: Optimized for classifying known attack vectors (DDoS, Recon, Exploits) with high precision.
    *   **Variational Autoencoder (VAE)**: Detects "Zero-Day" anomalies by measuring reconstruction error (MSE) against a learned baseline of "normal" traffic.
*   **Decision Engine**: A multi-criteria controller that fuses ML scores, signature hits, CTI reputation (AlienVault), and GeoIP context to produce a final security verdict.
*   **SHAP Explainer**: Provides eXplainable AI (XAI) by identifying the specific features that contributed most to a "malicious" classification.

### 3. Automated Mitigation
*   **Firewall Backend**: Interfaces with `iptables` and `ipset` for kernel-level blocking. Supports both IPv4 and IPv6 protocols.
*   **Hybrid SDN Connector**: (Optional) Communicates with SDN controllers (e.g., Ryu) to steer malicious traffic. Designed with a fail-safe fallback to legacy firewall mode if the SDN controller is unavailable.

### 4. Storage & Observability
*   **Forensics Database**: Stores detailed alert metadata, MITRE ATT&CK mappings, and SHAP values for long-term audit and analysis.
*   **Redis Registry**: Manages service heartbeats, real-time alert streams, and worker state.
*   **Observability Stack**:
    *   **Prometheus**: Tracks system performance metrics (inference latency, PPS, block counts).
    *   **Structlog**: Provides structured, searchable logs for debugging and system auditing.

### 5. Management & UI
*   **FastAPI Relay**: A centralized hub providing a RESTful API for configuration and high-speed WebSockets for real-time telemetry.
*   **React Dashboard**: A premium, responsive interface featuring real-time attack maps, forensic drills, and system health monitoring.

## 🛡️ Resilience & Reliability Engine

To ensure 24/7 operational stability, Sentinel Core V4 includes a dedicated resilience layer:

*   **Supervisor Loop**: The `start.sh` script acts as a lightweight supervisor, automatically restarting the Ingestion Bridge, ML Consumer, or Relay API if they crash or exit unexpectedly.
*   **Sudo Privilege Heartbeat**: Background processes maintain a permission "heartbeat" to ensure long-running services (like Suricata) never lose access to restricted networking hardware due to sudo timeouts.
*   **Parallel Boot Sequence**: Independent services are initialized in parallel to reduce system boot time by 60%, with health-check barriers ensuring dependent components only start when their precursors (like Redis) are ready.
*   **Absolute Health Checks**: The installer (`setup.sh`) utilizes runtime verification rather than cached state, ensuring the virtual environment and system dependencies are functional even after OS updates.

## 💻 Platform & Hardware Support

*   **Adaptive OS Support**: Optimized for modern Linux distributions, including experimental support for **Ubuntu 26.04 (Resolute)**.
*   **Experimental Python 3.14+**: Implements custom `PYO3` and `Setuptools` build-flags to support next-generation Python runtimes.
*   **CPU-Only Optimization**: Automatically detects hardware capabilities and defaults to **CPU-optimized PyTorch** binaries to ensure high performance on servers without NVIDIA GPUs.

---

## 📈 Performance Targets

| Component | Target Latency | Scale Capacity |
| :--- | :--- | :--- |
| **Ingestion Pipeline** | < 2ms | 50,000 EPS |
| **Feature Extraction** | < 8ms | 10,000 Flows/sec |
| **ML Inference (RF+VAE)** | < 12ms | 5,000 Inf/sec |
| **Mitigation Action** | < 50ms | 1,000 Blocks/sec |
