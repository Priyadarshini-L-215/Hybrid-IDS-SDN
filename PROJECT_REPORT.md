# Sentinel Core V4 — Detailed Project Report

**Project Name:** Sentinel Core: Hybrid ML-Powered IPS/IDS  
**Version:** V4.0.0  
**Report Date:** May 21, 2026  
**Repository:** `Priyadarshini-L-215/Hybrid-IDS-SDN`  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Project Objectives](#2-project-objectives)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Module Breakdown](#5-module-breakdown)
   - 5.1 [Data Acquisition Layer](#51-data-acquisition-layer)
   - 5.2 [ML Inference Engine (Tri-Layer)](#52-ml-inference-engine-tri-layer)
   - 5.3 [Decision Engine](#53-decision-engine)
   - 5.4 [Active Mitigation & Firewall](#54-active-mitigation--firewall)
   - 5.5 [SDN Integration](#55-sdn-integration)
   - 5.6 [Common Utilities](#56-common-utilities)
   - 5.7 [FastAPI Relay](#57-fastapi-relay)
   - 5.8 [React Dashboard UI](#58-react-dashboard-ui)
6. [Machine Learning Models](#6-machine-learning-models)
7. [Feature Engineering](#7-feature-engineering)
8. [API Reference](#8-api-reference)
9. [Testing](#9-testing)
10. [Configuration & Deployment](#10-configuration--deployment)
11. [Performance Targets](#11-performance-targets)
12. [Resilience & Reliability](#12-resilience--reliability)
13. [Security Considerations](#13-security-considerations)
14. [Project Statistics](#14-project-statistics)
15. [Roadmap & Future Work](#15-roadmap--future-work)

---

/## 1. Executive Summary

**Sentinel Core V4** is an enterprise-grade, high-performance **Hybrid Intrusion Prevention System (IPS/IDS)**. Unlike traditional rule-based systems, it fuses **Suricata's** signature engine with a three-layer machine learning pipeline to achieve both high-precision detection of known threats and **zero-day anomaly detection** using a Variational Autoencoder (VAE).

The system is designed for production Linux environments, achieving sub-millisecond inference latency at scale. It is capable of automatically blocking threats via kernel-level `ipset`/`iptables` rules or via Software-Defined Networking (SDN) flow rules, and presents all telemetry in a real-time React 19 SOC dashboard.

**Key Value Propositions:**
- **Hybrid Detection:** Combines rule-based and behavioral ML for low false-positive, high-recall detection.
- **Zero-Day Capability:** VAE anomaly detection catches novel attack patterns unseen during training.
- **Explainability (XAI):** SHAP values explain every ML verdict, enabling forensic auditability.
- **Automatic Blocking:** Real-time mitigation with dynamic reputation scoring and TTL-based expiry.
- **SDN-Aware:** Optional Ryu SDN controller integration for software-defined network traffic steering.

---

## 2. Project Objectives

| Objective | Description |
|-----------|-------------|
| **Hybrid Detection** | Combine Suricata's signature engine with Random Forest and VAE ML models for comprehensive threat coverage |
| **Zero-Day Detection** | Use a Variational Autoencoder to identify anomalous traffic patterns with no prior signatures |
| **Explainable AI** | Provide SHAP-based explanations for every ML-based classification decision |
| **Active Prevention** | Automatically block high-confidence threats using `ipset`/`iptables` or SDN flow rules |
| **Real-Time Visibility** | Surface alerts, GeoIP maps, MITRE ATT&CK mappings, and system health in a live SOC dashboard |
| **Production Resilience** | Self-healing supervisor loop, parallel boot, and graceful degradation under partial failures |
| **SDN Integration** | Traffic steering via Ryu SDN Controller as an optional modern mitigation backend |

---

## 3. System Architecture

The system follows a multi-layered, event-driven architecture with Redis Streams as the central message bus:

```
Network Traffic
      │
      ▼
┌─────────────┐     EVE JSON      ┌──────────────────┐    Redis    ┌───────────────────┐
│  Suricata   │ ─────────────────▶│ Ingestion Bridge │ ──────────▶│  Redis Streams    │
│  IDS/IPS    │   (Unix Socket)   │  (Normalizer)    │  (Buffer)  │  (Message Queue)  │
└─────────────┘                   └──────────────────┘            └─────────┬─────────┘
                                                                             │
                                                          ┌──────────────────▼──────────────────┐
                                                          │        ML Worker Pool / Consumers    │
                                                          │                                      │
                                                          │  ┌──────────┐  ┌──────────────────┐  │
                                                          │  │  Flow    │  │  Feature         │  │
                                                          │  │Aggregator│─▶│  Extractor (49)  │  │
                                                          │  └──────────┘  └────────┬─────────┘  │
                                                          │                          │             │
                                                          │  ┌───────────────────────┼──────────┐ │
                                                          │  │     Inference Pipeline│          │ │
                                                          │  │  ┌────────┐  ┌────────▼───────┐  │ │
                                                          │  │  │   RF   │  │   VAE          │  │ │
                                                          │  │  │(ONNX)  │  │(Zero-Day)      │  │ │
                                                          │  │  └───┬────┘  └────────┬───────┘  │ │
                                                          │  │      └────────┬────────┘         │ │
                                                          │  │         ┌─────▼──────┐           │ │
                                                          │  │         │  Decision  │           │ │
                                                          │  │         │   Engine   │           │ │
                                                          │  │         └─────┬──────┘           │ │
                                                          │  └───────────────┼──────────────────┘ │
                                                          └──────────────────┼─────────────────────┘
                                                                             │
                              ┌──────────────────────────────────────────────┼──────────────────────┐
                              │                                               │                      │
                    ┌─────────▼──────────┐                        ┌──────────▼──────┐  ┌───────────▼───────┐
                    │  Firewall Module   │                        │  FastAPI Relay  │  │ Forensics SQLite  │
                    │  (ipset/iptables)  │                        │  (REST + WS)    │  │ (Alert Store)     │
                    └────────────────────┘                        └──────────┬──────┘  └───────────────────┘
                    ┌────────────────────┐                                   │
                    │  SDN Connector     │                        ┌──────────▼──────┐
                    │  (Ryu OpenFlow)    │                        │  React Dashboard│
                    └────────────────────┘                        │  (SOC UI)       │
                                                                  └─────────────────┘
```

### Pipeline Summary

| Stage | Component | Description |
|-------|-----------|-------------|
| **Ingestion** | Suricata + Ingestion Bridge | Packet inspection → EVE JSON → Redis |
| **Processing** | Worker Pool | Concurrent event consumers from Redis |
| **Feature Extraction** | Feature Extractor | 49 UNSW-NB15 features from EVE events |
| **Layer 1 Inference** | Random Forest (ONNX/pkl) | Known attack classification |
| **Layer 2 Inference** | VAE Anomaly Detector | Zero-day anomaly detection via MSE |
| **Layer 3 Enrichment** | Decision Engine | Score fusion + CTI + GeoIP + MITRE mapping |
| **Mitigation** | Firewall / SDN | Block or redirect malicious flows |
| **Persistence** | SQLite (WAL mode) | Alert store with SHAP/MITRE metadata |
| **Delivery** | FastAPI + WebSocket | Real-time telemetry streaming to dashboard |

---

## 4. Technology Stack

| Layer | Technologies |
|-------|-------------|
| **Security Engine** | Suricata 7.0+ (IDS/IPS mode), `iptables`, `ipset` (IPv4/IPv6) |
| **Data Pipeline** | Redis 7.0+ (Streams + Queuing), Unix Socket bridge |
| **Machine Learning** | scikit-learn 1.6.1 (Random Forest), Keras 3.14 (VAE), ONNX Runtime 1.25.1 |
| **Explainability** | SHAP 0.51.0 (TreeExplainer for RF) |
| **Anomaly Detection** | Variational Autoencoder (PyTorch/Keras), River 0.24.2 (online learning) |
| **Backend** | Python 3.12+, FastAPI, Uvicorn (ASGI), Pydantic |
| **Observability** | Structlog 24.4.0 (structured JSON logs), Prometheus client, psutil |
| **Database** | SQLite3 (WAL mode) via `aiosqlite 0.20.0` (async writes) |
| **Frontend** | React 19, Vite 8, Framer Motion 12, Recharts 3, Lucide React |
| **Geolocation** | `maxminddb-geolite2` (GeoIP enrichment) |
| **CTI** | AlienVault OTX API (Cyber Threat Intelligence) |
| **SDN** | Ryu SDN Controller (optional, OpenFlow-based traffic steering) |
| **Containerization** | Docker + Docker Compose |
| **Code Quality** | Ruff (linting/formatting), mypy (type checking), pytest + asyncio |

---

## 5. Module Breakdown

### 5.1 Data Acquisition Layer

**File:** [`src/ml_engine/ingestion.py`](src/ml_engine/ingestion.py)

The **Ingestion Bridge** monitors Suricata's Unix socket for EVE JSON events in real time. It performs:

- **High-concurrency normalization** of raw Suricata EVE JSON payloads
- **Redis stream buffering** to prevent data loss under high packet rates (up to 50,000 EPS)
- **Flow event filtering** — only `flow` and `alert` event types are forwarded to the ML pipeline
- **Backpressure handling** — graceful queuing when Redis is temporarily unavailable

**File:** [`src/ml_engine/flow_aggregator.py`](src/ml_engine/flow_aggregator.py)

The **Flow Aggregator** groups raw packet events into stateful network flows, enabling temporal feature computation. It maintains a sliding time window and tracks bidirectional flow state.

---

### 5.2 ML Inference Engine (Tri-Layer)

**File:** [`src/ml_engine/engine.py`](src/ml_engine/engine.py)  
**Class:** `MLEngine`

This is the central inference hub. It orchestrates feature extraction, model loading, batch prediction, VAE anomaly detection, and SHAP explainability in a single unified interface.

#### Engine Lifecycle

1. **Initialization** — Loads model manifest, scaler, RF model (ONNX or pkl), and VAE components.
2. **Schema Validation** — Verifies that all model dimensions match the locked feature order.
3. **Batch Prediction** — Processes events in batches for throughput efficiency.
4. **Graceful Degradation** — Falls back to signature-only mode if ML models are unavailable.

#### Inference Modes

| Mode | Condition | Behavior |
|------|-----------|----------|
| `full` | All models loaded (RF + VAE) | Full tri-layer inference |
| `degraded` | RF only, no VAE | RF + signature detection |
| `fallback` | No ML models | Signature-only detection |
| `unavailable` | Schema validation failed | System alert raised |

#### Stage 1 — Random Forest (Known Attack Classification)

**Files:** `models/rf_model.pkl`, `models/scaler.pkl`

- Pre-trained on the **UNSW-NB15** dataset (49 features)
- Served via **ONNX Runtime** for maximum inference throughput (< 12ms per batch)
- Falls back to scikit-learn pkl if ONNX runtime is unavailable
- `CalibratedClassifierCV` wrapping provides calibrated probability outputs

#### Stage 2 — VAE Anomaly Detector (Zero-Day Detection)

**Files:** [`src/ml_engine/vae_detector.py`](src/ml_engine/vae_detector.py)

The **Variational Autoencoder** detects zero-day threats by measuring reconstruction error (MSE) against a baseline of "normal" traffic. Key design decisions:

- Applied **selectively** — only processes events with RF score below `ML_THRESHOLD_SUSPICIOUS` (0.6) to avoid false positives on known attacks
- Uses **22 manifold features** (a compressed subset of the 49 UNSW-NB15 features)
- Dynamic threshold: `0.014004` (loaded from `vae_config.json`)
- Encoder/Decoder architecture: Keras `.keras` format for portability

**File:** [`src/ml_engine/anomaly_scorer.py`](src/ml_engine/anomaly_scorer.py)

Wraps the VAE output with adaptive percentile-based thresholding. Uses a rolling window of past MSE values to dynamically recalibrate thresholds based on local baseline drift. Can **freeze** during active threat periods (Zero-Trust baseline protection).

**File:** [`src/ml_engine/baseline_updater.py`](src/ml_engine/baseline_updater.py)  
**File:** [`src/ml_engine/drift_detector.py`](src/ml_engine/drift_detector.py)

Implements concept drift detection using the **River** library for online learning. Detects when the traffic distribution drifts from the training baseline and triggers re-calibration of thresholds.

#### Stage 3 — SHAP Explainability (XAI)

- **TreeExplainer** initialized for the Random Forest inner estimator
- Computed **selectively** in batch mode — only for suspicious, attack, and anomalous events
- Returns **Top-3 contributing features** per prediction
- Results stored in the forensics database for audit trails

---

### 5.3 Decision Engine

**File:** [`src/ml_engine/decision_engine.py`](src/ml_engine/decision_engine.py)  
**Class:** `DecisionEngine`

The Decision Engine fuses all detection signals into a single weighted confidence score and produces a final classification verdict.

#### Signal Weights (Configurable)

| Signal | Default Weight | Notes |
|--------|---------------|-------|
| Signature (Suricata) | `1.0` | Treated as high-confidence binary signal |
| ML (Random Forest) | `0.5` | Probabilistic score [0.0, 1.0] |
| Anomaly (VAE) | `0.3` | Normalized MSE score |
| CTI (AlienVault) | `0.8` | External reputation score |

#### Classification Thresholds

| Label | Threshold | Action |
|-------|-----------|--------|
| `attack` | ≥ 0.85 | Active blocking triggered |
| `suspicious` | ≥ 0.60 | Alert generated, monitoring intensified |
| `anomaly` | ≥ 0.50 | Zero-day flag, human review recommended |
| `normal` | < 0.50 | Event logged, no action |

#### Dynamic Scoring

- Signature-based hits receive a **confidence floor of 0.92** (not absolute, still nuanced)
- Behavioral-only detections are **capped at 0.98** to reflect their probabilistic nature
- **Adversarial evasion check** via `AdversarialGuard` elevates score to ≥ 0.95 if evasion detected

#### SOAR Integration

For every non-normal event, the Decision Engine asynchronously triggers a **SOAR playbook** (`src/common/soar_engine.py`) that can:
- Log structured forensic records
- Trigger automated response actions
- Map events to MITRE ATT&CK tactics/techniques

#### Reputation System

- Redis-backed **global IP reputation scoring** with dynamic score decay
- Thresholds: `REPUTATION_TEMP_BLOCK=25.0`, `REPUTATION_PERM_BLOCK=50.0`
- Block TTL: 300 seconds (configurable)

---

### 5.4 Active Mitigation & Firewall

**File:** [`src/ml_engine/firewall.py`](src/ml_engine/firewall.py)

The Firewall module provides kernel-level traffic blocking via:

- **`ipset`** — IP-level blocklist management (IPv4 and IPv6 capable)
- **`iptables`** / **`nftables`** — Packet filtering rules
- **TTL-based expiry** — Blocks automatically expire after configurable duration
- **Protected IP list** — Internal IPs (loopback, gateways) are never blocked
- **Async write queue** — Non-blocking mitigation actions to avoid adding latency to the inference pipeline

---

### 5.5 SDN Integration

**File:** [`src/sdn/sentinel_controller.py`](src/sdn/sentinel_controller.py)  
**File:** [`src/ml_engine/sdn_client.py`](src/ml_engine/sdn_client.py)  
**File:** [`src/sdn/honeypot.py`](src/sdn/honeypot.py)

The SDN connector provides optional integration with **Ryu SDN Controllers** using the OpenFlow protocol.

**Capabilities:**
- **Traffic steering** — Redirect malicious flows to a honeypot IP (`10.99.0.2`)
- **Flow rule installation** — Programmatically install OpenFlow drop/redirect rules
- **Fail-safe fallback** — Automatically falls back to `ipset` blocking if the SDN controller is unreachable
- **Honeypot deception** — `honeypot.py` provides a lightweight deception endpoint for threat intelligence gathering

**SDN Configuration:**
```yaml
sdn:
  enabled: false                 # Disabled by default
  controller_host: "127.0.0.1"
  controller_port: 8080
  bridge_name: "br-sentinel"
  honeypot_ip: "10.99.0.2"
  fallback_to_ipset: true
```

---

### 5.6 Common Utilities

| File | Purpose |
|------|---------|
| [`src/common/config.py`](src/common/config.py) | Centralized configuration with YAML + env var precedence; supports live `refresh_config()` |
| [`src/common/feature_extractor.py`](src/common/feature_extractor.py) | 49-feature UNSW-NB15 extraction from Suricata EVE JSON with stateful flow tracking |
| [`src/common/database.py`](src/common/database.py) | SQLite WAL-mode async database with batch write buffering and 7-day retention policy |
| [`src/common/alert_builder.py`](src/common/alert_builder.py) | Constructs enriched alert objects (MITRE, GeoIP, SHAP, reputation) for storage and streaming |
| [`src/common/mitre_mapper.py`](src/common/mitre_mapper.py) | Maps Suricata alert signatures to MITRE ATT&CK tactics and technique IDs |
| [`src/common/schemas.py`](src/common/schemas.py) | Pydantic models for API request/response validation |
| [`src/common/soar_engine.py`](src/common/soar_engine.py) | Security Orchestration, Automation & Response engine for automated playbook execution |
| [`src/common/xai_translator.py`](src/common/xai_translator.py) | Translates raw SHAP values into human-readable feature impact descriptions |
| [`src/common/net_utils.py`](src/common/net_utils.py) | Network utility functions (IP validation, CIDR checks, GeoIP lookup) |
| [`src/common/logging_setup.py`](src/common/logging_setup.py) | Unified `structlog` configuration across all modules |
| [`src/common/metrics.py`](src/common/metrics.py) | Prometheus metric definitions (counters, histograms for inference latency, block counts) |
| [`src/common/fp_store.py`](src/common/fp_store.py) | False-positive store to suppress recurring benign alerts |
| [`src/common/model_manifest.py`](src/common/model_manifest.py) | Reads `models/manifest.json` for authoritative runtime model selection |
| [`src/common/config_validator.py`](src/common/config_validator.py) | Validates `sentinel_config.yaml` schema on startup |

#### Stateful Feature Tracker

The `StatefulFeatureTracker` class in `feature_extractor.py` is a core performance component:

- Maintains a **sliding window** (default: 10,000 events) of recent connection metadata
- Uses **Counter-based multi-level indices** (`O(1)` lookups) for connection tracking features:
  - `ct_srv_src` / `ct_srv_dst` — Service-level connection counts per source/destination
  - `ct_dst_ltm` / `ct_src_ltm` — Recent connection counts per destination/source IP
  - `ct_src_dport_ltm` / `ct_dst_sport_ltm` — Port-level connection frequencies
- Thread-safe via a `threading.Lock()` on write operations
- Event-level **LRU cache** (256 entries) to avoid redundant feature extraction on burst duplicates

---

### 5.7 FastAPI Relay

**File:** [`src/relay/app.py`](src/relay/app.py)

The **Relay API** is a centralized async hub serving both REST and WebSocket clients on port **3000** (single-port architecture). It acts as a bridge between the ML backend and the frontend dashboard.

#### API Route Modules

| Module | Routes | Description |
|--------|--------|-------------|
| [`health.py`](src/relay/routes/health.py) | `GET /api/health`, `GET /api/pipeline/status` | System and ML engine health checks |
| [`models.py`](src/relay/routes/models.py) | `GET/POST /api/models/*` | Model management, swapping, status |
| [`forensics.py`](src/relay/routes/forensics.py) | `GET /api/alerts`, `GET /api/forensics/*` | Historical alert retrieval with SHAP/MITRE data |
| [`mitigation_api.py`](src/relay/routes/mitigation_api.py) | `GET/POST /api/mitigation/*` | Blocklist management and manual block/unblock |
| [`intelligence_api.py`](src/relay/routes/intelligence_api.py) | `GET /api/intel/*` | CTI reputation queries, GeoIP lookups |
| [`simulation.py`](src/relay/routes/simulation.py) | `POST /api/simulate/*` | Attack traffic simulation for testing |
| [`config_api.py`](src/relay/routes/config_api.py) | `GET/POST /api/config` | Live configuration read and update |
| [`lab.py`](src/relay/routes/lab.py) | `POST /api/lab/*` | Experimental features and model evaluation |
| [`pcap.py`](src/relay/routes/pcap.py) | `POST /api/pcap/upload` | PCAP file upload for offline analysis |
| [`dev.py`](src/relay/routes/dev.py) | `GET /api/dev/*` | Development utilities and diagnostics |

#### WebSocket Manager

**File:** [`src/relay/ws_manager.py`](src/relay/ws_manager.py)

Manages active WebSocket connections with **broadcast** capability:
- Real-time alert streaming from Redis Alert Stream to all connected dashboard clients
- Connection lifecycle management (connect, disconnect, error handling)
- Batch broadcasting for performance efficiency

---

### 5.8 React Dashboard UI

**Directory:** [`ui/src/`](ui/src/)

The SOC dashboard is a React 19 single-page application built with Vite 8.

#### Core Components

| Component | File | Description |
|-----------|------|-------------|
| **Main App** | [`App.jsx`](ui/src/App.jsx) (~84KB) | Central orchestration: state management, WebSocket client, all panel layouts |
| **Attack Map** | [`components/AttackMap.jsx`](ui/src/components/AttackMap.jsx) | Real-time Force-directed graph of attack relationships using `react-force-graph-2d` |
| **MITRE Matrix** | [`components/MitreMatrix.jsx`](ui/src/components/MitreMatrix.jsx) | Interactive MITRE ATT&CK matrix highlighting active TTPs |
| **SHAP Panel** | [`components/ShapPanel.jsx`](ui/src/components/ShapPanel.jsx) | Feature importance visualization from SHAP explanations |
| **Error Boundary** | [`components/ErrorBoundary.jsx`](ui/src/components/ErrorBoundary.jsx) | Graceful error containment for panel-level failures |

#### Dashboard Panels

- **Live Alert Feed** — Real-time alert stream with severity color coding
- **GeoIP Map** — World map with attack origin markers (`react-simple-maps`, `d3-geo`)
- **Attack Force Graph** — Network topology visualization of attacker/target relationships
- **System Health** — CPU, memory, Redis queue depth, worker pool status
- **MITRE ATT&CK** — Active tactics and techniques from recent alerts
- **SHAP Explainability** — Per-alert feature impact breakdown
- **Reputation Scoreboard** — Top-N most active threat actors with reputation scores

#### Frontend Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| React | 19.2.4 | Core UI framework |
| Vite | 8.0.4 | Build tool and dev server |
| Framer Motion | 12.38.0 | Smooth animations and transitions |
| Recharts | 3.8.1 | Time-series and bar charts |
| Lucide React | 1.8.0 | Icon library |
| react-force-graph-2d | 1.29.1 | Network topology visualization |
| react-simple-maps | 3.0.0 | SVG world map for GeoIP |
| d3-geo | 3.1.1 | Geographic projections |
| @tanstack/react-virtual | 3.13.24 | Virtualized lists for large alert tables |

---

## 6. Machine Learning Models

### Model Manifest

The `models/manifest.json` serves as the **single authoritative record** for runtime model selection. All model loading paths are resolved through this file.

**Active Model Suite: `v4.0.0-multi-retrained`**

| Artifact | File | Description |
|----------|------|-------------|
| RF Model | `rf_model.pkl` | Random Forest classifier (scikit-learn, CalibratedClassifierCV) |
| RF Scaler | `scaler.pkl` | Feature scaler (PowerTransformer, Yeo-Johnson normalization) |
| VAE Encoder | `vae_encoder.keras` | Keras encoder network (22 input features, latent space) |
| VAE Decoder | `vae_decoder.keras` | Keras decoder network (reconstruction for MSE computation) |
| VAE Scaler | `vae_scaler.pkl` | Separate scaler for VAE's 22-feature subset |
| Feature Order | `feature_order.json` | Canonical 49-feature ordering for alignment |
| Feature Schema | `feature_schema.json` | Feature metadata and dtype definitions |
| Model Meta | `model_meta.json` | Architecture metadata and multi-dataset thresholds |

### Training Dataset — UNSW-NB15

The primary model suite is trained on the **UNSW-NB15** benchmark dataset:
- 49 network traffic features per sample
- Attack categories: DDoS, Reconnaissance, Exploits, Fuzzers, Backdoors, DoS, Shellcode, Worms
- Binary classification (Normal vs. Attack) for RF; reconstruction-error-based for VAE

### Multi-Dataset Thresholds

The VAE model supports adaptive thresholds for different dataset distributions:

| Dataset | VAE Threshold |
|---------|--------------|
| CIC-IDS | 0.008 |
| NSL-KDD | 0.422 |
| UNSW-NB15 | 0.013 |
| Default (operational) | 0.014 |

### Model Versioning & Rollback

The manifest maintains a `backups` list with version paths:
- `v3.1` → `backup_v3.1/`
- `vae_v3` → `backup_vae_v3/`

Model hot-swapping is supported via the `/api/models/swap` endpoint without system restart.

---

## 7. Feature Engineering

### 49 UNSW-NB15 Features

The feature extractor ([`src/common/feature_extractor.py`](src/common/feature_extractor.py)) derives 49 features from Suricata EVE JSON events:

#### Flow-Level Features (15)

| Feature | Description |
|---------|-------------|
| `flow_duration` | Total flow duration (ms) |
| `total_fwd_packets` | Packets from source to destination |
| `total_bwd_packets` | Packets from destination to source |
| `total_fwd_bytes` | Bytes from source to destination |
| `total_bwd_bytes` | Bytes from destination to source |
| `flow_iat_mean` | Mean inter-arrival time (ms) |
| `flow_iat_std` | Std of inter-arrival time (0.0 — requires raw timestamps) |
| `fwd_iat_mean` | Forward direction mean IAT |
| `bwd_iat_mean` | Backward direction mean IAT |
| `pkt_len_mean` | Mean packet length (bytes) |
| `pkt_len_std` | Std of packet length (0.0 — requires raw data) |
| `spkts` | Source packets count |
| `dpkts` | Destination packets count |
| `sbytes` | Source bytes count |
| `dbytes` | Destination bytes count |

#### Load & Loss Features (6)

| Feature | Description |
|---------|-------------|
| `sload` | Source bits per second |
| `dload` | Destination bits per second |
| `sloss` | Source packet retransmissions |
| `dloss` | Destination packet retransmissions |
| `smeansz` | Mean source packet size |
| `dmeansz` | Mean destination packet size |

#### TCP-Level Features (9)

| Feature | Description |
|---------|-------------|
| `sttl` | Source TTL (extracted from IP header or packet bytes) |
| `dttl` | Destination TTL |
| `swin` | Source TCP window size |
| `dwin` | Destination TCP window size |
| `stcpb` | Source TCP sequence number |
| `dtcpb` | Destination TCP ACK number |
| `tcprtt` | TCP round-trip time |
| `synack` | SYN→ACK timing (60% of RTT) |
| `ackdat` | ACK→data timing |

#### Jitter Features (4)

| Feature | Description |
|---------|-------------|
| `sinpkt` | Source inter-packet mean (≈ fwd IAT) |
| `dinpkt` | Destination inter-packet mean (≈ bwd IAT) |
| `sjit` | Source jitter (0.0 — requires per-packet timestamps) |
| `djit` | Destination jitter (0.0 — requires per-packet timestamps) |

#### Connection Tracking Features (7)

Computed via the `StatefulFeatureTracker` with `O(1)` lookups:

| Feature | Description |
|---------|-------------|
| `ct_state_ttl` | TTL-weighted connection state count |
| `ct_flw_http_mthd` | HTTP method flag (GET/POST = 1.0) |
| `ct_srv_src` | Recent connections from src to same service |
| `ct_srv_dst` | Recent connections to dst on same service |
| `ct_dst_ltm` | Recent connections to destination IP |
| `ct_src_ltm` | Recent connections from source IP |
| `ct_src_dport_ltm` | Recent dst-port connections from src |
| `ct_dst_sport_ltm` | Recent src-port connections to dst |
| `ct_dst_src_ltm` | Recent connections between src↔dst pair |

#### Application & Protocol Features (8)

| Feature | Description |
|---------|-------------|
| `trans_depth` | HTTP transaction depth |
| `res_bdy_len` | HTTP response body length |
| `is_sm_ips_ports` | Same IP:port on both sides (loopback/reflection detection) |
| `is_ftp_login` | FTP USER command presence |
| `ct_ftp_cmd` | FTP command count |
| `app_proto` | Protocol encoded as float (via LabelEncoder) |

### TTL Extraction

A specialized `extract_ttl_from_packet()` function handles raw packet bytes in base64 format, supporting:
- Ethernet (IPv4 and IPv6)
- VLAN-tagged frames (802.1Q)
- Linux SLL (cooked capture) format

---

## 8. API Reference

All endpoints are served on `http://localhost:3000` (or configured `API_PORT`).

### Health & Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/health` | GET | Overall system health check |
| `/api/pipeline/status` | GET | Detailed ML engine stage status |
| `/api/models/status` | GET | Loaded model versions and readiness |

### Alerts & Forensics

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | Paginated alert history |
| `/api/forensics/alert/{id}` | GET | Full alert details with SHAP and MITRE data |
| `/api/forensics/stats` | GET | Alert statistics and trend data |

### Mitigation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/mitigation/blocklist` | GET | Current active blocklist |
| `/api/mitigation/block` | POST | Manually block an IP |
| `/api/mitigation/unblock` | POST | Remove an IP from the blocklist |

### Intelligence

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/intel/reputation/{ip}` | GET | IP reputation score and history |
| `/api/intel/geoip/{ip}` | GET | Geographic information for an IP |

### Configuration

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config` | GET | Current system configuration |
| `/api/config` | POST | Update configuration (live reload) |
| `/api/models/reload` | POST | Hot-reload ML models |

### Simulation & Lab

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/simulate/attack` | POST | Simulate a specific attack event |
| `/api/pcap/upload` | POST | Upload PCAP for offline analysis |
| `/api/lab/evaluate` | POST | Run model evaluation on sample data |

### WebSocket

| Endpoint | Description |
|----------|-------------|
| `ws://localhost:3000/ws` | Real-time alert and telemetry stream |

---

## 9. Testing

The test suite is located in [`tests/`](tests/) and contains **27 test modules**.

### Test Coverage by Module

| Test File | Covers |
|-----------|--------|
| `test_tri_layer.py` | End-to-end tri-layer inference pipeline |
| `test_anomaly_scorer.py` | VAE anomaly scoring and percentile thresholding |
| `test_decision_engine.py` | Score fusion and classification thresholds |
| `test_feature_extractor.py` | 49-feature extraction from mock EVE events |
| `test_alert_builder.py` | Alert object construction and enrichment |
| `test_config_validator.py` | YAML configuration schema validation |
| `test_adversarial_robustness.py` | Adversarial evasion detection |
| `test_cti_client.py` | AlienVault CTI integration |
| `test_drift_detector.py` | Concept drift detection |
| `test_federated_broker.py` | Federated learning broker |
| `test_fp_store.py` | False-positive suppression store |
| `test_honeypot.py` | SDN honeypot deception layer |
| `test_mitre_mapper.py` | MITRE ATT&CK mapping accuracy |
| `test_model_manifest.py` | Model manifest parsing and validation |
| `test_net_utils.py` | Network utility functions |
| `test_sdn_client.py` | SDN controller client integration |
| `test_soar_engine.py` | SOAR playbook execution |
| `test_stabilization.py` | System startup and stabilization |
| `test_vae_loading.py` | VAE model loading and initialization |
| `test_db_writer.py` | Async database write operations |
| `validate_redis_pipeline.py` | End-to-end Redis pipeline validation |

### Running Tests

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run a specific test module
pytest tests/test_tri_layer.py -v

# Run tests with async support
pytest tests/ --asyncio-mode=auto
```

### Test Configuration (`pyproject.toml`)

- **Async mode:** Auto (`asyncio_mode = "auto"`)
- **Test paths:** `tests/`
- **Deprecation warnings** suppressed for cleaner CI output
- **Lint:** Ruff with rules E, F, I, UP, B, W (line-length 100)
- **Type checking:** mypy (Python 3.12 target)

---

## 10. Configuration & Deployment

### Configuration File

Primary configuration is in `config/sentinel_config.yaml`:

```yaml
network:
  api_port: 3000
  redis_host: "127.0.0.1"
  redis_port: 6379
  redis_db: 0

detection:
  decision_engine:
    thresholds:
      attack: 0.85
      suspicious: 0.60
      anomaly: 0.50
    weights:
      signature: 1.0
      ml: 0.5
      anomaly: 0.3
  anomaly_percentile: 99.5
  anomaly_min_samples: 50
  autoencoder_threshold: 0.0283

mitigation:
  reputation_temp_block: 25.0
  reputation_perm_block: 50.0
  block_ttl: 300
  rate_limit_per_sec: 5
  protected_ips: []

system:
  worker_count: 4
  batch_size: 20
  batch_flush_interval: 0.25
  db_retention_days: 7
  log_level: "INFO"
  dev_mode: false

sdn:
  enabled: false
  controller_host: "127.0.0.1"
  controller_port: 8080
  honeypot_ip: "10.99.0.2"
  fallback_to_ipset: true
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `127.0.0.1` | Redis server host |
| `REDIS_PORT` | `6379` | Redis server port |
| `REDIS_DB` | `0` | Redis database index |
| `WORKER_COUNT` | `4` | ML consumer worker threads |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `AUTOENCODER_THRESHOLD` | `0.0283` | VAE MSE threshold override |
| `EVE_LOG` | `data/logs/eve.json` | Suricata EVE JSON output path |

### Deployment Scripts

| Script | Purpose |
|--------|---------|
| `preflight.sh` | Pre-flight checks (Python 3.12, Node 20+, disk space, permissions) |
| `setup.sh` | Full installation (Suricata, Redis, Python venv, Node modules) |
| `start.sh` | Supervisor-mode startup with health checks and auto-restart |
| `stop.sh` | Graceful system shutdown |
| `diag.sh` | Comprehensive diagnostics and health reporting |
| `dev.sh` | Development mode startup with hot-reload |
| `sdn_setup.sh` | SDN component setup (Ryu controller, OVS bridge) |

### Docker Deployment

```bash
# Build and start all services
docker-compose up --build

# Stop services
docker-compose down
```

`docker-compose.yml` defines services for:
- **sentinel-backend** — ML engine + FastAPI relay
- **redis** — Redis 7.0 with persistence
- **suricata** — (Optional) containerized Suricata

### Startup Sequence

1. **Pre-flight** → Validate system requirements
2. **Redis** → Start and verify connection
3. **Suricata** → Start IDS/IPS with Unix socket output
4. **ML Consumer** → Initialize ML engine, load models, start workers
5. **Ingestion Bridge** → Connect to Suricata socket, begin event relay to Redis
6. **FastAPI Relay** → Start API server with WebSocket support
7. **UI** → Serve React dashboard (development: Vite dev server)

---

## 11. Performance Targets

| Component | Target Latency | Throughput Capacity |
|-----------|---------------|---------------------|
| **Ingestion Pipeline** | < 2 ms | 50,000 events/sec |
| **Feature Extraction** | < 8 ms | 10,000 flows/sec |
| **ML Inference (RF + VAE)** | < 12 ms | 5,000 inferences/sec |
| **SHAP Explanation** | < 25 ms (selective) | Per-alert on suspicious events |
| **Mitigation Action** | < 50 ms | 1,000 blocks/sec |
| **WebSocket Broadcast** | < 5 ms | All connected clients |
| **Database Write** | < 1 ms (async batch) | Buffered WAL writes |

### Performance Optimizations

1. **ONNX Runtime** for RF inference (removes Python overhead)
2. **Batch processing** (configurable `BATCH_SIZE=20`, `BATCH_FLUSH_INTERVAL=0.25s`)
3. **O(1) connection tracking** with pre-indexed Counters (vs. O(n) linear scan)
4. **LRU event cache** (256 entries) to skip duplicate feature extraction
5. **Selective SHAP** — Only computed for suspicious/attack events, not all traffic
6. **Async database writes** — WAL mode + batch accumulation prevents write stalls
7. **Parallel boot** — Independent services start concurrently (60% faster boot)

---

## 12. Resilience & Reliability

### Supervisor Loop

`start.sh` acts as a lightweight process supervisor:
- Monitors Ingestion Bridge, ML Consumer, and Relay API processes
- **Automatic restart** on unexpected exit with exponential backoff
- Health-check barriers ensure dependent services (Redis) are ready before dependents start

### Fault Tolerance

| Failure Scenario | System Response |
|-----------------|-----------------|
| Redis unavailable | Ingestion Bridge buffers locally; reconnects with backoff |
| ML model missing | Fallback to signature-only detection mode |
| SDN controller offline | Automatic fallback to `ipset` kernel firewall |
| VAE initialization fails | Degraded mode (RF + signatures only) |
| Database write error | In-memory queue, retry with exponential backoff |
| SHAP explainer error | Alert generated without XAI context (non-critical) |

### Privilege Heartbeat

A background process maintains `sudo` privilege TTL to ensure long-running services (Suricata packet capture, `iptables` management) retain kernel-level access without interactive sudo prompts.

---

## 13. Security Considerations

| Aspect | Implementation |
|--------|---------------|
| **Protected IPs** | Configurable list prevents blocking internal gateways or loopback |
| **False Positive Store** | Suppresses known-benign alerts to reduce alert fatigue |
| **Adversarial Guard** | Detects statistical evasion attempts (feature anomaly + confidence boosting) |
| **Path Traversal Prevention** | API endpoints validate and sanitize file paths |
| **PCAP Upload Security** | File type validation on upload; isolated analysis environment |
| **Mock Model Warning** | CRITICAL log emitted if mock models are loaded in production |
| **Zero-Trust Baseline** | Baseline updates freeze immediately during active threat detection |
| **Reputation Decay** | IPs gradually recover reputation over time for dynamic allowlisting |
| **CTI Integration** | AlienVault OTX reputation enriches decisions with external threat intelligence |

---

## 14. Project Statistics

| Metric | Value |
|--------|-------|
| **Total Python Source Lines** | ~15,224 lines |
| **Python Source Files** | 108 files |
| **React/JSX Source Files** | 6 files |
| **Test Modules** | 27 test files |
| **API Route Modules** | 11 modules |
| **ML Engine Modules** | 21 modules |
| **Common Utility Modules** | 19 modules |
| **Model Artifacts** | 15 files |
| **Git Commits (recent)** | 20+ commits (main branch) |
| **Feature Dimensions** | 49 UNSW-NB15 features |
| **VAE Feature Dimensions** | 22 manifold features |

### Code Distribution

| Component | Files | Description |
|-----------|-------|-------------|
| `src/ml_engine/` | 21 | ML inference, workers, VAE, firewall, SDN |
| `src/common/` | 19 | Shared utilities, config, DB, features |
| `src/relay/` | 13 | FastAPI app, routes, WebSocket manager |
| `src/sdn/` | 4 | SDN controller, honeypot |
| `ui/src/` | 6 | React components, hooks, utils |
| `tests/` | 27 | Test suite |
| `models/` | 15 | ML model artifacts and schemas |

---

## 15. Roadmap & Future Work

### Active Research

#### Graph Neural Network (GNN) Integration
A feasibility study is underway to evaluate **GNNs for topological threat detection**. GNNs can model network topology relationships between hosts, making them well-suited for detecting:
- Lateral movement patterns
- Botnet C2 communication graphs
- Multi-hop intrusion chains

#### Federated Learning

**File:** [`src/ml_engine/federated_broker.py`](src/ml_engine/federated_broker.py)

An experimental **Federated Learning Broker** is implemented to support privacy-preserving model updates across distributed sensor deployments. Each sensor can contribute to model improvements without sharing raw traffic data.

### Platform Enhancements

| Area | Planned Enhancement |
|------|---------------------|
| **Python 3.14+** | Custom PYO3 and Setuptools build flags for next-gen Python runtimes |
| **Ubuntu 26.04** | Experimental support for "Resolute" LTS release |
| **CPU Optimization** | Auto-detect hardware; default to CPU-optimized PyTorch binaries |
| **PCAP Analysis** | Full offline forensic re-analysis pipeline from PCAP uploads |
| **Model Retraining** | Automated periodic retraining trigger when drift is detected |
| **Multi-Tenant** | Role-based access control for SOC team management |
| **SIEM Integration** | Syslog/CEF output for enterprise SIEM forwarding |

### Configuration Targets

| Feature | Status |
|---------|--------|
| Live config reload (no restart) | ✅ Implemented |
| Model hot-swap | ✅ Implemented |
| SDN integration | ✅ Implemented (optional) |
| PCAP upload analysis | ✅ Implemented |
| Federated learning | 🚧 Experimental |
| GNN topology detection | 🔬 Research phase |
| GPU-accelerated inference | 📋 Planned |
| Automated model retraining | 📋 Planned |

---

## References & Architecture Documents

| Document | Description |
|----------|-------------|
| [`README.md`](README.md) | Quick-start guide and tech stack overview |
| [`project_architecture.md`](project_architecture.md) | Core system architecture with Mermaid diagrams |
| [`models/manifest.json`](models/manifest.json) | Authoritative model registry |
| [`models/README.md`](models/README.md) | Model artifact documentation |
| [`tests/README.md`](tests/README.md) | Test suite documentation |

---

*This report was generated on **May 21, 2026** from the active `main` branch of the Sentinel Core V4 codebase.*
