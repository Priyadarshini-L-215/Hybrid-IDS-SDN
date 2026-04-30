# Sentinel Core: Startup Optimization & Resiliency Plan

This document outlines the architectural improvements made to the **Sentinel Core** startup sequence to ensure high availability, dependency synchronization, and automated recovery.

## 🏗️ Startup Architecture

The system utilizes a unified launcher (`start.sh`) that manages the lifecycle of all microservices. The startup sequence is strictly ordered based on functional dependencies.

### 1. Dependency Ordering

| Order | Service | Dependency | Purpose |
| :--- | :--- | :--- | :--- |
| 1 | **Redis** | None | Core message bus and reputation store. |
| 2 | **Ingestion Bridge** | Redis | Sets up the Unix Socket and pipes raw data to Redis. |
| 3 | **Suricata IDS** | Ingestion | Signature-based detection engine. |
| 4 | **ML Consumer** | Redis, Ingestion | Feature extraction and ML inference. |
| 5 | **React UI** | Node.js | Dashboard build/dev server. |
| 6 | **FastAPI Relay** | Redis, UI | Real-time WebSocket bridge to the browser. |

## 🛡️ Resiliency Features

### 1. Pre-flight & Health Checks
- **Port Conflict Resolution**: Automatically identifies and terminates stale processes occupying configured ports (`5000` for API, `3000` for UI).
- **Socket Cleanup**: Removes stale `/tmp/sentinel_suricata.sock` files to prevent connection refused errors on restart.
- **Venv Validation**: Automatically checks for required Python packages and runs `setup.sh` if the environment is corrupt.

### 2. Automated Recovery
If a service fails to start (e.g., due to a missing dependency or configuration error), the system triggers an **Auto-Recovery Loop**:
1.  Runs `preflight.sh` to diagnose the root cause.
2.  Executes `setup.sh` to repair the virtual environment and system dependencies.
3.  Retries the startup sequence with a `--no-retry` flag to prevent infinite loops.

### 3. State Management
- **PID Tracking**: All active process IDs are stored in `.sentinel_state` for clean termination via `stop.sh`.
- **Locking**: `.sentinel.lock` prevents multiple concurrent startup instances which could cause race conditions.

## 🔍 Post-Startup Verification

After all services are launched, the system performs an **End-to-End Pipeline Test**:
1.  Injects a synthetic test event into the `sentinel_alerts_queue`.
2.  Waits for the ML Engine to process and move it to the `sentinel_alerts_stream`.
3.  Verifies the stream length to confirm that the full data path (Ingestion -> Redis -> ML -> Stream) is operational.

## 🛠️ Maintenance & Diagnostics

- **`./stop.sh`**: Gracefully terminates all services using the `.sentinel_state` manifest.
- **`./diag.sh`**: Returns a detailed health report including process status, port bindings, and recent log errors.
- **`./preflight.sh`**: Checks for hardware requirements (CPU cores, RAM) and system dependencies (ipset, suricata).
