# Sentinel Core - Installation & Startup Guide

## 🛠️ Prerequisites

Before starting, ensure you have the following installed on your **Windows** host:
1. **WSL2 (Ubuntu 22.04+)**: Required for the high-performance ML Sensor.
2. **Python 3.12+**: Required for both Windows (Relay) and WSL (Engine).
3. **Node.js 20+**: Required for the React SOC Dashboard.
4. **Suricata**: Automated install provided, but requires administrative privileges.

---

## 🚀 Installation Procedure

### 1. Unified Setup (Recommended)
The fastest way to install all dependencies across both Windows and WSL is the automated launcher:
```powershell
# Open PowerShell in the project root
.\start.bat --force-setup
```
This script will:
- Initialize the Windows virtual environment (`.venv`).
- Install all Python dependencies from `requirements.txt`.
- Provision WSL with Suricata, Redis, and PyTorch.
- Install Node.js packages for the dashboard.

### 2. Manual Step-by-Step
If you prefer granular control:

**A. Windows Backend & UI**
```powershell
.\setup.bat
```

**B. WSL Sensor (Linux)**
```bash
# Inside WSL
chmod +x setup_wsl.sh
./setup_wsl.sh
```

---

## 🚦 Starting the System

To launch the full stack (Sensor, Relay, and Dashboard):
```powershell
.\start.bat
```

### Startup Options
- `--legacy`: Disables Redis and uses the low-latency direct polling pipeline (not recommended for production).
- `--no-ui`: Starts the backend and sensor only (useful for headless servers).

---

## 📊 Access & Monitoring

| Service | URL / Access | Description |
|---------|--------------|-------------|
| **SOC Dashboard** | `http://localhost:3000` | Real-time threat visualization |
| **Pipeline Health** | `http://localhost:5000/api/pipeline/status` | Real-time diagnostic JSON |
| **ML Logs** | `wsl tail -f data/logs/consumer.log` | Raw inference results |
| **Relay Logs** | `data/logs/relay.log` | Windows-to-WSL bridge logs |

---

## 🛡️ Requirements & Dependencies

The system is optimized for the following stack:

### ML Pipeline (Engine)
- **PyTorch 2.11+**: Dense Autoencoder for Zero-Day detection.
- **Scikit-Learn 1.6+**: Random Forest classification & Scaling.
- **Redis 5.0+**: High-throughput event queueing.

### Backend (Relay)
- **Flask 3.1+**: Async REST API.
- **Flask-Sock 0.7+**: High-concurrency WebSocket bridge.

### Security (Sensor)
- **Suricata 7.0+**: Signature-based IDS/IPS.
- **Scapy 2.6+**: Packet reconstruction and feature extraction.

---

## 🔍 Troubleshooting Installation

### "ModuleNotFoundError: No module named 'torch' in WSL"
The Autoencoder requires PyTorch in the Linux environment. Run:
```bash
wsl python3 -m pip install --break-system-packages torch
```

### "WSL IP Resolution Failed"
If `start.bat` cannot find your WSL IP, ensure the `vEthernet (WSL)` adapter is enabled in Windows Network Connections and that WSL is running.

### "Suricata Permission Denied"
Suricata requires access to your network interfaces. Ensure you have accepted the UAC prompt or run your terminal as Administrator.

---

**Happy Hunting!** 🛡️
