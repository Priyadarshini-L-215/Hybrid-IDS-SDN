# Sentinel Core - Installation & Startup Guide

## 🛠️ Prerequisites

Before starting, ensure you have the following installed on your **Linux** system (or WSL Ubuntu):
1. **Ubuntu 22.04+** (Recommended)
2. **Python 3.12+**
3. **Node.js 20+**
4. **Sudo privileges** (Required for Suricata and iptables)

---

## 🚀 Installation Procedure

We provide an automated setup script that installs system packages, creates a Python virtual environment, and sets up the React UI.

```bash
# Clone the repository and navigate into it
# Make sure setup.sh is executable
chmod +x setup.sh

# Run the unified setup
./setup.sh
```

This script will:
- Install Suricata, Redis, nmap, and nftables via `apt`.
- Install Node.js if not present.
- Create `.venv` and install all Python dependencies from `requirements.txt`.
- Run `npm install` in the `ui/` directory.

---

## 🚦 Starting the System

To launch the full stack (Sensor, Relay, and Dashboard):

```bash
./start.sh
```

### Stopping the System

To gracefully shut down all components:

```bash
./stop.sh
```

---

## 📊 Access & Monitoring

| Service | URL / Access | Description |
|---------|--------------|-------------|
| **SOC Dashboard** | `http://localhost:3000` | Real-time threat visualization |
| **Pipeline Health** | `http://localhost:5000/api/pipeline/status` | Real-time diagnostic JSON |
| **ML Logs** | `tail -f data/logs/consumer.log` | Raw inference results |
| **Relay Logs** | `tail -f data/logs/relay.log` | Flask API logs |

---

## 🛡️ Requirements & Dependencies

The system is optimized for the following stack:

### ML Pipeline (Engine)
- **PyTorch (Latest Stable)**: Dense Autoencoder for Zero-Day detection.
- **Scikit-Learn 1.6.1**: Random Forest classification (77 features) & Scaling.
- **Redis 5.0.8**: High-throughput event queueing.

### Backend (Relay)
- **Flask 3.1.3**: Async REST API.
- **Flask-Sock 0.7.0**: High-concurrency WebSocket bridge.

### Security (Sensor)
- **Suricata 7.0.3+**: Signature-based IDS/IPS.
- **Scapy 2.6.1**: Packet reconstruction and feature extraction.

---

## 🔍 Diagnostics

If the system isn't starting properly, use the diagnostic tool:

```bash
./diag.sh
```

This will check all required processes, open ports, and the virtual environment.

---

**Happy Hunting!** 🛡️
