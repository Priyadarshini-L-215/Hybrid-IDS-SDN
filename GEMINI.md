# ML-Powered Intrusion Detection System (IDS)

## Project Overview
This project is an advanced Network Intrusion Detection System (NIDS) that integrates **Suricata** for real-time network traffic analysis with a **Machine Learning (ML)** engine for automated threat classification. The system captures network flows, extracts relevant features, and uses a trained model to identify potential attacks.

## Architecture
The system is divided into four main layers:

1.  **Traffic Capture (Suricata):** Monitors network interfaces and generates EVE JSON logs (`data/logs/eve.json`) containing detailed flow metrics.
2.  **ML Inference Engine (`src/ml_engine`):** A consumer service that tails Suricata logs in real-time, extracts 70+ network features, and performs inference using a Random Forest classifier.
3.  **Model Management (`models/`):** Contains the training pipeline (`train.py`), model artifacts (`model.pkl`), and feature definitions (`features.json`).
4.  **Dashboard (`src/dashboard`):** A Flask-based web interface that visualizes real-time alerts and ML insights for security analysts.

## Tech Stack
- **Network Security:** Suricata (IDS/IPS)
- **Machine Learning:** Scikit-learn (Random Forest), Pandas, NumPy
- **Backend/Dashboard:** Flask, Python 3.12
- **Data Format:** EVE JSON (Standard Suricata output)

## Key Components

### 1. ML Engine (`src/ml_engine/consumer.py`)
- **Tailing Logic:** Continuously monitors `eve.json`.
- **Feature Extraction:** Maps Suricata flow metrics to the feature vector expected by the ML model.
- **Classification:** Categorizes traffic as `normal` or `attack`.
- **Output:** Saves enriched alerts to `data/logs/ml_alerts.json`.

### 2. Training Pipeline (`models/train.py`)
- Trains a Random Forest model with class balancing.
- Evaluates performance using Accuracy and ROC-AUC metrics.
- Saves model artifacts and feature importance reports.

### 3. Web Dashboard (`src/dashboard/app.py`)
- Real-time API endpoints for alert consumption.
- Visual display of network events and ML-detected threats.

## Development Workflow

### Setup
1. Ensure Suricata is installed and running with the provided configuration in `config/suricata/`.
2. Activate the virtual environment: `.venv\Scripts\activate`.
3. Install dependencies: `pip install -r requirements.txt`.

### Running the System
1. **Start the ML Engine:**
   ```bash
   python src/ml_engine/consumer.py
   ```
2. **Start the Dashboard:**
   ```bash
   python src/dashboard/app.py
   ```
3. **Train/Retrain Model:**
   ```bash
   cd models
   python train.py
   ```

## Directory Structure
- `config/`: Suricata and system configuration files.
- `data/logs/`: Raw and processed log files.
- `models/`: Training scripts and model binary files.
- `src/ml_engine/`: Real-time processing and inference logic.
- `src/dashboard/`: Web visualization application.
