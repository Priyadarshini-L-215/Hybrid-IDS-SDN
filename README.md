# Anti-Gravity Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-black?logo=flask)
![React](https://img.shields.io/badge/Frontend-React-blue?logo=react)
![Suricata](https://img.shields.io/badge/Security-Suricata-red)
![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E?logo=scikit-learn)

## Project Overview

Anti-Gravity IDS is an advanced Network Intrusion Detection System (NIDS) designed for real-time monitoring and threat classification. The system integrates **Suricata** for high-performance network traffic analysis with a powerful **Machine Learning (ML)** engine for automated, intelligent threat detection. 

By capturing network flow data, extracting relevant features, and leveraging a trained Random Forest model, the Anti-Gravity IDS accurately identifies potential security breaches, presenting insights through a dynamic and professional dashboard interface.

---

## 🏗️ Architecture

The system operates across four primary layers:

1. **Traffic Capture (Suricata):** Actively monitors network interfaces and generates highly detailed EVE JSON logs (`data/logs/eve.json`) containing rich flow metrics.
2. **ML Inference Engine (`src/ml_engine`):** A persistent consumer service that tails Suricata logs in real-time, extracts over 70 pertinent network features, and executes inference using a tailored Random Forest classifier.
3. **Model Management (`models/`):** Manages the AI core, including the training pipeline (`train.py`), serialized model artifacts (`model.pkl`), and feature blueprints (`features.json`).
4. **Visual Subsystem & Dashboard (`ui/` & `src/dashboard/`):** A modern React-based frontend supported by a robust Flask backend API, providing real-time data visualization and alerts for security analysts.

---

## 🛠️ Tech Stack

* **Network Security Subsystem:** Suricata (IDS/IPS)
* **Machine Learning Engine:** Scikit-learn (Random Forest), Pandas, NumPy
* **Backend API & Web Orchestration:** Python 3.12, Flask
* **Frontend Visualization:** React, Node.js (`npm`)
* **Standard Data Exchange Format:** EVE JSON

---

## 📂 Key Components & Directory Structure

* **`config/`**: Contains core configurations for Suricata and the application itself.
* **`data/logs/`**: Repository for raw and processed network traffic and machine learning logs.
* **`models/`**: Houses the training scripts (`train.py`) and compiled binary models.
    * *Pipeline:* Trains the model employing class balancing, evaluating with Accuracy and ROC-AUC metrics, and generating feature importance reports.
* **`src/ml_engine/`**: The real-time inference logic.
    * *Consumer (`consumer.py`)*: Tails `eve.json`, extracts numerical features, categorizes traffic seamlessly as `normal` or `attack`, and pushes enriched security events to `ml_alerts.json`.
* **`src/dashboard/`**: The Flask REST Backend driving analytical data consumption (`app.py`).
* **`ui/`**: The React-based graphical command interface.
* **`start.bat`**: Windows quick-launcher script.

---

## 🚀 Development & Operational Workflow

### System Requirements
1. **Suricata** installed and properly bound to the primary network interface (configured via `config/suricata/`).
2. **Python 3.12+**
3. **Node.js 18+** & NPM

### Setup Instructions

1. **Initialize the Python Environment:**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```
2. **Install Frontend Dependencies:**
   ```bash
   cd ui
   npm install
   ```

### Running the System

You have two options for starting the system:

#### Option A: Quick Launch (Windows)
Simply run the included batch script to launch the unified servers automatically:
```cmd
start.bat
```
*(This bootstrapper automatically launches both the Defense Backend/Flask API on Port 5000 and the React Visual Dashboard on Port 5173).*

#### Option B: Manual Startup

**1. Start the Machine Learning Engine:**
*(For live inference against incoming Suricata logs)*
```bash
python src/ml_engine/consumer.py
```

**2. Start the Backend API (Flask):**
```bash
python src/dashboard/app.py
```

**3. Start the Frontend Application (React):**
```bash
cd ui
npm run dev
```

### Retraining the AI Model
To train or update the core detection algorithms based on new network datasets:
```bash
cd models
python train.py
```
