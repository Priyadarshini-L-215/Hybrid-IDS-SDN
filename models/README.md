# Models

This directory contains the serialized machine learning models (e.g., Random Forest, autoencoders) used for detecting anomalies and adversarial attacks.

## Detailed Directory Contents

*   **`model_v4.pkl`**: The primary predictive model (typically a Random Forest or XGBoost model) serialized using joblib or pickle. Used for high-speed binary or multi-class classification of network flows.
*   **`scaler_v4.pkl`**: The exact data scaler (e.g., StandardScaler) used during training. It must be applied to all live traffic features before they are passed to `model_v4`.
*   **`vae_encoder.keras` & `vae_decoder.keras`**: The saved Keras weights and architectures of a Variational Autoencoder, used as an unsupervised Anomaly Detector and Adversarial Guard.
*   **`vae_config.json`**: Hyperparameters and architectural configuration for the Variational Autoencoder.
*   **`feature_schema.json`**: The authoritative source defining the types and expectations of all input features for the ML models.
*   **`features.json` & `feature_order*.json`**: Defines the strict ordering of features expected by the models. Ensures that the data arrays passed to `.predict()` are correctly aligned with the training data.
*   **`manifest.json` & `model_meta.json`**: Metadata tracking versioning, creation dates, architecture types, and checksums of the models to ensure integrity when dynamically loading them into the ML Engine.
