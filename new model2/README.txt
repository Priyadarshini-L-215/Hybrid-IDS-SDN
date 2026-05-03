# Sentinel Core V4 - VAE Model

## Explanation of Anomaly Detection
This model uses a Variational Autoencoder (VAE) to learn the distribution of 'Normal' traffic.
Anomalies are detected by calculating the Reconstruction Error (MSE). If the error exceeds
the defined threshold, the traffic is flagged as an anomaly.

## List of Files
- vae_model.pth: PyTorch model state dictionary.
- vae_scaler.pkl: Pre-trained MinMaxScaler for feature normalization.
- feature_names.json: The strict 16-feature schema required for input.
- config.json: Model metadata and anomaly threshold.

## Steps to Use the Model
1. Load the features from the network packet in the order specified in feature_names.json.
2. Scale the input using vae_scaler.pkl.
3. Pass the scaled data through the VAE model.
4. Compare the reconstruction error to the threshold in config.json.

## Note about Feature Order Consistency
Strict adherence to the feature order in feature_names.json is CRITICAL. The model's 
input layer is mapped specifically to this 16-dimensional sequence.
