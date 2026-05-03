
SENTINEL CORE V4 - DEPLOYMENT README
====================================

FILES:
- model.pkl: Calibrated Random Forest Classifier (Scikit-Learn).
- scaler.pkl: PowerTransformer for feature standardization.
- feature_names.json: The 16 specific features required by the manifold schema.
- config.json: Operational thresholds for different network domains.

HOW TO USE:
1. Load model and scaler using pickle.load().
2. Extract the 16 manifold features from raw network traffic according to the feature_names.json list.
3. Transform the feature vector: `X_scaled = scaler.transform(X_input)`.
4. Predict probabilities: `probs = model.predict_proba(X_scaled)[:, 1]`.
5. Apply thresholds from config.json based on your traffic source.

Note: If the domain is unknown, use the 'default' threshold (0.153).
