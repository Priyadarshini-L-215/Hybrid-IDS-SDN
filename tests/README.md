# Tests

This directory contains the test suite (unit and integration tests) for all components in the Hybrid-IDS-SDN system, including ML logic, networking, API routes, and validations.

## Detailed Directory Contents

*   **`relay/`** (API Tests):
    *   `test_alert_routes.py`, `test_config_routes.py`, `test_health_routes.py`, `test_mitigation_routes.py`: End-to-end API tests ensuring the FastAPI endpoints return correct schemas, status codes, and handle errors properly.
    *   `conftest.py`: Test fixtures for generating mock API clients and data for the relay tests.
*   **ML Engine Tests**:
    *   `test_decision_engine.py`: Critical tests that verify the logic combining rule-based and ML-based triggers results in the correct mitigation action.
    *   `test_adversarial_robustness.py`: Tests the `adversarial_guard` to ensure it correctly flags crafted adversarial network packets.
    *   `test_drift_detector.py` & `test_federated_broker.py` & `test_vae_loading.py`: Tests validating the advanced ML components, including model loading and drift detection accuracy.
*   **Component Tests**:
    *   `test_alert_builder.py`: Verifies that alert JSON structures conform to the required schema.
    *   `test_consumer.py`: Unit tests for the Redis ingestion loop.
    *   `test_feature_extractor.py`: Ensures that edge-case packets don't crash the feature extractor and that values are normalized correctly.
    *   `test_honeypot.py`: Ensures the honeypot correctly mimics services and logs incoming connections.
    *   `test_mitre_mapper.py`: Verifies the translation of generic alerts to standard MITRE tactics.
*   **Integration & Validation**:
    *   `validate_redis_pipeline.py` & `test_redis_setup.py`: Integration tests checking the end-to-end flow from Redis all the way to the ML engine.
    *   `verify_new_model.py`: A validation script to test that an experimental model is sane and performs adequately before deployment.
    *   `test_stabilization.py`: Tests the health-checking and self-healing mechanisms of the pipeline.
*   **`conftest.py`**: Global pytest fixtures used across all test suites (e.g., mock databases, test config injection).
