import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
import os
import sys

# Ensure src is in the path
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE_DIR / "src"))

from common.config_validator import ConfigValidator

def test_check_model_files_missing_critical():
    validator = ConfigValidator()

    # Mock Path.exists to always return False
    with patch.object(Path, 'exists', return_value=False), \
         patch('common.config_validator.ACTIVE_MODEL_FILE', 'rf_model.pkl'), \
         patch('common.config_validator.ACTIVE_SCALER_FILE', 'scaler.pkl'):
        validator.check_model_files()

    # check that we have errors for missing critical files
    # rf_model.pkl, scaler.pkl, features.json
    assert any("Critical model file missing: rf_model.pkl" in err for err in validator.errors)
    assert any("Critical model file missing: scaler.pkl" in err for err in validator.errors)
    assert any("Critical model file missing: features.json" in err for err in validator.errors)

    # check that we have warnings for missing optional files
    # vae_encoder.keras, vae_decoder.keras, vae_scaler.pkl
    assert any("Optional model file missing: vae_encoder.keras" in warn for warn in validator.warnings)
    assert any("Optional model file missing: vae_decoder.keras" in warn for warn in validator.warnings)
    assert any("Optional model file missing: vae_scaler.pkl" in warn for warn in validator.warnings)

def test_check_model_files_all_exist():
    validator = ConfigValidator()

    # Mock Path.exists to always return True
    with patch.object(Path, 'exists', return_value=True):
        validator.check_model_files()

    assert len(validator.errors) == 0
    assert len(validator.warnings) == 0

def test_check_log_permissions_missing_dir_cant_create():
    validator = ConfigValidator()

    # Mock Path.exists to return False and Path.mkdir to raise Exception
    with patch.object(Path, 'exists', return_value=False):
        with patch.object(Path, 'mkdir', side_effect=Exception("Permission denied")):
            validator.check_log_permissions()

    assert len(validator.errors) == 1
    assert "Cannot create logs directory" in validator.errors[0]

def test_check_log_permissions_not_writable():
    validator = ConfigValidator()

    # Mock Path.exists to return True and os.access to return False
    with patch.object(Path, 'exists', return_value=True):
        with patch.object(os, 'access', return_value=False):
            validator.check_log_permissions()

    assert len(validator.errors) == 1
    assert "Logs directory not writable" in validator.errors[0]

def test_check_ui_build_missing():
    validator = ConfigValidator()

    # Mock Path.exists to return False
    with patch.object(Path, 'exists', return_value=False):
        validator.check_ui_build()

    assert len(validator.warnings) == 1
    assert "UI dist directory missing" in validator.warnings[0]

def test_check_redis_connectivity_failed():
    validator = ConfigValidator()

    # Need to mock the redis import and raise an exception when pinging
    mock_redis = MagicMock()
    mock_redis.Redis.return_value.ping.side_effect = Exception("Connection refused")

    with patch.dict('sys.modules', {'redis': mock_redis}):
        validator.check_redis_connectivity()

    assert len(validator.errors) == 1
    assert "Redis connectivity failed" in validator.errors[0]

def test_validate_all():
    validator = ConfigValidator()

    # Mocking out the individual check methods
    with patch.object(validator, 'check_model_manifest') as mock_manifest, \
         patch.object(validator, 'check_model_files') as mock_files, \
         patch.object(validator, 'check_vae_loadability') as mock_vae, \
         patch.object(validator, 'check_log_permissions') as mock_logs, \
         patch.object(validator, 'check_redis_connectivity') as mock_redis, \
         patch.object(validator, 'check_ui_build') as mock_ui:

        success, errors, warnings = validator.validate_all()

        # Verify all check methods were called
        mock_manifest.assert_called_once()
        mock_files.assert_called_once()
        mock_vae.assert_called_once()
        mock_logs.assert_called_once()
        mock_redis.assert_called_once()
        mock_ui.assert_called_once()

        assert success is True
        assert len(errors) == 0
        assert len(warnings) == 0

def test_check_model_manifest_missing():
    validator = ConfigValidator()
    with patch('common.config_validator.load_model_manifest', return_value={}):
        validator.check_model_manifest()

    assert len(validator.warnings) == 1
    assert "models/manifest.json missing or unreadable" in validator.warnings[0]

def test_check_model_manifest_invalid_active():
    validator = ConfigValidator()
    with patch('common.config_validator.load_model_manifest', return_value={"active": "invalid"}):
        validator.check_model_manifest()

    assert len(validator.errors) == 1
    assert "models/manifest.json has an invalid 'active' section" in validator.errors[0]

def test_check_model_manifest_mismatch():
    validator = ConfigValidator()
    manifest_data = {
        "active": {
            "rf": {"model": "different_model.pkl", "scaler": "different_scaler.pkl"},
            "feature_schema": {"feature_count": 50}
        }
    }

    with patch('common.config_validator.load_model_manifest', return_value=manifest_data):
        validator.check_model_manifest()

    assert len(validator.warnings) == 3
    assert any("Manifest RF model" in w for w in validator.warnings)
    assert any("Manifest scaler" in w for w in validator.warnings)
    assert any("Manifest feature count" in w for w in validator.warnings)

def test_check_vae_loadability_missing_files():
    validator = ConfigValidator()
    with patch.object(Path, 'exists', return_value=False):
        validator.check_vae_loadability()

    # Should just return without errors or warnings if files are missing
    assert len(validator.errors) == 0

def test_check_vae_loadability_load_error():
    validator = ConfigValidator()

    # Mock files to exist
    with patch.object(Path, 'exists', return_value=True):
        # Mock VAE anomaly detector to raise exception
        mock_detector_class = MagicMock(side_effect=Exception("Failed to load weights"))

        # We need to mock the import of VaeAnomalyDetector inside the method
        with patch.dict('sys.modules', {'ml_engine.vae_detector': MagicMock(VaeAnomalyDetector=mock_detector_class)}):
            validator.check_vae_loadability()

    assert len(validator.errors) == 1
    assert "VAE detector loadability check failed" in validator.errors[0]

def test_check_vae_loadability_not_ready():
    validator = ConfigValidator()

    with patch.object(Path, 'exists', return_value=True):
        # Create a mock detector that is not ready
        mock_detector_instance = MagicMock()
        mock_detector_instance.is_ready = False
        mock_detector_class = MagicMock(return_value=mock_detector_instance)

        with patch.dict('sys.modules', {'ml_engine.vae_detector': MagicMock(VaeAnomalyDetector=mock_detector_class)}):
            validator.check_vae_loadability()

    assert len(validator.errors) == 1
    assert "VAE detector failed to load saved artifacts" in validator.errors[0]

def test_check_redis_connectivity_no_package():
    validator = ConfigValidator()

    # Mock redis to raise ImportError
    with patch.dict('sys.modules', {'redis': None}):
        validator.check_redis_connectivity()

    assert len(validator.warnings) == 1
    assert "Python 'redis' package not installed" in validator.warnings[0]
