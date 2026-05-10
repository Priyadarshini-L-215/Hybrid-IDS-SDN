import pytest
import asyncio
import time
from unittest.mock import MagicMock, patch, AsyncMock

# Important: drift_detector may have already imported and set RIVER_AVAILABLE
# We'll use patch on the module attribute to simulate different environments.
from ml_engine.drift_detector import DriftDetector
import ml_engine.drift_detector as dd

@pytest.fixture
def mock_adwin():
    with patch("ml_engine.drift_detector.river_drift.ADWIN") as mock_adwin_class:
        mock_instance = MagicMock()
        mock_adwin_class.return_value = mock_instance
        yield mock_instance

@pytest.mark.asyncio
async def test_river_not_available():
    with patch.object(dd, "RIVER_AVAILABLE", False):
        detector = DriftDetector()
        assert detector._detector is None

        result = await detector.update(0.5)
        assert result is False

@pytest.mark.asyncio
async def test_river_available(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        detector = DriftDetector()
        assert detector._detector is not None

@pytest.mark.asyncio
async def test_update_no_drift(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        detector = DriftDetector()

        mock_adwin.drift_detected = False

        result = await detector.update(0.5)

        mock_adwin.update.assert_called_once_with(0.5)
        assert result is False
        assert detector._sample_count == 1

@pytest.mark.asyncio
async def test_update_with_drift_sync_callback(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        callback = MagicMock()
        detector = DriftDetector(on_drift=callback)

        mock_adwin.drift_detected = True

        # Ensure cooldown doesn't block it (initially last_drift_time is 0)
        result = await detector.update(0.8)

        assert result is True
        callback.assert_called_once()
        args, kwargs = callback.call_args
        assert args[0]["type"] == "drift_alert"
        assert args[0]["samples_observed"] == 1
        assert "timestamp" in args[0]

@pytest.mark.asyncio
async def test_update_with_drift_async_callback(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        callback = AsyncMock()
        detector = DriftDetector(on_drift=callback)

        mock_adwin.drift_detected = True

        result = await detector.update(0.8)

        assert result is True
        callback.assert_awaited_once()

@pytest.mark.asyncio
async def test_drift_cooldown(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        callback = MagicMock()
        detector = DriftDetector(on_drift=callback)

        mock_adwin.drift_detected = True

        # First drift should trigger
        result1 = await detector.update(0.8)
        assert result1 is True
        assert callback.call_count == 1

        # Second drift immediately after should be ignored due to cooldown
        result2 = await detector.update(0.9)
        assert result2 is False
        assert callback.call_count == 1

@pytest.mark.asyncio
async def test_drift_callback_exception(mock_adwin):
    with patch.object(dd, "RIVER_AVAILABLE", True):
        callback = MagicMock(side_effect=Exception("Callback failed"))
        detector = DriftDetector(on_drift=callback)

        mock_adwin.drift_detected = True

        # Exception should be caught and logged, not propagated
        result = await detector.update(0.8)

        assert result is True
        callback.assert_called_once()
