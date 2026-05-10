import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import logging

from src.common.fp_store import FalsePositiveStore

@pytest.fixture
def mock_redis():
    mock = AsyncMock()
    # We don't want it to act as a falsey mock, so we use MagicMock which evaluates to True
    # in python unless __bool__ is overridden
    # Wait, in python `AsyncMock` evaluates to True.
    # We can mock setex and get
    mock.setex = AsyncMock()
    mock.get = AsyncMock()
    return mock

@pytest.fixture
def fp_store(mock_redis):
    with patch('src.common.fp_store.rc') as mock_rc:
        mock_rc.async_redis_client = mock_redis
        store = FalsePositiveStore()
        yield store, mock_redis

@pytest.mark.asyncio
async def test_add_suppression_success(fp_store):
    store, mock_redis = fp_store

    await store.add_suppression("192.168.1.1", "SIG_123", ttl=3600)

    expected_key = "sentinel:suppress:192.168.1.1:SIG_123"
    mock_redis.setex.assert_called_once_with(expected_key, 3600, "1")

@pytest.mark.asyncio
async def test_add_suppression_no_redis(caplog):
    # Setup store without redis
    with patch('src.common.fp_store.rc') as mock_rc:
        mock_rc.async_redis_client = None
        store = FalsePositiveStore()

        with caplog.at_level(logging.WARNING):
            await store.add_suppression("192.168.1.1", "SIG_123")

        assert "Redis client not available for FP suppression" in caplog.text

@pytest.mark.asyncio
async def test_add_suppression_exception(fp_store, caplog):
    store, mock_redis = fp_store
    mock_redis.setex.side_effect = Exception("Redis error")

    with caplog.at_level(logging.ERROR):
        await store.add_suppression("192.168.1.1", "SIG_123")

    assert "Failed to add FP suppression: Redis error" in caplog.text

@pytest.mark.asyncio
async def test_is_suppressed_true(fp_store):
    store, mock_redis = fp_store
    mock_redis.get.return_value = "1"

    result = await store.is_suppressed("192.168.1.1", "SIG_123")

    expected_key = "sentinel:suppress:192.168.1.1:SIG_123"
    mock_redis.get.assert_called_once_with(expected_key)
    assert result is True

@pytest.mark.asyncio
async def test_is_suppressed_false(fp_store):
    store, mock_redis = fp_store
    mock_redis.get.return_value = None

    result = await store.is_suppressed("192.168.1.1", "SIG_123")

    expected_key = "sentinel:suppress:192.168.1.1:SIG_123"
    mock_redis.get.assert_called_once_with(expected_key)
    assert result is False

@pytest.mark.asyncio
async def test_is_suppressed_no_redis():
    with patch('src.common.fp_store.rc') as mock_rc:
        mock_rc.async_redis_client = None
        store = FalsePositiveStore()

        result = await store.is_suppressed("192.168.1.1", "SIG_123")

        assert result is False

@pytest.mark.asyncio
async def test_is_suppressed_exception(fp_store, caplog):
    store, mock_redis = fp_store
    mock_redis.get.side_effect = Exception("Redis connection lost")

    with caplog.at_level(logging.ERROR):
        result = await store.is_suppressed("192.168.1.1", "SIG_123")

    assert "Failed to check FP suppression: Redis connection lost" in caplog.text
    assert result is False
