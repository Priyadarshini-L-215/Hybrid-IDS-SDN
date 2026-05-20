import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from ml_engine.federated_broker import FederatedThreatBroker
from ml_engine import redis_client as rc

@pytest.mark.asyncio
async def test_federated_broker_vae_threshold_sync():
    """Verify that broadcasting a VAE threshold change on Node 1 updates Node 2 in real-time."""
    # Reset connection for the fresh event loop
    await rc.close_async_redis()
    await rc.init_async_redis()
        
    # Setup Node 2 mock targets
    mock_detector = MagicMock()
    mock_detector.threshold = 0.015
    mock_ml_engine = MagicMock()
    mock_ml_engine.vae_detector = mock_detector
    
    mock_fp_store = AsyncMock()
    
    # Spin up Node 1 (broadcaster) and Node 2 (listener)
    broker1 = FederatedThreatBroker(node_id="node-1")
    broker2 = FederatedThreatBroker(node_id="node-2")
    
    broker2.start(mock_ml_engine, mock_fp_store)
    
    # Wait for the Pub/Sub subscription to complete
    await asyncio.sleep(0.2)
    
    try:
        # Broadcast in a retry loop to wait for subscription propagation
        subs = 0
        for _ in range(30):
            subs = await broker1.broadcast_vae_threshold(0.042)
            if subs > 0:
                break
            await asyncio.sleep(0.1)
            
        assert subs > 0, "No active subscribers found on threat exchange channel"
        
        # Wait for the async message propagation
        await asyncio.sleep(0.3)
        
        # Verify Node 2 successfully synced and updated the threshold on its ML Engine VAE
        assert mock_detector.threshold == 0.042
    finally:
        await broker2.stop()

@pytest.mark.asyncio
async def test_federated_broker_fp_suppression_sync():
    """Verify that broadcasting an administrative FP suppression on Node 1 is synced to Node 2."""
    # Reset connection for the fresh event loop
    await rc.close_async_redis()
    await rc.init_async_redis()
        
    mock_ml_engine = MagicMock()
    mock_fp_store = AsyncMock()
    
    broker1 = FederatedThreatBroker(node_id="node-1")
    broker2 = FederatedThreatBroker(node_id="node-2")
    
    broker2.start(mock_ml_engine, mock_fp_store)
    
    await asyncio.sleep(0.2)
    
    try:
        # Broadcast in a retry loop to wait for subscription propagation
        subs = 0
        for _ in range(30):
            subs = await broker1.broadcast_fp_suppression("192.168.1.99", "ET ATTACK Bruteforce")
            if subs > 0:
                break
            await asyncio.sleep(0.1)
            
        assert subs > 0, "No active subscribers found on threat exchange channel"
        
        await asyncio.sleep(0.3)
        
        # Verify Node 2 successfully invoked add_suppression on its local fp_store
        mock_fp_store.add_suppression.assert_awaited_once_with("192.168.1.99", "ET ATTACK Bruteforce")
    finally:
        await broker2.stop()
