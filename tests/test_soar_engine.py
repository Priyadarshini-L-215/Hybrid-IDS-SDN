import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from common.soar_engine import SOAREngine

@pytest.fixture
def mock_firewall():
    with patch("ml_engine.firewall.ActiveFirewall") as mock_fw:
        mock_fw.micro_block = AsyncMock(return_value=True)
        mock_fw.redirect_to_honeypot = AsyncMock(return_value=True)
        mock_fw.rate_limit = AsyncMock(return_value=True)
        mock_fw.block = AsyncMock(return_value=True)
        mock_fw.process_incident = AsyncMock(return_value=True)
        mock_fw.is_banning_disabled = AsyncMock(return_value=False)
        yield mock_fw

@pytest.mark.asyncio
async def test_soar_engine_load_playbooks():
    """Verify that the SOAR engine loads YAML playbooks correctly."""
    engine = SOAREngine(playbooks_path="config/playbooks.yaml")
    assert "ddos_mitigation" in engine.playbooks
    assert "recon_deception" in engine.playbooks
    assert "zeroday_anomaly" in engine.playbooks

@pytest.mark.asyncio
async def test_soar_engine_trigger_ddos(mock_firewall):
    """Verify that DDoS event triggers micro-mitigation playbook."""
    engine = SOAREngine(playbooks_path="config/playbooks.yaml")
    
    event = {
        "src_ip": "10.0.0.5",
        "proto": "UDP",
        "dest_port": 53
    }
    
    # Trigger DDoS (T1498) Playbook
    await engine.execute_playbook(
        classification="attack",
        confidence=90.0,
        mitre_info={"tactic": "Impact", "technique": "T1498"},
        shap_features=[{"feature": "dest_port", "weight": 0.8}],
        event=event
    )
    
    # Wait for the async task inside SOAREngine to execute
    await asyncio.sleep(0.1)
    
    # Assert micro-block was called
    mock_firewall.micro_block.assert_awaited_once_with("10.0.0.5", "UDP", 53, 300)

@pytest.mark.asyncio
async def test_soar_engine_trigger_recon(mock_firewall):
    """Verify that Scanning/Recon event triggers honeypot redirection and reputation penalty."""
    engine = SOAREngine(playbooks_path="config/playbooks.yaml")
    
    event = {
        "src_ip": "10.0.0.6",
        "proto": "TCP",
        "dest_port": 80
    }
    
    # Trigger Recon (T1595) Playbook
    await engine.execute_playbook(
        classification="attack",
        confidence=75.0,
        mitre_info={"tactic": "Discovery", "technique": "T1595"},
        shap_features=[],
        event=event
    )
    
    await asyncio.sleep(0.1)
    
    # Assert honeypot redirection and reputation penalty
    mock_firewall.redirect_to_honeypot.assert_awaited_once_with("10.0.0.6", 600)
    mock_firewall.process_incident.assert_awaited_once_with("10.0.0.6", delta=25.0)

@pytest.mark.asyncio
async def test_soar_engine_trigger_zeroday(mock_firewall):
    """Verify that Zero-Day anomaly event triggers rate limiting."""
    engine = SOAREngine(playbooks_path="config/playbooks.yaml")
    
    event = {
        "src_ip": "10.0.0.7",
        "proto": "TCP"
    }
    
    # Trigger Zero-Day Playbook
    await engine.execute_playbook(
        classification="anomaly",
        confidence=65.0,
        mitre_info=None,
        shap_features=[],
        event=event
    )
    
    await asyncio.sleep(0.1)
    
    # Assert rate limiting and honeypot redirection are called
    mock_firewall.rate_limit.assert_awaited_once_with("10.0.0.7")
    mock_firewall.redirect_to_honeypot.assert_awaited_once_with("10.0.0.7", 120)

@pytest.mark.asyncio
async def test_soar_engine_protected_ip_skips(mock_firewall):
    """Verify that protected internal IPs are skipped for any dynamic playbooks to prevent self-denial."""
    engine = SOAREngine(playbooks_path="config/playbooks.yaml")
    
    # Mock get_protected_ips to return our target IP
    with patch("common.config.get_protected_ips", return_value=["192.168.1.1"]):
        event = {
            "src_ip": "192.168.1.1",
            "proto": "UDP",
            "dest_port": 53
        }
        
        await engine.execute_playbook(
            classification="attack",
            confidence=95.0,
            mitre_info={"tactic": "Impact", "technique": "T1498"},
            shap_features=[],
            event=event
        )
        
        await asyncio.sleep(0.1)
        
        # Verify no mitigation was called
        mock_firewall.micro_block.assert_not_called()
        mock_firewall.redirect_to_honeypot.assert_not_called()
        mock_firewall.rate_limit.assert_not_called()
