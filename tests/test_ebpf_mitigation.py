# test_ebpf_mitigation.py - Unit tests for eBPF XDP mitigation manager
import pytest
from unittest.mock import MagicMock, patch
import ctypes

from ml_engine.ebpf_mitigation import EBPFMitigationManager

class MockBPFTable(dict):
    def __setitem__(self, key, value):
        raw_key = key.value if hasattr(key, 'value') else key
        super().__setitem__(raw_key, value)

    def __delitem__(self, key):
        raw_key = key.value if hasattr(key, 'value') else key
        super().__delitem__(raw_key)

    def __contains__(self, key):
        raw_key = key.value if hasattr(key, 'value') else key
        return super().__contains__(raw_key)

def test_ebpf_mitigation_singleton():
    EBPFMitigationManager._instance = None
    mgr1 = EBPFMitigationManager(interface="eth0")
    mgr2 = EBPFMitigationManager(interface="eth0")
    assert mgr1 is mgr2

@patch("ml_engine.ebpf_mitigation.BCC_AVAILABLE", True)
@patch("ml_engine.ebpf_mitigation.BPF")
def test_ebpf_mitigation_load_and_block(mock_bpf_class):
    mock_bpf = MagicMock()
    mock_bpf_class.return_value = mock_bpf
    mock_table = MockBPFTable()
    mock_bpf.get_table.return_value = mock_table
    
    # Reset singleton state for testing
    EBPFMitigationManager._instance = None
    mgr = EBPFMitigationManager(interface="eth0")
    
    assert mgr.load_xdp() is True
    mock_bpf_class.assert_called_once()
    mock_bpf.load_func.assert_called_with("xdp_drop_prog", mock_bpf_class.XDP)
    mock_bpf.attach_xdp.assert_called_with("eth0", mock_bpf.load_func.return_value, 0)
    
    # Block an IP
    assert mgr.block_ip("1.2.3.4") is True
    # The key should be ctypes.c_uint32 representation of 1.2.3.4
    assert len(mock_table) == 1
    
    # Verify is_blocked
    assert mgr.is_blocked("1.2.3.4") is True
    assert mgr.is_blocked("5.6.7.8") is False
    
    # Unblock the IP
    assert mgr.unblock_ip("1.2.3.4") is True
    assert len(mock_table) == 0
    
    # Unload XDP
    mgr.unload_xdp()
    mock_bpf.remove_xdp.assert_called_with("eth0", 0)

@patch("ml_engine.ebpf_mitigation.BCC_AVAILABLE", False)
def test_ebpf_mitigation_disabled_when_bcc_missing():
    EBPFMitigationManager._instance = None
    mgr = EBPFMitigationManager(interface="eth0")
    assert mgr.load_xdp() is False
    assert mgr.block_ip("1.2.3.4") is False
