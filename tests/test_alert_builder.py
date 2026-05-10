import pytest
import math
from src.common.alert_builder import safe_float

def test_safe_float_valid():
    assert safe_float(1.5) == 1.5
    assert safe_float("2.0") == 2.0
    assert safe_float(0) == 0.0

def test_safe_float_invalid_types():
    assert safe_float(None) == 0.0
    assert safe_float("invalid") == 0.0
    assert safe_float({}) == 0.0
    assert safe_float([]) == 0.0
    assert safe_float(object()) == 0.0

def test_safe_float_edge_cases():
    assert safe_float(math.nan) == 0.0
    assert safe_float(math.inf) == 0.0
    assert safe_float("-inf") == 0.0
    assert safe_float("nan") == 0.0
