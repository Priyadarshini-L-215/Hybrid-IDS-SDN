import json
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open

from common import model_manifest
from common.model_manifest import (
    load_model_manifest,
    _merge_dicts,
    get_active_model_spec,
    write_model_manifest,
    write_model_meta,
)

@pytest.fixture
def mock_dirs(tmp_path):
    models_dir = tmp_path / "models"
    manifest_path = models_dir / "manifest.json"

    with patch.object(model_manifest, "MODELS_DIR", models_dir), \
         patch.object(model_manifest, "MANIFEST_PATH", manifest_path):
        yield models_dir, manifest_path

def test_load_model_manifest_not_exists(mock_dirs):
    models_dir, manifest_path = mock_dirs
    assert not manifest_path.exists()
    assert load_model_manifest() == {}

def test_load_model_manifest_exists_valid(mock_dirs):
    models_dir, manifest_path = mock_dirs
    models_dir.mkdir()
    manifest_path.write_text(json.dumps({"test": "value"}))
    assert load_model_manifest() == {"test": "value"}

def test_load_model_manifest_invalid_json(mock_dirs):
    models_dir, manifest_path = mock_dirs
    models_dir.mkdir()
    manifest_path.write_text("invalid json")
    assert load_model_manifest() == {}

def test_merge_dicts():
    base = {"a": 1, "b": {"c": 2, "d": 3}}
    updates = {"a": 10, "b": {"c": 20, "e": 4}, "f": 5}
    expected = {"a": 10, "b": {"c": 20, "d": 3, "e": 4}, "f": 5}
    assert _merge_dicts(base, updates) == expected

def test_merge_dicts_overwrite_dict_with_value():
    base = {"a": {"b": 1}}
    updates = {"a": 2}
    expected = {"a": 2}
    assert _merge_dicts(base, updates) == expected

def test_get_active_model_spec(mock_dirs):
    models_dir, manifest_path = mock_dirs
    models_dir.mkdir()
    manifest_path.write_text(json.dumps({"active": {"model_id": "v1"}}))
    assert get_active_model_spec() == {"model_id": "v1"}

def test_get_active_model_spec_missing(mock_dirs):
    models_dir, manifest_path = mock_dirs
    models_dir.mkdir()
    manifest_path.write_text(json.dumps({"other": "value"}))
    assert get_active_model_spec() == {}

def test_write_model_manifest(mock_dirs):
    models_dir, manifest_path = mock_dirs
    updates = {"active": {"model_id": "v2"}}
    res = write_model_manifest(updates)

    assert manifest_path.exists()
    saved = json.loads(manifest_path.read_text())
    assert saved["active"]["model_id"] == "v2"
    assert saved["schema_version"] == "1.0"
    assert saved["project"] == "Sentinel Core V4"
    assert res == saved

def test_write_model_manifest_merge(mock_dirs):
    models_dir, manifest_path = mock_dirs
    models_dir.mkdir()
    manifest_path.write_text(json.dumps({"existing": "data", "active": {"old": 1}}))

    updates = {"active": {"new": 2}}
    write_model_manifest(updates)

    saved = json.loads(manifest_path.read_text())
    assert saved["existing"] == "data"
    assert saved["active"] == {"old": 1, "new": 2}
    assert saved["schema_version"] == "1.0"

def test_write_model_meta(mock_dirs):
    models_dir, _ = mock_dirs
    meta_path = models_dir / "model_meta.json"

    # Test writing from scratch
    summary = {"meta_key": "meta_value"}
    res = write_model_meta(summary)
    assert meta_path.exists()
    saved = json.loads(meta_path.read_text())
    assert saved == summary
    assert res == saved

    # Test updating existing
    update_summary = {"new_key": "new_value", "meta_key": "updated_value"}
    res2 = write_model_meta(update_summary)
    saved2 = json.loads(meta_path.read_text())
    expected = {"meta_key": "updated_value", "new_key": "new_value"}
    assert saved2 == expected
    assert res2 == expected

def test_write_model_meta_invalid_existing(mock_dirs):
    models_dir, _ = mock_dirs
    models_dir.mkdir()
    meta_path = models_dir / "model_meta.json"
    meta_path.write_text("invalid json")

    summary = {"meta_key": "meta_value"}
    write_model_meta(summary)

    saved = json.loads(meta_path.read_text())
    assert saved == summary
