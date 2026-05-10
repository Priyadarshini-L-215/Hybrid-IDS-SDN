import json
from pathlib import Path
from typing import Any, Dict


BASE_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = BASE_DIR / "models"
MANIFEST_PATH = MODELS_DIR / "manifest.json"


def load_model_manifest() -> Dict[str, Any]:
    """Load the canonical model manifest if it exists."""
    if not MANIFEST_PATH.exists():
        return {}

    try:
        with open(MANIFEST_PATH, "r") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _merge_dicts(base: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def get_active_model_spec() -> Dict[str, Any]:
    """Return the active model specification with a safe fallback."""
    manifest = load_model_manifest()
    active = manifest.get("active", {}) if isinstance(manifest, dict) else {}
    return active if isinstance(active, dict) else {}


def write_model_manifest(updates: Dict[str, Any]) -> Dict[str, Any]:
    """Merge updates into the canonical manifest and persist it."""
    manifest = load_model_manifest()
    if not isinstance(manifest, dict):
        manifest = {}

    merged = _merge_dicts(manifest, updates)
    merged.setdefault("schema_version", "1.0")
    merged.setdefault("project", "Sentinel Core V4")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w") as f:
        json.dump(merged, f, indent=4, sort_keys=True)

    return merged


def write_model_meta(summary: Dict[str, Any]) -> Dict[str, Any]:
    """Persist the legacy metadata file used by runtime logging and compatibility."""
    meta_path = MODELS_DIR / "model_meta.json"
    meta = {}
    if meta_path.exists():
        try:
            with open(meta_path, "r") as f:
                meta = json.load(f) or {}
        except Exception:
            meta = {}

    merged = _merge_dicts(meta, summary)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(meta_path, "w") as f:
        json.dump(merged, f, indent=4, sort_keys=True)

    return merged
