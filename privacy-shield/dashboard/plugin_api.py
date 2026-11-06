"""Privacy-Shield dashboard plugin API.

Mounted at ``/api/plugins/privacy-shield/`` by the Hermes dashboard plugin
system. Provides a thin, validated REST surface for the Desktop-Controls
pane so workshop participants can tune settings without editing YAML.

v1.6.1: Reasoning-Mode-Steuerung via ``/api/plugins/privacy-shield/reasoning``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except Exception:  # pragma: no cover - optional in minimal test harness
    yaml = None  # type: ignore[assignment,unused-ignore]

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import importlib.util
import sys as _sys


def _load_own_shield() -> Any:
    """Load THIS dashboard's plugin root under a private package name.

    Bare ``import privacy_shield`` resolves via stale site-packages
    editable finders to whichever old copy is installed — the root cause
    of the Desktop dashboard reading another copy's config/state.
    """
    root = Path(__file__).resolve().parent.parent
    name = "_privacy_shield_dashboard_own"
    if name not in _sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, root / "__init__.py",
            submodule_search_locations=[str(root)],
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot spec-load plugin root {root}")
        pkg = importlib.util.module_from_spec(spec)
        _sys.modules[name] = pkg
        spec.loader.exec_module(pkg)
    return _sys.modules[name]


_shield = _load_own_shield()
DEFAULT_HASH_LENGTH = _shield.DEFAULT_HASH_LENGTH
__version__ = _shield.__version__
_cfg_pkg = importlib.import_module("_privacy_shield_dashboard_own.config")
_audit_pkg = importlib.import_module("_privacy_shield_dashboard_own.audit")
_chain_pkg = importlib.import_module("_privacy_shield_dashboard_own.detectors.chain_factory")
_data_pkg = importlib.import_module("_privacy_shield_dashboard_own.detectors.dataclasses")
_map_pkg = importlib.import_module("_privacy_shield_dashboard_own.mapping_table")
_pseudo_pkg = importlib.import_module("_privacy_shield_dashboard_own.pseudonymizer")

ALLOWED_MODES = _cfg_pkg.ALLOWED_MODES
ALLOWED_REASONING_MODES = _cfg_pkg.ALLOWED_REASONING_MODES
PrivacyShieldConfig = _cfg_pkg.PrivacyShieldConfig
ReasoningBlockConfig = _cfg_pkg.ReasoningBlockConfig
load_config = _cfg_pkg.load_config
validate_config = _cfg_pkg.validate_config

AuditLogger = _audit_pkg.AuditLogger

build_default_chain = _chain_pkg.build_default_chain
PIIMatch = _data_pkg.PIIMatch
InMemoryMappingTable = _map_pkg.InMemoryMappingTable
Pseudonymizer = _pseudo_pkg.Pseudonymizer

logger = logging.getLogger(__name__)
router = APIRouter()

# ---------------------------------------------------------------------------
# Schema exposed to the frontend: every field the UI may render/edit.
# Values are the defaults shown when no user override exists yet.
# ---------------------------------------------------------------------------
EDITABLE_FIELDS: dict[str, dict[str, Any]] = {
    "enabled": {"type": "bool", "label": "Plugin enabled", "default": True},
    "mode": {
        "type": "choice",
        "label": "Operating mode",
        "choices": list(ALLOWED_MODES),
        "default": "limited",
    },
    "detection_engine": {
        "type": "choice",
        "label": "Detection engine",
        "choices": ["regex", "ner", "hybrid"],
        "default": "regex",
    },
    "confidence_threshold": {
        "type": "float",
        "label": "Confidence threshold",
        "min": 0.0,
        "max": 1.0,
        "step": 0.05,
        "default": 0.8,
    },
    "restore_allowed_channels": {
        "type": "string_list",
        "label": "Restore-allowed channels",
        "default": [],
    },
    "token_style": {
        "type": "choice",
        "label": "Token style",
        "choices": ["deterministic", "random"],
        "default": "deterministic",
    },
    "token_prefix": {
        "type": "string",
        "label": "Token prefix",
        "default": "TOKEN",
    },
    "storage_mode": {
        "type": "choice",
        "label": "Mapping storage",
        "choices": ["memory", "disk"],
        "default": "memory",
    },
    "cache_bypass": {"type": "bool", "label": "Cache bypass", "default": True},
    "pdf_enabled": {"type": "bool", "label": "PDF preprocessing", "default": True},
    "image_enabled": {"type": "bool", "label": "Image OCR", "default": True},
    "ocr_lang": {"type": "string", "label": "OCR languages", "default": "deu+eng"},
    "audit_log_path": {
        "type": "string",
        "label": "Operator audit log path",
        "default": "~/.hermes/profiles/default/workspace/05-Logs-Snapshots/privacy-shield.log",
    },
    "audit_log_retention_days": {
        "type": "int",
        "label": "Log retention (days)",
        "min": 1,
        "max": 3650,
        "default": 90,
    },
}


def _config_path() -> Path:
    home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    return home / "config.yaml"


class ConfigUpdate(BaseModel):
    """Flat key/value payload for POST /config. Unknown keys are ignored."""

    updates: dict[str, Any] = Field(default_factory=dict)


class RestoreTestRequest(BaseModel):
    """Request body for POST /restore-test."""

    text: str = Field(
        default="Call me at 030-12345678 or email test@example.com",
        description="Synthetic text containing PII to pseudonymize and restore.",
    )


class ReasoningModeUpdate(BaseModel):
    """Request body for POST /api/plugins/privacy-shield/reasoning."""

    mode: str = Field(
        default="restore",
        description="Reasoning redaction mode: off | audit | restore",
    )
    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Optional confidence threshold override",
    )


def _config_to_dict(config: PrivacyShieldConfig) -> dict[str, Any]:
    """Return only the editable fields as JSON-serializable values."""
    out: dict[str, Any] = {}
    for name in EDITABLE_FIELDS:
        value = getattr(config, name)
        if isinstance(value, tuple):
            value = list(value)
        out[name] = value
    return out


def _load_user_overrides() -> dict[str, Any]:
    """Read current ``plugins.entries.privacy-shield`` from config.yaml."""
    config_path = _config_path()
    if yaml is None or not config_path.exists():
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            full = yaml.safe_load(f) or {}
        return full.get("plugins", {}).get("entries", {}).get("privacy-shield", {}) or {}
    except Exception as exc:
        logger.warning("Privacy-Shield dashboard: failed to read config.yaml: %s", exc)
        return {}


def _write_user_overrides(updates: dict[str, Any]) -> None:
    """Persist editable overrides under ``plugins.entries.privacy-shield``."""
    if yaml is None:
        raise HTTPException(status_code=500, detail="PyYAML not available; cannot write config")
    config_path = _config_path()
    full: dict[str, Any] = {}
    if config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                full = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("Privacy-Shield dashboard: failed to parse config.yaml: %s", exc)
            raise HTTPException(status_code=500, detail=f"Failed to parse config.yaml: {exc}")

    full.setdefault("plugins", {}).setdefault("entries", {}).setdefault("privacy-shield", {})
    current = full["plugins"]["entries"]["privacy-shield"]
    for key, value in updates.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value

    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(full, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


@router.get("/config")
def get_config() -> dict[str, Any]:
    """Return the effective configuration limited to editable fields."""
    config = load_config()
    return {
        "version": __version__,
        "fields": EDITABLE_FIELDS,
        "values": _config_to_dict(config),
        "overrides": _load_user_overrides(),
    }


def _validate_editable(config: PrivacyShieldConfig) -> list[str]:
    """Validate only the fields exposed by the desktop UI.

    We intentionally skip ``encryption_key`` checks: the UI never edits
    secrets, and a fresh workshop/test HERMES_HOME may not have a key yet.
    """
    issues = []
    if config.mode not in ALLOWED_MODES:
        issues.append(f"Invalid mode: {config.mode} (expected one of {ALLOWED_MODES})")
    if config.detection_engine not in ("regex", "ner", "hybrid"):
        issues.append(f"Invalid detection_engine: {config.detection_engine}")
    if config.token_style not in ("deterministic", "random"):
        issues.append(f"Invalid token_style: {config.token_style}")
    if config.storage_mode not in ("memory", "disk"):
        issues.append(f"Invalid storage_mode: {config.storage_mode}")
    if not 0.0 <= config.confidence_threshold <= 1.0:
        issues.append(
            f"confidence_threshold must be in [0.0, 1.0]: {config.confidence_threshold}"
        )
    if config.audit_log_retention_days < 1 or config.audit_log_retention_days > 3650:
        issues.append(
            f"audit_log_retention_days must be in [1, 3650]: {config.audit_log_retention_days}"
        )
    return issues


@router.post("/config")
def post_config(payload: ConfigUpdate) -> dict[str, Any]:
    """Validate and persist config overrides.

    The effective config is rebuilt from defaults + new overrides and run
    through an editable-only validation. Only known editable keys are written.
    """
    allowed = set(EDITABLE_FIELDS)
    filtered: dict[str, Any] = {}
    for key, value in payload.updates.items():
        if key not in allowed:
            continue
        # Coerce list inputs back to tuple for dataclass fields that need it.
        field_type = EDITABLE_FIELDS[key].get("type")
        if field_type == "string_list" and isinstance(value, list):
            value = tuple(str(x) for x in value)
        filtered[key] = value

    # Build a candidate config to validate against.
    candidate = PrivacyShieldConfig()
    for key, value in filtered.items():
        try:
            setattr(candidate, key, value)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid value for {key}: {exc}",
            ) from exc

    issues = _validate_editable(candidate)
    if issues:
        raise HTTPException(status_code=400, detail="; ".join(issues))

    _write_user_overrides(filtered)

    # Audit-log the configuration change.
    try:
        logger_name = "privacy_shield_config_changed"
        old_mode = load_config().mode
        AuditLogger().log(
            event=logger_name,
            session_id=f"desktop-controls-{os.urandom(4).hex()}",
            mode=filtered.get("mode", old_mode),
            platform="desktop",
            changed_keys=list(filtered.keys()),
            previous_mode=old_mode,
        )
    except Exception as exc:  # pragma: no cover - audit failure must not break save
        logger.warning("Privacy-Shield dashboard: failed to write config audit log: %s", exc)

    return {"ok": True, "saved": filtered}


@router.get("/status")
def get_status() -> dict[str, Any]:
    """Runtime status: version, enabled state, mode, last audit log write."""
    config = load_config()
    log_path = Path(config.audit_log_path).expanduser()
    last_audit: str | None = None
    if log_path.exists():
        mtime = log_path.stat().st_mtime
        last_audit = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    return {
        "version": __version__,
        "enabled": config.enabled,
        "mode": config.mode,
        "reasoning_mode": config.reasoning.mode,
        "last_audit_time": last_audit,
    }


@router.post("/restore-test")
def post_restore_test(payload: RestoreTestRequest) -> dict[str, Any]:
    """Synthetic restore smoke test.

    Runs the configured detector chain + pseudonymizer on the supplied text,
    stores the resulting mappings, restores the pseudonymized text, and
    reports whether every detector match round-tripped successfully.
    """
    config = load_config()
    session_id = f"restore-test-{os.urandom(4).hex()}"

    detector_chain = build_default_chain()
    pseudonymizer = Pseudonymizer(
        token_style=config.token_style,
        token_prefix=config.token_prefix,
    )
    mapper = InMemoryMappingTable(
        token_prefix=config.token_prefix,
        hash_length=DEFAULT_HASH_LENGTH,
    )

    matches = [
        PIIMatch(
            type=m["type"],
            value=m["value"],
            start=m["start"],
            end=m["end"],
            confidence=m.get("confidence", 1.0),
            rule=m.get("rule", ""),
        )
        for m in detector_chain.detect(payload.text)
    ]
    masked, mapping = pseudonymizer.replace(
        payload.text,
        matches,
        session_id=session_id,
    )

    if not mapping:
        return {
            "ok": True,
            "restore_works": False,
            "reason": "no PII detected in sample text",
            "original": payload.text,
            "masked": masked,
            "restored": masked,
        }

    mapper.store(
        [
            {
                "token": m["token"],
                "original_value": m["original_value"],
            }
            for m in mapping
        ],
        session_id=session_id,
    )
    restored = mapper.restore_text(masked, session_id=session_id)

    originals = {m["original_value"] for m in mapping}
    restored_count = sum(1 for orig in originals if orig in restored)

    return {
        "ok": True,
        "restore_works": restored_count == len(originals),
        "matches": len(mapping),
        "restored_count": restored_count,
        "original": payload.text,
        "masked": masked,
        "restored": restored,
    }


@router.get("/reasoning")
def get_reasoning_mode() -> dict[str, Any]:
    """Return the current Reasoning-Block configuration for Desktop-Controls."""
    config = load_config()
    overrides = _load_user_overrides()
    return {
        "version": __version__,
        "mode": overrides.get("reasoning_mode", config.reasoning.mode),
        "confidence_threshold": overrides.get(
            "reasoning_confidence_threshold", config.reasoning.confidence_threshold
        ),
        "skip_fields": list(config.reasoning.skip_fields),
        "allowed_modes": list(ALLOWED_REASONING_MODES),
    }


@router.post("/reasoning")
def update_reasoning_mode(payload: ReasoningModeUpdate) -> dict[str, Any]:
    """Update the Reasoning-Block mode and optional confidence threshold.

    Values are persisted under ``plugins.entries.privacy-shield`` in
    ``config.yaml``. The in-memory config is refreshed on the next
    PrivacyShieldPlugin instantiation / Hermes reload.
    """
    if payload.mode not in ALLOWED_REASONING_MODES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid reasoning mode: {payload.mode} "
                f"(expected one of {ALLOWED_REASONING_MODES})"
            ),
        )

    updates: dict[str, Any] = {"reasoning_mode": payload.mode}
    if payload.confidence is not None:
        updates["reasoning_confidence_threshold"] = round(payload.confidence, 4)

    _write_user_overrides(updates)

    return {
        "ok": True,
        "mode": payload.mode,
        "confidence_threshold": payload.confidence,
    }
