"""Tests for PRIVACY_SHIELD_REASONING_MODE environment validation."""

from privacy_shield.config import ReasoningBlockConfig, load_config


def _patch_no_pass_key(monkeypatch):
    """Disable pass-store key lookup so the workshop env block is reachable."""
    monkeypatch.setattr(
        "privacy_shield.config._load_key_from_pass",
        lambda: None,
    )


def test_load_config_default_reasoning_mode(monkeypatch):
    """Without the env var, the default reasoning mode is 'restore'."""
    _patch_no_pass_key(monkeypatch)
    monkeypatch.delenv("PRIVACY_SHIELD_REASONING_MODE", raising=False)
    monkeypatch.setenv("PRIVACY_SHIELD_WORKSHOP", "1")
    config = load_config()
    assert config.reasoning.mode == "restore"


def test_valid_reasoning_mode_env_overrides(monkeypatch):
    _patch_no_pass_key(monkeypatch)
    monkeypatch.setenv("PRIVACY_SHIELD_WORKSHOP", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_REASONING_MODE", "audit")
    config = load_config()
    assert config.reasoning.mode == "audit"


def test_valid_reasoning_mode_env_off(monkeypatch):
    _patch_no_pass_key(monkeypatch)
    monkeypatch.setenv("PRIVACY_SHIELD_WORKSHOP", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_REASONING_MODE", "off")
    config = load_config()
    assert config.reasoning.mode == "off"


def test_invalid_reasoning_mode_env_falls_back_to_default(monkeypatch, caplog):
    _patch_no_pass_key(monkeypatch)
    monkeypatch.setenv("PRIVACY_SHIELD_WORKSHOP", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_REASONING_MODE", "invalid_value")
    with caplog.at_level("WARNING"):
        config = load_config()
    assert config.reasoning.mode == "restore"
    assert "invalid PRIVACY_SHIELD_REASONING_MODE" in caplog.text


def test_reasoning_block_config_default():
    cfg = ReasoningBlockConfig()
    assert cfg.mode == "restore"
    assert cfg.confidence_threshold == 0.85
    assert "codex_reasoning_items" in cfg.skip_fields


def test_reasoning_mode_env_restore_explicit(monkeypatch):
    _patch_no_pass_key(monkeypatch)
    monkeypatch.setenv("PRIVACY_SHIELD_WORKSHOP", "1")
    monkeypatch.setenv("PRIVACY_SHIELD_REASONING_MODE", "restore")
    config = load_config()
    assert config.reasoning.mode == "restore"
