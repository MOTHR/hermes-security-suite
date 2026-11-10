"""Tests for PrivacyShieldConfig — Phase 1."""

import os
import pytest
import privacy_shield.config as ps_config
from privacy_shield.config import (
    PrivacyShieldConfig,
    load_config,
    validate_config,
    effective_threshold,
    _load_key_via_hermes,
)


class TestConfigDefaults:
    """Default configuration values."""

    def test_default_mode_is_limited(self):
        config = PrivacyShieldConfig()
        assert config.mode == "limited"

    def test_default_detection_is_regex(self):
        config = PrivacyShieldConfig()
        assert config.detection_engine == "regex"

    def test_default_token_style_is_deterministic(self):
        config = PrivacyShieldConfig()
        assert config.token_style == "deterministic"

    def test_default_fallback_is_block(self):
        config = PrivacyShieldConfig()
        assert config.fallback_on_timeout == "block"

    def test_default_enabled_is_true(self):
        config = PrivacyShieldConfig()
        assert config.enabled is True


class TestConfigValidation:
    """Configuration validation."""

    def test_valid_config(self):
        config = PrivacyShieldConfig(encryption_key="test-key")
        issues = validate_config(config)
        assert issues == []

    def test_invalid_mode(self):
        config = PrivacyShieldConfig(mode="invalid", encryption_key="k")
        issues = validate_config(config)
        assert any("mode" in i for i in issues)

    def test_allowed_modes(self):
        for mode in ("off", "audit", "limited", "strict", "paranoid"):
            config = PrivacyShieldConfig(mode=mode, encryption_key="k")
            issues = validate_config(config)
            assert issues == [], f"mode {mode} should be valid"

    def test_invalid_detection_engine(self):
        config = PrivacyShieldConfig(detection_engine="invalid", encryption_key="k")
        issues = validate_config(config)
        assert any("detection_engine" in i for i in issues)

    def test_invalid_token_style(self):
        config = PrivacyShieldConfig(token_style="invalid", encryption_key="k")
        issues = validate_config(config)
        assert any("token_style" in i for i in issues)

    def test_invalid_fallback(self):
        config = PrivacyShieldConfig(fallback_on_timeout="invalid", encryption_key="k")
        issues = validate_config(config)
        assert any("fallback_on_timeout" in i for i in issues)

    def test_missing_encryption_key(self):
        config = PrivacyShieldConfig(encryption_key="")
        issues = validate_config(config)
        assert any("encryption_key" in i for i in issues)

    def test_negative_latency(self):
        config = PrivacyShieldConfig(max_latency_ms=-1, encryption_key="k")
        issues = validate_config(config)
        assert any("max_latency_ms" in i for i in issues)


class TestConfidenceThreshold:
    """FIX-4B: confidence_threshold + per-type overrides (Architect NEU-002)."""

    def test_default_confidence_threshold(self):
        config = PrivacyShieldConfig()
        assert config.confidence_threshold == 0.8

    def test_default_overrides_force_detection_only(self):
        """Cookie, *_context and gps must default to 1.0 (detection-only)."""
        config = PrivacyShieldConfig()
        for pii_type in (
            "cookie_id",
            "health_context",
            "sensitive_context",
            "salary_context",
            "gps",
        ):
            assert config.confidence_overrides[pii_type] == 1.0, (
                f"{pii_type} override must be 1.0 by default"
            )

    def test_effective_threshold_uses_override(self):
        config = PrivacyShieldConfig(
            confidence_threshold=0.5,  # would mask everything ≥0.5
        )
        # cookie_id has a per-type override of 1.0 → still detection-only
        assert effective_threshold(config, "cookie_id") == 1.0
        # email has no override → falls back to global 0.5
        assert effective_threshold(config, "email") == 0.5

    def test_effective_threshold_falls_back_to_global(self):
        config = PrivacyShieldConfig(confidence_threshold=0.9)
        assert effective_threshold(config, "phone") == 0.9

    def test_invalid_confidence_threshold(self):
        config = PrivacyShieldConfig(
            confidence_threshold=1.5,  # out of range
            encryption_key="k",
        )
        issues = validate_config(config)
        assert any("confidence_threshold" in i for i in issues)

    def test_invalid_override_threshold(self):
        config = PrivacyShieldConfig(
            confidence_overrides={"cookie_id": -0.5},
            encryption_key="k",
        )
        issues = validate_config(config)
        assert any("confidence_overrides" in i for i in issues)


class TestKeyLoading:
    """Encryption key loading through the Hermes secret scope."""

    def _patch_secret_scope(self, monkeypatch, value):
        import agent.secret_scope as ss

        monkeypatch.setattr(ss, "get_secret", lambda name, default=None: value)

    def test_secret_scope_key_loading(self, monkeypatch):
        self._patch_secret_scope(monkeypatch, "scoped-test-key")
        assert _load_key_via_hermes() == "scoped-test-key"

    def test_secret_scope_key_missing(self, monkeypatch):
        self._patch_secret_scope(monkeypatch, None)
        assert _load_key_via_hermes() is None

    def test_secret_scope_unavailable_returns_none(self, monkeypatch):
        """Outside Hermes, the import must fail cleanly (None, no crash)."""
        import sys

        monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
        assert _load_key_via_hermes() is None

    def test_load_config_uses_secret_scope_key(self, monkeypatch):
        monkeypatch.setattr(ps_config, "_load_key_via_hermes", lambda: "cfg-key")
        monkeypatch.delenv("PRIVACY_SHIELD_KEY_FILE", raising=False)
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        cfg = load_config()
        assert cfg.encryption_key == "cfg-key"
