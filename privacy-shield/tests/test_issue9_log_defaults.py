"""Issue #9 (t_6fb53a12): HERMES_HOME-aware audit-sink defaults + warn-guard.

v1.9.7 contracts asserted here:

1. Default resolution: with no env pin and no config.yaml pin, both audit
   sinks resolve under ``$HERMES_HOME`` (neutral fleet root) — never the
   legacy hardcoded ``profiles/default`` claim (the shared-gateway plugin
   instance is single-identity: a profile-claiming default can only
   misattribute the log).
2. ``HERMES_HOME`` unset → ``Path.home()/.hermes`` fallback (same fallback
   the user-config merge already uses).
3. Precedence (Issue #9 backward-compat): explicit env pin > explicit
   config.yaml pin > default. Existing deploy setups keep every pinned
   value; nothing moves silently.
4. Warn-guard (``log_utils.warn_sink_outside_hermes_home``): a resolved
   sink outside ``$HERMES_HOME`` emits ONE loud WARNING per init, fail-open
   (the sink keeps working). Inside → silent.
5. Plugin-init integration: a direct-config plugin with a sink outside
   ``$HERMES_HOME`` warns on init and still attaches (fail-open).
"""

import logging
import os
from pathlib import Path

import pytest

from _ps_test_isolation import PS_TEST_SINK_ENV, fake_home_env

from privacy_shield.audit import AuditLogger
from privacy_shield.config import PrivacyShieldConfig, load_config
from privacy_shield.log_utils import warn_sink_outside_hermes_home
from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.rotating_log import detach_rotating_handler


def _clear_audit_pins(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("PRIVACY_SHIELD_AUDIT_LOG_PATH", "PRIVACY_SHIELD_AUDIT_JSONL_PATH"):
        monkeypatch.delenv(var, raising=False)


class TestHermesHomeDefaultResolution:
    def test_default_follows_set_hermes_home(self, monkeypatch, tmp_path):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        _clear_audit_pins(monkeypatch)

        cfg = load_config()

        assert cfg.audit_log_path == str(hermes_home / "privacy-shield.log")
        assert cfg.audit_jsonl_path == str(
            hermes_home / "privacy-shield-audit.jsonl"
        )
        assert "~" not in cfg.audit_log_path
        assert "~" not in cfg.audit_jsonl_path

    def test_default_follows_home_when_hermes_home_unset(self, monkeypatch, tmp_path):
        home = tmp_path / "home"
        (home / ".hermes").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("HERMES_HOME", raising=False)
        _clear_audit_pins(monkeypatch)

        cfg = load_config()

        assert cfg.audit_log_path == str(home / ".hermes" / "privacy-shield.log")
        assert cfg.audit_jsonl_path == str(
            home / ".hermes" / "privacy-shield-audit.jsonl"
        )


class TestExplicitPinWins:
    def test_config_yaml_pin_wins_over_default(self, monkeypatch, tmp_path):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        pin = tmp_path / "pinned-op.log"
        (hermes_home / "config.yaml").write_text(
            "plugins:\n"
            "  entries:\n"
            "    privacy-shield:\n"
            f"      audit_log_path: {pin}\n"
        )
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        _clear_audit_pins(monkeypatch)

        cfg = load_config()

        assert cfg.audit_log_path == str(pin)
        # Unpinned sibling keeps Issue-#9 fleet-root default.
        assert cfg.audit_jsonl_path == str(
            hermes_home / "privacy-shield-audit.jsonl"
        )

    def test_env_pin_wins_over_config_yaml_merge(self, monkeypatch, tmp_path):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        merge_pin = tmp_path / "merge-pin.log"
        env_pin = tmp_path / "env-pin.log"
        (hermes_home / "config.yaml").write_text(
            "plugins:\n"
            "  entries:\n"
            "    privacy-shield:\n"
            f"      audit_log_path: {merge_pin}\n"
        )
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", str(env_pin))
        monkeypatch.delenv("PRIVACY_SHIELD_AUDIT_JSONL_PATH", raising=False)

        cfg = load_config()

        assert cfg.audit_log_path == str(env_pin)
        assert cfg.audit_log_path != str(merge_pin)


class TestWarnGuard:
    def _fresh_home(self, monkeypatch, tmp_path) -> Path:
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        return hermes_home

    def test_fires_outside_hermes_home(self, monkeypatch, tmp_path, caplog):
        self._fresh_home(monkeypatch, tmp_path)
        outside = tmp_path / "elsewhere" / "ps-op.log"
        outside.parent.mkdir(parents=True)

        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            warned = warn_sink_outside_hermes_home(outside, sink="audit-log")

        assert warned is True
        assert "OUTSIDE" in caplog.text
        assert str(outside) in caplog.text

    def test_silent_inside_hermes_home(self, monkeypatch, tmp_path, caplog):
        home = self._fresh_home(monkeypatch, tmp_path)
        inside = home / "workspace" / "ps-op.log"

        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            warned = warn_sink_outside_hermes_home(inside, sink="audit-log")

        assert warned is False
        assert caplog.text == ""

    def test_fires_when_test_sink_base_set_but_outside_hermes_home(
        self, monkeypatch, tmp_path, caplog
    ):
        """The guard stays active in test-capable environments: only the
        path's own location decides (conftest places sinks under the fake
        home so suite runs stay silent without weakening production
        semantics)."""
        self._fresh_home(monkeypatch, tmp_path)
        outside = tmp_path / "elsewhere" / "ps-op.log"
        outside.parent.mkdir(parents=True)
        assert PS_TEST_SINK_ENV in os.environ  # conftest session contract

        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            warned = warn_sink_outside_hermes_home(outside, sink="audit-log")

        assert warned is True


class TestPluginInitWarnGuardIntegration:
    def test_direct_config_outside_hermes_home_warns_and_fails_open(
        self, monkeypatch, tmp_path, caplog
    ):
        home, _ = fake_home_env(Path(os.environ[PS_TEST_SINK_ENV]))
        monkeypatch.setenv("HERMES_HOME", str(home))
        sink_base = Path(os.environ[PS_TEST_SINK_ENV])
        outside_log = sink_base / "issue9-warn-guard.log"

        cfg = PrivacyShieldConfig(
            storage_mode="memory",  # PS-MAPPER-004: no key in test env
        )
        cfg.audit_log_path = str(outside_log)
        cfg.audit_jsonl_path = str(
            sink_base / "issue9-warn-guard.jsonl"
        )

        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            plugin = PrivacyShieldPlugin(config=cfg)

        assert "OUTSIDE" in caplog.text
        assert plugin is not None

    def test_direct_config_inside_hermes_home_stays_silent(
        self, monkeypatch, tmp_path, caplog
    ):
        sink_base = Path(os.environ[PS_TEST_SINK_ENV])
        home, _ = fake_home_env(sink_base)
        monkeypatch.setenv("HERMES_HOME", str(home))
        home.mkdir(parents=True, exist_ok=True)

        cfg = PrivacyShieldConfig(
            storage_mode="memory",  # PS-MAPPER-004: no key in test env
        )
        cfg.audit_log_path = str(home / "issue9-inside.log")
        cfg.audit_jsonl_path = str(
            home / "issue9-inside.jsonl"
        )

        with caplog.at_level(
            logging.WARNING, logger="privacy_shield.plugin"
        ):
            plugin = PrivacyShieldPlugin(config=cfg)

        assert caplog.text == ""
        assert plugin is not None


class TestAuditLoggerFallback:
    """Wave-2 F1 (seraph t_af81f106): AuditLogger's no-arg fallback.

    dashboard/plugin_api.py calls ``AuditLogger()`` without a path. The
    fallback must resolve under ``$HERMES_HOME`` like ``load_config``'s
    audit_jsonl_path default — never the legacy ``profiles/default`` claim
    (Issue #9 single-identity contract).
    """

    def test_no_arg_fallback_under_set_hermes_home(self, monkeypatch, tmp_path):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))

        logger_ = AuditLogger()

        assert logger_.log_path == hermes_home / "privacy-shield-audit.jsonl"

    def test_no_arg_fallback_home_when_hermes_home_unset(
        self, monkeypatch, tmp_path
    ):
        home = tmp_path / "home"
        (home / ".hermes").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("HERMES_HOME", raising=False)

        logger_ = AuditLogger()

        assert logger_.log_path == home / ".hermes" / "privacy-shield-audit.jsonl"

    def test_explicit_log_path_wins_over_fallback(self, monkeypatch, tmp_path):
        pinned = tmp_path / "pinned.jsonl"
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))

        logger_ = AuditLogger(pinned)

        assert logger_.log_path == tmp_path / "pinned.jsonl"

    def test_noarg_fallback_matches_load_config_default(self, monkeypatch, tmp_path):
        hermes_home = tmp_path / "hermes"
        hermes_home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(hermes_home))
        _clear_audit_pins(monkeypatch)

        cfg = load_config()

        assert AuditLogger().log_path == Path(cfg.audit_jsonl_path)
        assert "profiles/default" not in str(AuditLogger().log_path)
