"""Issue #8 (t_70e1ea18): suite-level test-log isolation regression.

The old conftest relied on ``setdefault`` BEFORE any attach context the
tests built themselves — empirically insufficient (orakel t_f0434d31):
the operator-log leak happens at plugin-INIT, not at import, and the
idempotent first-attach freeze locks whatever path ran first. These
tests assert the WHOLE-RUN contracts:

1. conftest Layer-1: fake HOME/HERMES_HOME redirect + hard-set sink
   paths (+ TEST_SINK_BASE) + ambient scrub,
2. Layer-2 in-package attach guard (fail-closed at ``PRIVACY_SHIELD_
   TEST_SINK_BASE``),
3. Layer-3 autouse assertion helper flags out-of-base rotating handlers,
4. B1 direct-config sites use deliberate tmp-based sinks,
5. JSONL ``AuditLogger`` init behaviour (mkdir/chmod at init).
"""

import logging
import logging.handlers
import os
import stat
from pathlib import Path

import pytest

from _ps_test_isolation import (
    AMBIENT_SCRUB_VARS,
    ISOLATED_ENV_VARS,
    PS_TEST_SINK_ENV,
    apply_test_isolation,
    assert_rotating_handlers_inside,
    fake_home_env,
    set_direct_config_sinks,
)

from privacy_shield.config import PrivacyShieldConfig, load_config
from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.rotating_log import attach_rotating_handler, detach_rotating_handler
from privacy_shield.audit import AuditLogger


def _sink_base() -> Path:
    return Path(os.environ[PS_TEST_SINK_ENV])


class TestConftestIsolationLayer:
    """Layer-1: the conftest hard-sets the isolation, never setdefault."""

    def test_sink_base_published_under_pytest_tmp(self, tmp_path_factory):
        base = _sink_base()
        assert base.is_relative_to(tmp_path_factory.getbasetemp())

    def test_both_sink_paths_hard_set_under_base(self):
        sink = _sink_base()
        for var in (
            "PRIVACY_SHIELD_AUDIT_LOG_PATH",
            "PRIVACY_SHIELD_AUDIT_JSONL_PATH",
        ):
            assert var in os.environ
            assert Path(os.environ[var]).is_relative_to(sink)

    def test_home_and_hermes_home_redirected_to_fake_tree(self):
        home, hermes_home = fake_home_env(_sink_base())
        assert Path(os.environ["HOME"]) == home
        assert Path(os.environ["HERMES_HOME"]) == hermes_home
        assert hermes_home == home / ".hermes"

    def test_ambient_env_vars_scrubbed(self):
        # Ambient doctor-channel leftovers must not survive the conftest
        # scrub (B3): the tests below re-set what they need via monkeypatch.
        leftovers = [var for var in AMBIENT_SCRUB_VARS if var in os.environ]
        assert leftovers == []

    def test_restore_chat_id_dummy_set(self):
        # Dataclass-default factory must never shell the pass secret store
        # from tests — the conftest pins a dummy chat id instead.
        assert os.environ.get("PRIVACY_SHIELD_RESTORE_CHAT_ID") == "0-test-fixture"

    def test_hard_set_overrides_pre_set_ambient(self, monkeypatch, tmp_path):
        """Design change vs t_83df8a1b (orakel K6): conftest is the
        isolation authority — a caller-pre-set ambient value is
        intentionally overridden, not respected. Test-scoped values go
        through monkeypatch, never through ambient env."""
        monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", "/tmp/ambient-must-not-win")
        # Snapshot: the hard-set mutates env beyond monkeypatch's keys — the
        # session-level values must be restored for the following tests.
        env_before = {k: os.environ.get(k) for k in ISOLATED_ENV_VARS}
        try:
            sink = apply_test_isolation(tmp_path)
            # Issue #9: the hard-set sinks live under the fake hermes home
            # (inside the sink base) so the warn-guard treats the test
            # deployment like a production pin.
            _, hermes_home = fake_home_env(sink)
            assert os.environ["PRIVACY_SHIELD_AUDIT_LOG_PATH"] == str(
                hermes_home / "05-Logs-Snapshots" / "privacy-shield-test.log"
            )
            assert os.environ["PRIVACY_SHIELD_AUDIT_LOG_PATH"] != "/tmp/ambient-must-not-win"
        finally:
            for key, value in env_before.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


class TestAttachGuardLayer:
    """Layer-2: in-package fail-closed guard at plugin attach time."""

    def test_guard_rejects_path_outside_sink_base(self, monkeypatch, tmp_path):
        monkeypatch.setenv(PS_TEST_SINK_ENV, str(tmp_path))
        outside = tmp_path.parent / "ps-outside-leak.log"
        with pytest.raises(RuntimeError):
            attach_rotating_handler(str(outside))
        assert not outside.exists()

    def test_guard_allows_path_inside_sink_base(self, monkeypatch, tmp_path):
        monkeypatch.setenv(PS_TEST_SINK_ENV, str(tmp_path))
        target = tmp_path / "guard-allowed.log"
        detach_rotating_handler()
        try:
            handler = attach_rotating_handler(str(target))
            assert Path(handler.baseFilename).resolve() == target.resolve()
        finally:
            detach_rotating_handler()

    def test_guard_absent_keeps_production_attach_behaviour(
        self, monkeypatch, tmp_path
    ):
        # Production runs never see PRIVACY_SHIELD_TEST_SINK_BASE — the
        # guard must not change the default attach path then (Kontra:
        # Produktionsverhalten sichern).
        monkeypatch.delenv(PS_TEST_SINK_ENV, raising=False)
        target = tmp_path / "prod-style.log"
        detach_rotating_handler()
        try:
            handler = attach_rotating_handler(str(target))
            assert Path(handler.baseFilename).resolve() == target.resolve()
        finally:
            detach_rotating_handler()


class TestSinkAssertionLayer:
    """Layer-3: function-scoped autouse assertion over every attached
    rotating handler (Regression statt silent)."""

    def test_assertion_flags_rotating_handler_outside_base(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        logger = logging.getLogger("privacy_shield.selftest")
        inside = logging.handlers.RotatingFileHandler(str(base / "in.log"))
        try:
            logger.addHandler(inside)
            # Spoof an offender without touching any file outside tmp.
            outside = tmp_path.parent / "spoofed-outside.log"
            inside.baseFilename = str(outside)
            offenders = assert_rotating_handlers_inside(base)
            assert offenders == [f"privacy_shield.selftest: {outside}"]
        finally:
            logger.removeHandler(inside)
            inside.close()

    def test_assertion_passes_for_compliant_handlers(self, tmp_path):
        base = tmp_path / "base2"
        base.mkdir()
        logger = logging.getLogger("privacy_shield.selftest.compliant")
        inside = logging.handlers.RotatingFileHandler(str(base / "ok.log"))
        try:
            logger.addHandler(inside)
            assert assert_rotating_handlers_inside(base) == []
        finally:
            logger.removeHandler(inside)
            inside.close()


class TestDirectConfigSites:
    """B1 regression: direct-config plugin construction must use
    deliberate tmp-based sinks (env-blind dataclass defaults + the
    idempotent first-attach freeze are the leak mechanics)."""

    def test_direct_config_sinks_are_deliberate(self, tmp_path):
        sink = _sink_base()
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="x" * 64,
            storage_mode="memory",
        )
        set_direct_config_sinks(config, "issue8-direct")
        assert Path(config.audit_log_path).is_relative_to(sink)
        assert Path(config.audit_jsonl_path).is_relative_to(sink)
        plugin = PrivacyShieldPlugin(config=config)
        attach_rotating_handler(plugin.config.audit_log_path)  # guard must accept

    def test_direct_config_fails_closed_without_isolation(self, monkeypatch):
        monkeypatch.delenv(PS_TEST_SINK_ENV, raising=False)
        config = PrivacyShieldConfig(storage_mode="memory")
        with pytest.raises(RuntimeError):
            set_direct_config_sinks(config, "issue8-unisolated")

    def test_load_config_route_honours_hard_set_paths(self):
        config = load_config()
        sink = _sink_base()
        assert Path(config.audit_log_path).is_relative_to(sink)
        assert Path(config.audit_jsonl_path).is_relative_to(sink)


class TestJsonlInitBehaviour:
    """Layer-6: JSONL sink is created (mkdir+chmod) at INIT time, not
    lazily — the fake HOME must cover the default route, and explicit
    tmp paths must work identically."""

    def test_jsonl_default_expands_into_fake_home(self):
        config = PrivacyShieldConfig()
        audit = AuditLogger(config.audit_jsonl_path)
        _, hermes_home = fake_home_env(_sink_base())
        assert audit.log_path.is_relative_to(hermes_home)
        assert audit.log_path.parent.is_dir()

    def test_jsonl_default_dir_is_chmod_700(self):
        config = PrivacyShieldConfig()
        audit = AuditLogger(config.audit_jsonl_path)
        mode = stat.S_IMODE(os.stat(audit.log_path.parent).st_mode)
        assert mode == 0o700

    def test_jsonl_explicit_tmp_path_dir_created_700(self, tmp_path):
        audit = AuditLogger(str(tmp_path / "issue8-audit.jsonl"))
        assert audit.log_path.parent == tmp_path
        assert audit.log_path.parent.is_dir()
        mode = stat.S_IMODE(os.stat(audit.log_path.parent).st_mode)
        assert mode == 0o700
