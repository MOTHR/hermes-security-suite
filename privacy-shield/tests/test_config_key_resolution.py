"""Key resolution + pass-binary hardening regression tests.

Key loading moved to the Hermes secret scope (v1.9.0, plugin.yaml
``requires_env: [PRIVACY_SHIELD_KEY]``): the plugin resolves the value via
``agent.secret_scope.get_secret`` and must not read ``os.environ`` or invoke
the ``pass`` binary itself. The ``pass`` binary resolution hardening
(C-001/H-002) stays covered — it is still used for the restore chat-id lookup
(``hermes/telegram/chat_id``).
"""

from __future__ import annotations

import os
import pwd
import stat
import sys

import pytest

import privacy_shield.config as ps_config
from privacy_shield import config
from privacy_shield.config import _load_key_via_hermes, _resolve_pass_binary


class TestHermesSecretScopeKey:
    """Key comes from agent.secret_scope.get_secret('PRIVACY_SHIELD_KEY')."""

    def _patch_secret_scope_module(self, monkeypatch, value):
        """Inject a fake agent.secret_scope module — CI has no Hermes core."""
        import types

        agent_pkg = types.ModuleType("agent")
        agent_pkg.__path__ = []
        ss_mod = types.ModuleType("agent.secret_scope")
        ss_mod.get_secret = lambda name, default=None: value
        agent_pkg.secret_scope = ss_mod
        monkeypatch.setitem(sys.modules, "agent", agent_pkg)
        monkeypatch.setitem(sys.modules, "agent.secret_scope", ss_mod)

    def test_secret_scope_key_loading(self, monkeypatch):
        self._patch_secret_scope_module(monkeypatch, "scoped-key")
        assert _load_key_via_hermes() == "scoped-key"

    def test_secret_scope_key_missing(self, monkeypatch):
        self._patch_secret_scope_module(monkeypatch, None)
        assert _load_key_via_hermes() is None

    def test_secret_scope_unavailable_returns_none(self, monkeypatch):
        """Outside Hermes (standalone CLI/tests) the import fails cleanly."""
        monkeypatch.setitem(sys.modules, "agent", None)
        monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
        assert _load_key_via_hermes() is None

    def test_plugin_does_not_read_os_environ(self, monkeypatch):
        """Review demand: no bare ``os.environ[PRI...]`` read for the key."""
        monkeypatch.setenv("PRIVACY_SHIELD_KEY", "from-env")
        monkeypatch.setitem(sys.modules, "agent", None)
        monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
        assert _load_key_via_hermes() is None  # env var must NOT be picked up

    def test_load_config_uses_secret_scope(self, monkeypatch):
        monkeypatch.setattr(ps_config, "_load_key_via_hermes", lambda: "cfg-key")
        monkeypatch.delenv("PRIVACY_SHIELD_KEY_FILE", raising=False)
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        cfg = config.load_config()
        assert cfg.encryption_key == "cfg-key"

    def test_load_config_key_file_fallback(self, monkeypatch, tmp_path):
        monkeypatch.setattr(ps_config, "_load_key_via_hermes", lambda: None)
        key_file = tmp_path / "key"
        key_file.write_text("file-key\n")
        # W2-3 gate: the fallback refuses group/other-accessible key files.
        key_file.chmod(0o600)
        monkeypatch.setenv("PRIVACY_SHIELD_KEY_FILE", str(key_file))
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        cfg = config.load_config()
        assert cfg.encryption_key == "file-key"

    def test_load_config_key_file_insecure_permissions_refused(self, monkeypatch, tmp_path):
        """Orakel W2-3: a world-readable key file must be refused, not loaded."""
        monkeypatch.setattr(ps_config, "_load_key_via_hermes", lambda: None)
        key_file = tmp_path / "key"
        key_file.write_text("file-key\n")
        key_file.chmod(0o644)
        monkeypatch.setenv("PRIVACY_SHIELD_KEY_FILE", str(key_file))
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        cfg = config.load_config()
        assert cfg.encryption_key == ""


# ---------------------------------------------------------------------------
# pass-binary hardening (C-001/H-002) — still used by restore chat-id lookup
# ---------------------------------------------------------------------------


def _write_stub(binary, payload="fallback-key"):
    binary.write_text(f"#!/bin/sh\necho {payload}\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)


class TestPassBinaryHardening:
    """Adversarial tests for C-001/H-002 (HOME-hijacking / symlink tampering)."""

    @pytest.fixture(autouse=True)
    def _isolate_pass_on_path(self, tmp_path, monkeypatch):
        # No pass anywhere on PATH: force the fallback path under test.
        monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))

    def test_c001_home_hijack_executes_nothing(self, tmp_path, monkeypatch):
        """PoC from Agent-Smith: HOME=/tmp/evil with fake binary → not executed."""
        evil = tmp_path / "evil"
        (evil / ".local" / "bin").mkdir(parents=True)
        evil_pass = evil / ".local" / "bin" / "pass"
        evil_pass.write_text('#!/bin/sh\necho "pwned-key"\n')
        evil_pass.chmod(evil_pass.stat().st_mode | stat.S_IXUSR)

        marker = tmp_path / "exec-marker"
        evil_pass.write_text(
            f"#!/bin/sh\ntouch {marker}\necho pwned-key\n"
        )
        evil_pass.chmod(evil_pass.stat().st_mode | stat.S_IXUSR)

        monkeypatch.setenv("HOME", str(evil))

        assert not marker.exists(), "attacker binary was executed"
        assert _resolve_pass_binary() is None

    def test_fallback_uses_pwd_home_not_env_home(self, tmp_path, monkeypatch):
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        _write_stub(local_bin / "pass")

        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(
            pwd, "getpwuid", lambda uid: _FakePwd(), raising=False
        )
        monkeypatch.setenv("HOME", str(tmp_path / "hijacked"))
        assert str(local_bin) == str(config.Path.home() / ".local" / "bin")
        resolved = _resolve_pass_binary()
        assert resolved == str(local_bin / "pass")
        assert config.Path.home() != os.environ["HOME"]

    def test_rejects_binary_outside_whitelist(self, tmp_path, monkeypatch):
        unapproved = tmp_path / "unapproved"
        unapproved.mkdir()
        _write_stub(unapproved / "pass")
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _resolve_pass_binary() is None

    def test_h002_rejects_symlink_escaping_whitelist(self, tmp_path, monkeypatch):
        """Symlink at ~/.local/bin/pass pointing to attacker dir → rejected."""
        attacker_dir = tmp_path / "attacker"
        attacker_dir.mkdir()
        _write_stub(attacker_dir / "real-pass", payload="symlink-key")

        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        (local_bin / "pass").symlink_to(attacker_dir / "real-pass")
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _resolve_pass_binary() is None

    def test_h002_accepts_symlink_within_whitelist(self, tmp_path, monkeypatch):
        """A symlink that stays inside ~/.local/bin is legitimate."""
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        _write_stub(local_bin / "pass-1.9")
        (local_bin / "pass").symlink_to(local_bin / "pass-1.9")
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _resolve_pass_binary() == str(local_bin / "pass")

    def test_rejects_group_or_other_writable_binary(self, tmp_path, monkeypatch):
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        stub = local_bin / "pass"
        _write_stub(stub)
        stub.chmod(stub.stat().st_mode | stat.S_IWOTH)
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _resolve_pass_binary() is None

    def test_rejects_binary_owned_by_other_user(self, tmp_path, monkeypatch):
        if os.geteuid() == 0:
            pytest.skip("ownership check not testable as root")
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        stub = local_bin / "pass"
        _write_stub(stub)
        try:
            os.chown(stub, 65534, 65534)
        except PermissionError:
            pytest.skip("cannot chown to foreign uid without privileges")
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _resolve_pass_binary() is None

    def test_end_to_end_real_env_home_never_reaches_fallback(
        self, tmp_path, monkeypatch
    ):
        """The full Agent-Smith PoC: even with HOME fully hijacked, no
        attacker binary runs and no key is returned from it."""
        evil = tmp_path / "evil"
        (evil / ".local" / "bin").mkdir(parents=True)
        _write_stub(evil / ".local" / "bin" / "pass", payload="pwned-key")
        monkeypatch.setenv("HOME", str(evil))
        monkeypatch.delenv("PRIVACY_SHIELD_KEY_FILE", raising=False)
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        monkeypatch.setattr(
            ps_config, "_load_key_via_hermes", lambda: None
        )

        # getpwuid untouched: the real user home is outside the fake whitelist
        # patched below, so the fallback must resolve to None.
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))
        cfg = config.load_config()
        assert cfg.encryption_key != "pwned-key"
        assert _resolve_pass_binary() is None
