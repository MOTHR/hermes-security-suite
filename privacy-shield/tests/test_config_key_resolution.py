"""Regression tests for launchd PATH robustness of pass-store key loading.

Reproduces the gateway bug: under launchd, ~/.local/bin is often missing
from PATH, so a bare ``pass`` invocation raised FileNotFoundError and the
plugin fell back to workshop mode. The binary must now be resolved via
``shutil.which("pass")`` with a filesystem fallback to ``~/.local/bin/pass``.

C-001/H-002 hardening (Agent-Smith review): the fallback must NOT trust the
``HOME`` environment variable, must reject binaries outside the whitelist
directories, binaries owned by another user, group/other-writable binaries,
and symlinked binaries pointing outside the whitelist.
"""

from __future__ import annotations

import os
import pwd
import stat

import pytest

from privacy_shield import config
from privacy_shield.config import _load_key_from_pass, _resolve_pass_binary


@pytest.fixture
def fake_pass(tmp_path, monkeypatch):
    """Create a stub pass binary and a PATH that excludes ~/.local/bin."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = (
        "#!/bin/sh\n"
        'if [ "$1" = "show" ] && [ "$2" = "hermes/privacy-shield-key" ]; then\n'
        '    echo "stub-key-from-pass"\n'
        "    exit 0\n"
        "fi\n"
        "exit 1\n"
    )
    pass_bin = bin_dir / "pass"
    pass_bin.write_text(script)
    pass_bin.chmod(pass_bin.stat().st_mode | stat.S_IXUSR)

    # PATH without ~/.local/bin — simulates the launchd gateway environment.
    monkeypatch.setenv("PATH", str(bin_dir))
    return pass_bin


def _write_stub(binary, payload="fallback-key"):
    binary.write_text(f"#!/bin/sh\necho {payload}\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)


class TestPassPathFallback:
    def test_resolves_via_shutil_which(self, fake_pass):
        key = _load_key_from_pass()
        assert key == "stub-key-from-pass"

    def test_falls_back_to_local_bin_when_absent_from_path(
        self, tmp_path, monkeypatch
    ):
        # No pass anywhere on PATH, but a working binary at the fallback path
        # (resolved via getpwuid home, NOT the HOME env var).
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        _write_stub(local_bin / "pass")

        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        monkeypatch.setenv("HOME", str(tmp_path / "hijacked"))
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        key = _load_key_from_pass()
        assert key == "fallback-key"

    def test_returns_none_when_no_pass_at_all(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
        assert _load_key_from_pass() is None

    def test_load_config_prefers_pass_key(self, fake_pass, monkeypatch):
        monkeypatch.delenv("PRIVACY_SHIELD_KEY", raising=False)
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        cfg = config.load_config()
        assert cfg.encryption_key == "stub-key-from-pass"


def test_module_path_env_independent(monkeypatch, tmp_path):
    """Sanity: _load_key_from_pass must not rely on sys.path-side effects."""
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))

    class _FakePwd:
        pw_dir = str(tmp_path / "nonexistent-home")

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: _FakePwd(), raising=False)
    assert _load_key_from_pass() is None


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
        key = _load_key_from_pass()

        assert key != "pwned-key"
        assert not marker.exists(), "attacker binary was executed"
        assert _resolve_pass_binary() is None

    def test_fallback_uses_pwd_home_not_env_home(self, tmp_path, monkeypatch):
        """Legit binary under the real (getpwuid) home still works, even with
        a hostile HOME pointing elsewhere."""
        local_bin = tmp_path / ".local" / "bin"
        local_bin.mkdir(parents=True)
        _write_stub(local_bin / "pass")

        real_home = pwd.getpwuid(os.getuid()).pw_dir
        # Whitelist must contain the REAL home bin dir; patch Path.home
        # so the test does not depend on where this checkout lives.
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))
        # But getpwuid returns the real home — so instead run the stub there?
        # No: keep the test fully hermetic. Patch getpwuid instead of relying
        # on it, and verify _resolve_pass_binary resolves via the whitelist.
        class _FakePwd:
            pw_dir = str(tmp_path)

        monkeypatch.setattr(
            pwd, "getpwuid", lambda uid: _FakePwd(), raising=False
        )
        monkeypatch.setenv("HOME", str(tmp_path / "hijacked"))
        # tmp_path/.local/bin is the whitelist parent under the patched home.
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
        assert _load_key_from_pass() is None

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
        """A symlink that stays inside ~/.local/bin (e.g. to a versioned
        binary in the same dir) is legitimate and must keep working."""
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
        # Simulate a foreign owner by chowning to nobody (uid -2 on macOS,
        # 65534 on Linux) — may require privileges; skip if it fails.
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
        """The full Agent-Smith PoC against load_config: even with HOME fully
        hijacked, no attacker binary runs and no key is returned from it."""
        evil = tmp_path / "evil"
        (evil / ".local" / "bin").mkdir(parents=True)
        _write_stub(evil / ".local" / "bin" / "pass", payload="pwned-key")
        monkeypatch.setenv("HOME", str(evil))
        monkeypatch.delenv("PRIVACY_SHIELD_KEY", raising=False)

        class _FakePwd:
            pw_dir = pwd.getpwuid(os.getuid()).pw_dir

        # getpwuid untouched: the real user home is outside the fake whitelist
        # patched below, so the fallback must resolve to None.
        monkeypatch.setattr(config.Path, "home", staticmethod(lambda: tmp_path))
        cfg = config.load_config()
        assert cfg.encryption_key != "pwned-key"
        assert _resolve_pass_binary() is None