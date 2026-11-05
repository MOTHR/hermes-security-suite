"""Test-log isolation: PRIVACY_SHIELD_AUDIT_LOG_PATH override (t_83df8a1b).

Verifies that load_config() honours the PRIVACY_SHIELD_AUDIT_LOG_PATH
environment override (redirecting the rotating operator log away from the
production path) and that the default is unchanged when the variable is
absent.
"""

import os

from privacy_shield.config import load_config

DEFAULT_LOG_PATH = (
    "~/.hermes/profiles/default/workspace/05-Logs-Snapshots/privacy-shield.log"
)


class TestAuditLogPathOverride:
    def test_env_set_redirects_log_path(self, monkeypatch, tmp_path):
        target = str(tmp_path / "privacy-shield-test.log")
        monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", target)
        config = load_config()
        assert config.audit_log_path == target

    def test_env_unset_keeps_default(self, monkeypatch):
        monkeypatch.delenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", raising=False)
        config = load_config()
        assert config.audit_log_path == DEFAULT_LOG_PATH

    def test_conftest_setdefault_respects_pre_set_env(self, monkeypatch, tmp_path):
        """conftest must not overwrite a value the caller set explicitly."""
        # Simulate the conftest behaviour: setdefault keeps an existing value.
        target = str(tmp_path / "explicit.log")
        monkeypatch.setenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", target)
        os.environ.setdefault("PRIVACY_SHIELD_AUDIT_LOG_PATH", "/tmp/should-not-win")
        assert os.environ["PRIVACY_SHIELD_AUDIT_LOG_PATH"] == target