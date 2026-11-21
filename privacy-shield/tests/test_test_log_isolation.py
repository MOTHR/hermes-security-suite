"""Test-log isolation: PRIVACY_SHIELD_AUDIT_LOG_PATH override (t_83df8a1b).

Verifies that load_config() honours the PRIVACY_SHIELD_AUDIT_LOG_PATH
environment override (redirecting the rotating operator log away from the
production path) and that the default is unchanged when the variable is
absent.
"""

import os
from pathlib import Path

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
        """Smith R2-blocker-3: load_config hands out EXPANDED paths — the
        literal-~ default never reaches a consumer cwd-relative."""
        monkeypatch.delenv("PRIVACY_SHIELD_AUDIT_LOG_PATH", raising=False)
        config = load_config()
        assert config.audit_log_path == os.path.expanduser(DEFAULT_LOG_PATH)
        assert "~" not in config.audit_log_path

    def test_conftest_hard_set_replaces_setdefault_semantics(self):
        """Issue #8 (orakel K6): the old contract 'setdefault keeps a
        pre-set value authoritative' is deliberately retired — probe B3
        proved ambient values survive setdefault into the attach path.
        The conftest is now the isolation authority and HARD-sets both
        sinks; test-local overrides go through monkeypatch and the ambient
        doctor channel is scrubbed outright. Behaviour coverage lives in
        test_suite_log_isolation.py (TestConftestIsolationLayer); this
        test guards against regressing the conftest back to setdefault."""
        conftest_src = Path(__file__).parent.joinpath("conftest.py").read_text()
        assert "os.environ.setdefault" not in conftest_src