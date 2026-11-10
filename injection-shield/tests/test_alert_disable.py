"""Tests for the INJECTION_SHIELD_ALERT_DISABLE env flag (t_deb39cb0).

The eval-honesty-watcher replays functional_proof commands via
``bash -c``; those sub-sessions inherit a HERMES_HOME with
``telegram.enabled=true``. The flag silences ONLY the Telegram send —
detection and the audit-log entry must stay fully active.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from injection_shield.plugin import InjectionShieldPlugin

_VIOLATION_TEXT = "Here is the key: sk-abc123456789012345678"


@pytest.fixture
def plugin(tmp_path) -> InjectionShieldPlugin:
    p = InjectionShieldPlugin(profile="default")
    p.audit_log = tmp_path / "audit.log"
    p.mode = "audit"
    return p


def test_alert_disabled_via_env_returns_early(plugin: InjectionShieldPlugin, monkeypatch) -> None:
    """ENV=1 -> _alert_telegram returns before any requests.post call."""
    monkeypatch.setenv("INJECTION_SHIELD_ALERT_DISABLE", "1")
    with patch("requests.post") as mock_post:
        plugin._alert_telegram("🚨 test alert", [{"type": "credential_leak", "severity": "critical"}])
        mock_post.assert_not_called()


def test_alert_enabled_via_env_sends_normally(plugin: InjectionShieldPlugin, monkeypatch) -> None:
    """ENV unset -> alert path runs (send attempted when configured)."""
    monkeypatch.delenv("INJECTION_SHIELD_ALERT_DISABLE", raising=False)
    plugin.telegram_cfg = {"enabled": True, "chat_id": "12345", "min_severity": "medium"}
    monkeypatch.setenv("INJECTION_SHIELD_TELEGRAM_BOT_TOKEN", "test-token")
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        plugin._alert_telegram("🚨 test alert", [{"type": "credential_leak", "severity": "critical"}])
        assert mock_post.called


def test_alert_standalone_env_fallback_without_hermes(plugin: InjectionShieldPlugin, monkeypatch) -> None:
    """CI-fix regression: without a Hermes core (no `agent` module) the alert
    must resolve the plugin's OWN env var instead of aborting silently."""
    import sys

    monkeypatch.delenv("INJECTION_SHIELD_ALERT_DISABLE", raising=False)
    plugin.telegram_cfg = {"enabled": True, "chat_id": "12345", "min_severity": "medium"}
    monkeypatch.setenv("INJECTION_SHIELD_TELEGRAM_BOT_TOKEN", "standalone-token")
    monkeypatch.setitem(sys.modules, "agent", None)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", None)
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        plugin._alert_telegram("🚨 test alert", [{"type": "credential_leak", "severity": "critical"}])
        assert mock_post.called
        assert "standalone-token" in mock_post.call_args.args[0]


def test_audit_log_still_written_when_alert_disabled(plugin: InjectionShieldPlugin, monkeypatch) -> None:
    """ENV=1 -> post_llm_call still writes the audit entry (detection intact).

    Asserts the invariant — an audit entry with a violation was written —
    not the specific violation type: detector classification of the probe
    text may change as detectors evolve (it drifted from credential_leak to
    injection on main after the 2026-10 detector updates).
    """
    monkeypatch.setenv("INJECTION_SHIELD_ALERT_DISABLE", "1")
    plugin.mode = "audit"
    plugin.post_llm_call({"text": _VIOLATION_TEXT})
    log = plugin.audit_log.read_text()
    assert '"layer": "post_llm_call"' in log
    assert '"violations": [{' in log