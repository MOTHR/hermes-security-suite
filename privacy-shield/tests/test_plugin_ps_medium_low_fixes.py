"""Regression tests for the open MEDIUM/LOW audit findings in plugin.py.

Coverage contract (audit Run-1, PR #17 follow-up):

- PS-CHANNEL-007: ``cron`` must not be restored by default. Cron output may
  egress to shared logs, webhooks or files rather than the user, so restoring
  PII on the cron channel requires an explicit operator opt-in via
  ``restore_allowed_channels``.
- PS-MAPPER-004: an ENABLED plugin in ``disk`` storage mode without an
  ``encryption_key`` must fail closed (RuntimeError) instead of silently
  falling back to an in-memory mapping table that loses all mappings on
  restart. Disabled configs keep the legitimate graceful path.
"""

from __future__ import annotations

import pytest

from privacy_shield.config import PrivacyShieldConfig, _default_restore_channels
from privacy_shield.mapping_table import InMemoryMappingTable, MappingTable
from privacy_shield.plugin import PrivacyShieldPlugin
from tests.test_post_llm_call_output_scanning import _seed_session_with_token

_KEY = "test-key-32-bytes-xxxxxxxxxxxxx"


def _pass_miss(monkeypatch) -> None:
    """Force _default_restore_channels down the bare-list fallback."""
    monkeypatch.delenv("PRIVACY_SHIELD_RESTORE_CHAT_ID", raising=False)
    monkeypatch.setattr(
        "privacy_shield.config._resolve_pass_binary", lambda: None
    )


class TestPSChannel007CronDefault:
    """PS-CHANNEL-007 — cron channel not user-facing by default."""

    def test_cron_not_restored_with_default_channels(self, monkeypatch):
        """Attack path: cron job processes PII bearing prompts and egresses to
        a log/webhook. With default channels, tokens must stay pseudonymised
        (restore skipped) — previously the bare default list contained cron."""
        _pass_miss(monkeypatch)
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key=_KEY,
            storage_mode="memory",
            restore_allowed_channels=_default_restore_channels(),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-cron-default", original=original
        )
        restored = plugin.post_llm_response(
            f"Mail an {token} gesendet.",
            session_id="sess-cron-default",
            target_channel="cron",
        )
        assert original not in restored, (
            "PS-CHANNEL-007 violated: PII restored on cron channel with "
            "default restore whitelist"
        )
        assert token in restored, "token must stay pseudonymised on cron"

    def test_telegram_still_restored_with_default_channels(self, monkeypatch):
        """Positive: the legit interactive surfaces keep restoring."""
        _pass_miss(monkeypatch)
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key=_KEY,
            storage_mode="memory",
            restore_allowed_channels=_default_restore_channels(),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-tg-default", original=original
        )
        restored = plugin.post_llm_response(
            f"Mail an {token} gesendet.",
            session_id="sess-tg-default",
            target_channel="telegram",
        )
        assert original in restored, "bare telegram restore must keep working"
        assert "TOKEN_" not in restored


class TestPSMapper004DiskWithoutKey:
    """PS-MAPPER-004 — disk mode without encryption_key fails closed."""

    def test_enabled_disk_mode_without_key_raises(self):
        """The audited misconfiguration must fail with a loud error instead of
        silently degrading to a lossy in-memory mapping table."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            storage_mode="disk",
            encryption_key="",
        )
        with pytest.raises(RuntimeError, match="disk.*requires.*encryption_key"):
            PrivacyShieldPlugin(config=config)

    def test_disabled_disk_mode_without_key_stays_graceful(self):
        """Legitimate load path preserved: load_config sets enabled=False when
        no key resolves; constructing the plugin must not crash Hermes init
        and yields an inert in-memory backend."""
        config = PrivacyShieldConfig(
            enabled=False,
            mode="limited",
            storage_mode="disk",
            encryption_key="",
        )
        plugin = PrivacyShieldPlugin(config=config)
        assert isinstance(plugin.mapper, InMemoryMappingTable)

    def test_disk_mode_with_key_builds_persistent_table(self, tmp_path):
        """Positive: properly configured disk mode still maps to the
        persistent, encrypted MappingTable."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key=_KEY,
            storage_mode="disk",
            storage_path=str(tmp_path / "mappings.db"),
        )
        plugin = PrivacyShieldPlugin(config=config)
        assert isinstance(plugin.mapper, MappingTable)
        plugin.mapper.close()