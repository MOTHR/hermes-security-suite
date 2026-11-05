"""Channel matching for token restoration (fix 2026-09-19).

Regression contract: the gateway delivers bare platform names as
``platform``/``target_channel`` ("telegram", "desktop", "cli"), while config
entries may be scoped ("telegram:1234567890"). Before the fix, a bare delivery
never matched a scoped entry — restoration skipped on EVERY channel and the
user saw ``TOKEN_*`` instead of plaintext (0 restores across all profiles).

Matching rules under test:
- exact match wins;
- a bare configured entry matches a bare delivery of that platform;
- a scoped ``telegram:<id>``-only configuration does NOT restore a bare
  ``telegram`` delivery (fail-closed, operator pinned to one chat);
- a scoped ``telegram:<id>`` configuration DOES restore a scoped delivery of
  the same id;
- unknown platforms stay blocked.
"""

from __future__ import annotations

import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin
from tests.test_post_llm_call_output_scanning import _seed_session_with_token


class TestChannelAllowed:
    @pytest.mark.parametrize(
        ("target", "allowed", "expected"),
        [
            # Exact match wins.
            ("desktop", ("desktop", "cli"), True),
            ("cli", ("desktop", "cli"), True),
            # Bare delivery of a platform that also has a bare entry.
            ("telegram", ("telegram:1234567890", "telegram", "desktop"), True),
            ("telegram:1234567890", ("telegram:1234567890", "telegram"), True),
            # FAIL-CLOSED: bare telegram delivery vs scoped-only configuration.
            ("telegram", ("telegram:1234567890",), False),
            ("telegram:999", ("telegram:1234567890",), False),
            # Unknown / empty channels stay blocked.
            ("", ("telegram", "desktop", "cli"), False),
            ("kanban", ("telegram", "desktop", "cli"), False),
            ("write_file", ("telegram", "desktop", "cli"), False),
            # Scoped delivery of another chat does not inherit the bare entry
            # match for a DIFFERENT id — but its platform part still matches a
            # bare configured entry.
            ("telegram:999", ("telegram:1234567890", "telegram"), True),
        ],
    )
    def test_channel_allowed(self, target, allowed, expected):
        assert PrivacyShieldPlugin._channel_allowed(target, allowed) is expected

    def test_restoration_runs_for_bare_desktop_channel(self):
        """The observed regression: bare 'desktop' delivery restores tokens."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            restore_allowed_channels=("desktop", "cli"),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(plugin, session_id="sess-fix", original=original)
        restored = plugin.post_llm_response(
            f"Mail an {token} gesendet.", session_id="sess-fix", target_channel="desktop",
        )
        assert original in restored, f"bare desktop restore failed: {restored!r}"
        assert "TOKEN_" not in restored

    def test_restoration_runs_for_bare_telegram_delivery_with_scoped_config(self):
        """Bare 'telegram' delivery (gateway form) matches when both the scoped
        chat entry AND a bare telegram entry are configured (our profile sweep)."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            restore_allowed_channels=("telegram:1234567890", "telegram", "desktop", "cli"),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(plugin, session_id="sess-tg", original=original)
        restored = plugin.post_llm_response(
            f"Mail an {token} gesendet.", session_id="sess-tg", target_channel="telegram",
        )
        assert original in restored, f"bare telegram restore failed: {restored!r}"

    def test_restoration_skips_for_disallowed_channel(self):
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            restore_allowed_channels=("desktop",),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(plugin, session_id="sess-skip", original=original)
        result = plugin.post_llm_response(
            f"Mail an {token} gesendet.", session_id="sess-skip", target_channel="kanban",
        )
        assert token in result, "token must stay pseudonymised on disallowed channels"

    def test_restoration_runs_for_cron_platform(self):
        """Cron stamps platform=\"cron\" while delivering the final response to
        the user (telegram/origin). Without ``cron`` in the whitelist, every
        scheduled delivery left raw TOKEN_* placeholders (2026-10-06)."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            restore_allowed_channels=("telegram", "desktop", "cli", "cron"),
        )
        plugin = PrivacyShieldPlugin(config=config)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(plugin, session_id="sess-cron", original=original)
        restored = plugin.post_llm_response(
            f"Mail an {token} gesendet.",
            session_id="sess-cron",
            target_channel="cron",
        )
        assert original in restored, f"cron restore failed: {restored!r}"
        assert "TOKEN_" not in restored

    def test_default_restore_channels_never_empty(self, monkeypatch):
        """Factory must always ship bare user-facing platforms — empty () made
        every profile without an explicit YAML override skip restoration.

        PS-CHANNEL-007: 'cron' must NOT be among the defaults — cron output
        may egress to logs/webhooks/files, so restoring PII there requires an
        explicit operator opt-in via ``restore_allowed_channels``."""
        monkeypatch.delenv("PRIVACY_SHIELD_RESTORE_CHAT_ID", raising=False)
        # Force the pass-store path to miss so we exercise the bare fallback.
        monkeypatch.setattr(
            "privacy_shield.config._resolve_pass_binary", lambda: None
        )
        from privacy_shield.config import _default_restore_channels

        channels = _default_restore_channels()
        assert channels, "default restore whitelist must never be empty"
        for required in ("telegram", "desktop", "cli"):
            assert required in channels, f"missing bare platform {required!r}"
        assert "cron" not in channels, (
            "PS-CHANNEL-007: 'cron' must not be restored by default — "
            "explicit operator opt-in required"
        )