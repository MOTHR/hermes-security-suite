"""Issue #5 regression tests — delegated-subagent transit corruption.

Issue comment (2026-11-18): a Hermes subagent delegation result was masked
in transit and partially NOT restored before the parent agent read it:

- ``STRONG REVIEWER``              → ``STRONG TOKEN_BIC_<hash>_017``
- ``ASYNC DELEGATION BATCH COMPLETE`` → ... ``TOKEN_BIC_<hash>_018``
- ``line 117``                     → ``line [maskiertes PII – nicht wiederherstellbar]``

Root causes in Privacy-Shield:

1. The gateway runs delegate subagents with ``platform=\"subagent\"``
   (delegate_tool.py).  ``subagent`` was not in the default
   ``restore_allowed_channels``, so the subagent's result kept its tokens
   when handed back to the parent agent — internal agent-to-agent transit
   is NOT provider egress and must behave like the kanban channel
   (v1.7.6 Decision 3): tokens are restorable there.
2. On the restore path, any unresolvable token was replaced with the
   destructive ``restore_miss_placeholder`` — content DESTROYED instead of
   tokenized-and-restored.  On delegation transit a restore miss must keep
   the token verbatim (lossless).

TEST-FIRST: these tests were written against 1.9.3 behaviour and fail
before the fix.
"""

import logging
import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin
from tests.test_post_llm_call_output_scanning import _seed_session_with_token

TEST_KEY = "test-key-32-bytes-xxxxxxxxxxxxx"


def _plugin(**overrides) -> PrivacyShieldPlugin:
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key=TEST_KEY,
        storage_mode="memory",
        **overrides,
    )
    return PrivacyShieldPlugin(config=config)


class TestDelegatedTransitRestore:
    """Delegation results must be restored before the parent reads them."""

    def test_subagent_channel_restores_tokens(self):
        """Gateway delivers subagent results with platform='subagent'.

        Contract: restoration runs on that channel — the parent agent must
        receive the original role labels, not ``TOKEN_BIC_*`` noise.
        """
        plugin = _plugin()
        session = "sess-subagent"
        token = _seed_session_with_token(
            plugin, session_id=session, original="DEUTDEFF", pii_type="bic",
        )
        restored = plugin.post_llm_response(
            f"STRONG {token} — ASYNC DELEGATION BATCH COMPLETE",
            session_id=session,
            target_channel="subagent",
        )
        assert "DEUTDEFF" in restored, f"transit restore failed: {restored!r}"
        assert "TOKEN_" not in restored

    def test_transit_channel_in_default_restore_channels(self):
        """'subagent' is a bare default (analogous to the kanban decision)."""
        from privacy_shield.config import _default_restore_channels

        assert "subagent" in _default_restore_channels()

    def test_transit_restore_uses_operator_allowlist_too(self):
        """Explicit operator allowlists keep working alongside the default."""
        plugin = _plugin(restore_allowed_channels=("telegram",))
        session = "sess-operator-allow"
        token = _seed_session_with_token(
            plugin, session_id=session, original="DEUTDEFF", pii_type="bic",
        )
        restored = plugin.post_llm_response(
            f"result with {token}", session_id=session, target_channel="subagent",
        )
        assert "DEUTDEFF" in restored


class TestDelegatedTransitLossless:
    """Restore misses on transit channels must be lossless, not destroying."""

    def test_restore_miss_keeps_token_verbatim_on_subagent(self):
        """'line 123'-style corruption: a token the mapping cannot resolve
        must NOT become '[maskiertes PII – nicht wiederherstellbar]' in
        internal transit — the content would be destroyed. Keep the token
        verbatim so the mapping (or a later session) can still resolve it."""
        plugin = _plugin()
        # Token deliberately unknown to the mapping: mint a syntactically
        # valid one after a real masking pass under a THROWAWAY session,
        # then replay it against the transit session so the restore lookup
        # misses (session-scoped restore).
        staging = _plugin()  # separate mapping: token unknown to plugin
        staged_token = _seed_session_with_token(
            staging, session_id="sess-staging", original="DEUTDEFF", pii_type="bic",
        )
        restored = plugin.post_llm_response(
            f"line 117 in file, see staged {staged_token}",
            session_id="sess-transit",
            target_channel="subagent",
        )
        assert "[maskiertes PII" not in restored, (
            f"placeholder DESTROYED transit content: {restored!r}"
        )
        assert staged_token in restored

    def test_transit_miss_keeps_placeholder_behaviour_for_user_channels(self):
        """v1.7.6 Decision 1 (fail-closed placeholder) is untouched on
        user-facing channels — only delegation transit is lossless."""
        plugin = _plugin(restore_miss_strategy="placeholder")
        staging = _plugin()
        staged_token = _seed_session_with_token(
            staging, session_id="sess-staging-2", original="DEUTDEFF", pii_type="bic",
        )
        restored = plugin.post_llm_response(
            f"unresolved {staged_token}", session_id="sess-transit-2",
            target_channel="desktop",
        )
        assert "[maskiertes PII" in restored

    def test_transit_miss_stays_not_restored_for_real_egress_channels(self):
        """A channel that is neither user-facing nor delegation transit must
        keep tokens exactly as the sanitizer left them (egress safety)."""
        plugin = _plugin(restore_allowed_channels=("subagent",))
        staging = _plugin()
        staged_token = _seed_session_with_token(
            staging, session_id="sess-staging-3", original="DEUTDEFF", pii_type="bic",
        )
        restored = plugin.post_llm_response(
            f"egress {staged_token}", session_id="sess-transit-3",
            target_channel="write_file",
        )
        assert "DEUTDEFF" not in restored
        assert "[maskiertes PII" not in restored
        assert staged_token in restored

    def test_miss_log_has_no_token_content(self, caplog):
        """No credentials / PII in logs: the transit miss warning must not
        contain the token string or the original value."""
        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            plugin = _plugin()
            staging = _plugin()
            staged_token = _seed_session_with_token(
                staging, session_id="sess-staging-4",
                original="DEUTDEFF", pii_type="bic",
            )
            plugin.post_llm_response(
                f"see {staged_token}", session_id="sess-transit-4",
                target_channel="subagent",
            )
        token_core = staged_token.split("_", 2)[-1]
        assert token_core not in caplog.text
        assert "DEUTDEFF" not in caplog.text
