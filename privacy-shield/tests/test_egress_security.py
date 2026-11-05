"""Tests for cache-bypass resistance and side-channel mitigation."""

import re

import pytest

from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.config import PrivacyShieldConfig


@pytest.fixture
def plugin():
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
    )
    return PrivacyShieldPlugin(config=config)


class TestCacheBypass:
    def test_cache_bypass_includes_multiple_markers(self, plugin):
        result = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        assert result is not None
        sanitized = result["user_message"]
        assert "[Privacy-Shield Session:sess-123" in sanitized
        assert "[PS:sess-123" in sanitized
        assert "privacy-shield session=sess-123" in sanitized

    def test_cache_bypass_changes_between_calls(self, plugin):
        r1 = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        r2 = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        assert r1["user_message"] != r2["user_message"]


class TestSideChannelBuckets:
    def test_bucket_count(self, plugin):
        assert plugin._bucket_count(0) == "0"
        assert plugin._bucket_count(1) == "1-1"
        assert plugin._bucket_count(5) == "1-10"
        assert plugin._bucket_count(50) == "1-100"
        assert plugin._bucket_count(500) == "1-1000"
        assert plugin._bucket_count(5000) == "10000+"

    def test_bucket_count_boundary(self, plugin):
        assert plugin._bucket_count(1000) == "1-1000"
        assert plugin._bucket_count(1001) == "10000+"

    def test_audit_mode_does_not_modify_message(self, plugin):
        plugin.config.mode = "audit"
        result = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        assert result is None

    def test_paranoid_mode_blocks_pii(self, plugin):
        plugin.config.mode = "paranoid"
        result = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        # Spec v1.1 4c: block as return-contract signal (exceptions are
        # swallowed by the Core hook dispatcher).
        assert isinstance(result, dict) and result.get("blocked") is True
        assert "paranoid mode" in result.get("block_reason", "")

    def test_off_mode_returns_none(self, plugin):
        plugin.config.mode = "off"
        result = plugin.pre_llm_call(
            "email: test@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        assert result is None


class TestRestoreChannelControl:
    def test_restore_only_allowed_channels(self, plugin):
        plugin.config.restore_allowed_channels = ("telegram:12345",)
        # Store a mapping first so the token can be restored
        redacted = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )["user_message"]
        token_match = re.search(r"TOKEN_EMAIL_[0-9a-f]{10}_\d{3}", redacted)
        assert token_match, "no token generated"
        real_token = token_match.group(0)

        # Allowed channel restores tokens
        restored = plugin.post_llm_response(
            f"Mail to {real_token}",
            session_id="sess-123",
            target_channel="telegram:12345",
        )
        assert "TOKEN_EMAIL_" not in restored
        assert "alice@example.com" in restored

        # Other channel keeps tokens (and keeps response unchanged)
        blocked = plugin.post_llm_response(
            f"Mail to {real_token}",
            session_id="sess-123",
            target_channel="kanban_complete",
        )
        assert real_token in blocked


class TestModeBehaviour:
    def test_limited_mode_redacts_and_stores(self, plugin):
        redacted = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        assert "TOKEN_EMAIL_" in redacted["user_message"]
        assert plugin.mapper.count() == 1

    def test_strict_mode_blocks_cloud(self, plugin):
        plugin.config.mode = "strict"
        plugin.config.paranoid_cloud_providers = True
        result = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-123", "provider": "openai"},
        )
        # Spec v1.1 4c: block as return-contract signal.
        assert isinstance(result, dict) and result.get("blocked") is True
        assert "strict mode" in result.get("block_reason", "")


# ── FIX-4B / Architect NEU-002: Confidence-Threshold für Low-Patterns ───────

class TestConfidenceThreshold:
    """Auto-masking must respect the confidence threshold.

    High-confidence regex matches (email, IBAN, phone, credit card, …) are
    always pseudonymized. Low-confidence patterns (cookie_id, health_context,
    salary_context, gps, …) are detected for logging but only auto-masked
    when the per-type override (or global threshold) allows it.
    """

    # 32-character alphanumeric token to trigger the cookie_id regex.
    _COOKIE_TOKEN = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

    def test_high_confidence_email_is_masked(self, plugin):
        """email is high-confidence → must always be masked in limited mode."""
        result = plugin.pre_llm_call(
            "Contact: max.mustermann@example.com",
            context={"session_id": "sess-ct-1", "provider": "openai"},
        )
        assert result is not None
        assert "TOKEN_EMAIL_" in result["user_message"]
        assert "max.mustermann@example.com" not in result["user_message"]

    def test_low_confidence_cookie_not_masked(self, plugin):
        """32+ char alphanumeric match must NOT be auto-masked by default."""
        result = plugin.pre_llm_call(
            f"session_id={self._COOKIE_TOKEN}",
            context={"session_id": "sess-ct-2", "provider": "openai"},
        )
        # The override for cookie_id is 1.0 → detection-only → no masking,
        # no replacement → pre_llm_call returns None.
        assert result is None

    def test_low_confidence_health_context_not_masked(self, plugin):
        """health_context has confidence=0.5 + override=1.0 → detection-only."""
        result = plugin.pre_llm_call(
            "Diagnose: Diabetes mellitus",
            context={"session_id": "sess-ct-3", "provider": "openai"},
        )
        assert result is None

    def test_low_confidence_salary_context_not_masked(self, plugin):
        """salary_context has confidence=0.5 + override=1.0 → detection-only."""
        result = plugin.pre_llm_call(
            "Gehalt: 5000 Euro brutto",
            context={"session_id": "sess-ct-4", "provider": "openai"},
        )
        assert result is None

    def test_mixed_email_and_cookie_only_email_masked(self, plugin):
        """When high- and low-confidence patterns coexist, only high is masked."""
        text = f"Mail max.mustermann@example.com sid={self._COOKIE_TOKEN}"
        result = plugin.pre_llm_call(
            text,
            context={"session_id": "sess-ct-5", "provider": "openai"},
        )
        assert result is not None
        assert "TOKEN_EMAIL_" in result["user_message"]
        # Cookie token must remain in the masked output (not replaced).
        assert self._COOKIE_TOKEN in result["user_message"]

    def test_low_confidence_does_not_increment_mapping(self, plugin):
        """Dropped (low-conf) matches must NOT be stored in the mapping table.

        Otherwise a later restore attempt would fail (no entry exists) and the
        user would see the raw `TOKEN_COOKIE_ID_…` literal in the response.
        """
        result = plugin.pre_llm_call(
            f"session_id={self._COOKIE_TOKEN}",
            context={"session_id": "sess-ct-6", "provider": "openai"},
        )
        assert result is None
        assert plugin.mapper.count() == 0

    def test_override_takes_precedence_over_global_threshold(self):
        """Per-type override (cookie_id=1.0) beats a lowered global threshold."""
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            confidence_threshold=0.5,  # low: would mask cookie if no override
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        result = plugin.pre_llm_call(
            f"session_id={self._COOKIE_TOKEN}",
            context={"session_id": "sess-ct-7", "provider": "openai"},
        )
        # Default config still ships cookie_id=1.0 override → still NOT masked.
        assert result is None

    def test_empty_overrides_lets_low_confidence_through(self):
        """With overrides={}, the global threshold (0.5) decides."""
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            confidence_threshold=0.5,
            confidence_overrides={},  # no per-type overrides
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        result = plugin.pre_llm_call(
            f"session_id={self._COOKIE_TOKEN}",
            context={"session_id": "sess-ct-8", "provider": "openai"},
        )
        assert result is not None
        assert "TOKEN_COOKIE_" in result["user_message"]

    def test_partition_by_confidence_helper(self, plugin):
        """Direct unit test for the internal partition helper."""
        from privacy_shield.detectors.regex_detector import PIIMatch

        matches = [
            PIIMatch(type="email", value="x@y.com", start=0, end=7, confidence=1.0),
            PIIMatch(type="cookie_id", value=self._COOKIE_TOKEN, start=0, end=32, confidence=0.5),
            PIIMatch(type="health_context", value="Diagnose: foo", start=0, end=14, confidence=0.5),
        ]
        masked, dropped = plugin._partition_by_confidence(matches)
        assert len(masked) == 1
        assert masked[0].type == "email"
        assert {h.type for h in dropped} == {"cookie_id", "health_context"}

    def test_low_confidence_logged_but_not_masked(self, plugin, caplog):
        """Low-confidence detections must be logged for visibility."""
        import logging

        with caplog.at_level(logging.INFO, logger="privacy_shield.plugin"):
            plugin.pre_llm_call(
                f"session_id={self._COOKIE_TOKEN}",
                context={"session_id": "sess-ct-9", "provider": "openai"},
            )
        # At least one log line should announce that low-confidence matches
        # were detected but NOT masked.
        assert any(
            "low-confidence" in record.message and "NOT masked" in record.message
            for record in caplog.records
        ), f"Expected low-confidence log line, got: {[r.message for r in caplog.records]}"
