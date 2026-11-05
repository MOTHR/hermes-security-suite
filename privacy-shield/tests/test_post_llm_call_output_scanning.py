"""Tests for FIX-1B: Output-Scanning via post_llm_call + transform_llm_output.

Agent-Smith CRIT-1 (parallel for privacy-shield):
The LLM response can carry PII that was NOT produced by Privacy-Shield's
own pseudonymizer — hallucinated, leaked, or smuggled in by prompt injection.
Without output scanning those values reach the user (or write_file / kanban
outputs). FIX-1B closes that gap by adding:

  1. ``PrivacyShieldPlugin.post_llm_call`` — audit-log side-effect hook.
  2. ``PrivacyShieldPlugin._sanitize_output_pii`` — fresh-PII tokenisation
     that runs inside ``post_llm_response`` BEFORE token restoration.
  3. ``MappingTable.known_original_values`` — session-scoped lookup so the
     scanner can distinguish fresh PII from already-mapped originals.
  4. ``_mask_tokens`` — whitespace-masking of existing tokens so the regex
     detector does not match hex tails inside tokens.
"""

from __future__ import annotations

import logging
import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.mapping_table import InMemoryMappingTable, MappingTable
from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.pseudonymizer import Pseudonymizer


# ── Shared fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def plugin():
    """Default PrivacyShieldPlugin instance, in-memory mapping, limited mode."""
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
    )
    return PrivacyShieldPlugin(config=config)


@pytest.fixture
def paranoid_plugin():
    config = PrivacyShieldConfig(
        enabled=True,
        mode="paranoid",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
    )
    return PrivacyShieldPlugin(config=config)


@pytest.fixture
def strict_plugin():
    config = PrivacyShieldConfig(
        enabled=True,
        mode="strict",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
    )
    return PrivacyShieldPlugin(config=config)


def _seed_session_with_token(plugin, *, session_id: str, original: str, pii_type: str = "email"):
    """Store a single pre_llm_call-derived token in the session mapping.

    Returns the emitted token string so the test can reference it directly.
    """
    redacted = plugin.pre_llm_call(
        f"contact: {original}",
        context={"session_id": session_id, "provider": "openai"},
    )["user_message"]
    # The token prefix is configurable (TOKEN / PS); pick the longest match
    # that uses the configured prefix so the test does not depend on the
    # default.  We scan for {prefix}_{TYPE}_<hex>{_NNN}.
    token_re = re.compile(
        rf"\b{re.escape(plugin.config.token_prefix)}_[A-Z_]+_[0-9a-f]{{10}}(?:_\d{{3}})?\b"
    )
    match = token_re.search(redacted)
    assert match, f"no token generated for {original!r}"
    return match.group(0)


# ── Class 1: post_llm_call side-effect hook ───────────────────────────────


class TestPostLlmCallAudit:
    """post_llm_call records the audit-log entry but does NOT mutate the response."""

    def test_returns_none_for_clean_response(self, plugin, caplog):
        """No PII → no audit line, return value is None (Hermes discards it)."""
        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            result = plugin.post_llm_call(
                assistant_response="All clear, nothing to see here.",
                session_id="sess-1",
                model="openai:gpt-4o",
                platform="",
            )
        assert result is None
        # No 'output PII detected' warning expected.
        assert not any(
            "output PII detected" in record.message
            for record in caplog.records
        )

    def test_returns_none_for_empty_response(self, plugin):
        assert plugin.post_llm_call(
            assistant_response="", session_id="sess-1",
        ) is None

    def test_returns_none_when_plugin_disabled(self):
        config = PrivacyShieldConfig(
            enabled=False, mode="limited",
            encryption_key="x" * 32, storage_mode="memory",
        )
        p = PrivacyShieldPlugin(config=config)
        assert p.post_llm_call(
            assistant_response="leak: secret@example.com",
            session_id="sess-1",
        ) is None

    def test_audit_log_emitted_on_fresh_pii(self, plugin, caplog):
        """A fresh PII match in the response triggers an audit line."""
        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            plugin.post_llm_call(
                assistant_response="Bitte schreib an halluzinierte@example.com",
                session_id="sess-1",
                model="openai:gpt-4o",
                platform="telegram",
            )
        assert any(
            "Privacy-Shield output PII detected" in record.message
            for record in caplog.records
        ), "expected audit log line for output PII"

    def test_audit_log_uses_bucketed_count_not_plaintext(self, plugin, caplog):
        """The audit log carries the count bucket, never the original PII value."""
        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            plugin.post_llm_call(
                assistant_response=(
                    "alice@x.com bob@y.com carol@z.com dave@w.com erin@v.com "
                    "frank@u.com grace@t.com heidi@s.com ivan@r.com judy@q.com"
                ),
                session_id="sess-1",
                model="openai:gpt-4o",
            )
        line = next(
            r.message for r in caplog.records
            if "Privacy-Shield output PII detected" in r.message
        )
        # Must contain a bucket token from _bucket_count, never a count integer.
        assert "count_bucket=" in line
        # Must NOT contain any original PII value (the @example.com domain).
        assert "alice@x.com" not in line
        assert "@example.com" not in line
        # Type samples are kept to a small constant (≤3) for side-channel safety.
        assert line.count("email") <= 1

    def test_audit_log_emitted_only_when_masked_hit_count_positive(
        self, plugin, caplog
    ):
        """A response that triggers only low-confidence matches is silent."""
        # Build a response that contains no high-confidence PII.  Names
        # below the confidence threshold are not "masked" (see FIX-4B), so
        # the audit log stays empty.
        with caplog.at_level(logging.WARNING, logger="privacy_shield.plugin"):
            plugin.post_llm_call(
                assistant_response="Just normal text about weather and cats.",
                session_id="sess-1",
                model="openai:gpt-4o",
            )
        assert not any(
            "output PII detected" in r.message for r in caplog.records
        )


# ── Class 2: post_llm_call mode enforcement ──────────────────────────────


class TestPostLlmCallModeEnforcement:
    """In strict / paranoid mode the hook raises PermissionError."""

    def test_paranoid_mode_raises_on_any_pii(self, paranoid_plugin):
        with pytest.raises(PermissionError) as excinfo:
            paranoid_plugin.post_llm_call(
                assistant_response="Email: foo@bar.com",
                session_id="sess-1",
                model="openai:gpt-4o",
            )
        assert "Privacy-Shield" in str(excinfo.value)
        assert "blocking forward propagation" in str(excinfo.value)

    def test_strict_mode_blocks_cloud_provider_response(self, strict_plugin):
        with pytest.raises(PermissionError):
            strict_plugin.post_llm_call(
                assistant_response="+49 30 12345678 ist die Nummer",
                session_id="sess-1",
                model="openai:gpt-4o",  # cloud
            )

    def test_strict_mode_allows_local_provider_response(self, strict_plugin):
        """Local providers never cross an egress boundary, so strict does not block."""
        # The model string carries the provider prefix that the dispatcher
        # passes through.  Local providers are exempt.
        strict_plugin.post_llm_call(
            assistant_response="+49 30 12345678",
            session_id="sess-1",
            model="ollama_local:llama3.2",
        )  # no exception

    def test_limited_mode_does_not_raise(self, plugin):
        """Limited mode is the default — it should never raise on the response."""
        plugin.post_llm_call(
            assistant_response="leak: foo@bar.com",
            session_id="sess-1",
            model="openai:gpt-4o",
        )  # no exception

    def test_audit_mode_does_not_raise(self):
        config = PrivacyShieldConfig(
            enabled=True, mode="audit",
            encryption_key="x" * 32, storage_mode="memory",
        )
        p = PrivacyShieldPlugin(config=config)
        p.post_llm_call(
            assistant_response="leak: foo@bar.com",
            session_id="sess-1",
            model="openai:gpt-4o",
        )  # no exception


# ── Class 3: _sanitize_output_pii token-mask filter ──────────────────────


class TestSanitizeOutputPiiTokenMask:
    """The token-mask filter prevents feedback loops and false positives."""

    def test_does_not_match_hex_tail_inside_existing_token(self, plugin):
        """A response that contains a known token is NOT re-tokenised.

        Regression test for the bug where ``TOKEN_EMAIL_fe17341303_000``
        produced ``TOKEN_EMAIL_feTOKEN_PHONE_e5417b3a4e_001_000`` because
        the phone regex matched the hex tail ``17341303``.
        """
        token = _seed_session_with_token(
            plugin, session_id="sess-1",
            original="max.mustermann@firma-gmbh.de",
        )
        # Simulate the LLM echoing the token back to the user.
        response = f"Bestätige Empfang: Mail an {token}"
        sanitized, count = plugin._sanitize_output_pii(response, session_id="sess-1")
        # Token survives verbatim — no cascade.
        assert token in sanitized, (
            f"token was disturbed: {sanitized!r}"
        )
        # No new TOKEN_ prefix is introduced.
        assert sanitized.count("TOKEN_") == response.count("TOKEN_")

    def test_fresh_email_in_response_gets_tokenised(self, plugin):
        """Fresh PII (not in the session mapping) is replaced with a token."""
        sanitized, count = plugin._sanitize_output_pii(
            "Bitte kontaktiere leaked@example.com für Details.",
            session_id="sess-1",
        )
        assert count == 1
        assert "leaked@example.com" not in sanitized
        # A TOKEN_ placeholder is now present.
        assert re.search(
            rf"\b{re.escape(plugin.config.token_prefix)}_[A-Z_]+_[0-9a-f]{{10}}",
            sanitized,
        )

    def test_session_mapping_filter_protects_known_originals(self, plugin):
        """A value that already has a token in this session is left alone."""
        original = "alice@example.com"
        token = _seed_session_with_token(plugin, session_id="sess-1", original=original)
        # Sanity: token is in the mapping.
        assert original in plugin.mapper.known_original_values("sess-1")
        # Simulate the LLM echoing the ORIGINAL value (not the token) back.
        sanitized, count = plugin._sanitize_output_pii(
            f"Mail to {original}", session_id="sess-1",
        )
        # The original is preserved (the user is supposed to see it after
        # restoration — this hook just runs in transform_llm_output BEFORE
        # restoration, so the original passes through, gets restored from
        # the token it was paired with in the session mapping, and the user
        # sees it as expected).
        assert original in sanitized
        # Sanitisation reported zero fresh replacements.
        assert count == 0

    def test_empty_text_returns_zero(self, plugin):
        assert plugin._sanitize_output_pii("", session_id="sess-1") == ("", 0)
        assert plugin._sanitize_output_pii(None, session_id="sess-1") == (None, 0)

    def test_clean_text_returns_zero(self, plugin):
        sanitized, count = plugin._sanitize_output_pii(
            "Just a normal sentence with no PII at all.",
            session_id="sess-1",
        )
        assert count == 0
        assert sanitized == "Just a normal sentence with no PII at all."

    def test_session_id_filter_blocks_cross_session_leak(self, plugin):
        """Mappings from a different session must not protect the current one."""
        original = "bob@example.com"
        _seed_session_with_token(plugin, session_id="sess-A", original=original)
        # The same value appears in a different session (sess-B has no mapping).
        sanitized, count = plugin._sanitize_output_pii(
            f"Echo: {original}", session_id="sess-B",
        )
        assert count == 1, "cross-session leak: fresh PII not detected"
        assert original not in sanitized

    def test_mask_tokens_preserves_length(self):
        """_mask_tokens is offset-preserving (whitespace has equal length)."""
        text = "Hello TOKEN_EMAIL_abcd123456_001 World"
        # TOKEN_EMAIL_abcd123456_001 = 26 chars
        # "Hello " = 6 chars → token starts at 6, ends at 6+26 = 32
        expected_start = len("Hello ")
        expected_end = expected_start + len("TOKEN_EMAIL_abcd123456_001")
        token_re = re.compile(r"\bTOKEN_[A-Z_]+_[0-9a-f]{10}(?:_\d{3})?\b")
        masked, spans = PrivacyShieldPlugin._mask_tokens(text, token_re)
        assert len(masked) == len(text)
        assert spans == [(expected_start, expected_end)]
        # Token region is whitespace only.
        for start, end in spans:
            assert all(c == " " for c in masked[start:end])

    def test_mask_tokens_no_tokens_passthrough(self):
        text = "Just plain text without any tokens."
        token_re = re.compile(r"\bTOKEN_[A-Z_]+_[0-9a-f]{10}(?:_\d{3})?\b")
        masked, spans = PrivacyShieldPlugin._mask_tokens(text, token_re)
        assert masked == text
        assert spans == []

    def test_mask_tokens_empty_string(self):
        masked, spans = PrivacyShieldPlugin._mask_tokens("", re.compile(r"x"))
        assert masked == ""
        assert spans == []


# ── Class 4: post_llm_response integration ───────────────────────────────


class TestPostLlmResponseIntegration:
    """End-to-end: post_llm_response sanitises fresh PII AND restores tokens."""

    def test_token_restoration_still_works(self, plugin):
        """No-regression: an echoed token is still restored to its original."""
        plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT",)
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-1", original=original,
        )
        response = f"Bestätige Empfang: Mail an {token}"
        restored = plugin.post_llm_response(
            response, session_id="sess-1", target_channel="telegram:TEST_CHAT",
        )
        assert original in restored, f"restore failed: {restored!r}"
        assert "TOKEN_" not in restored

    def test_fresh_pii_in_response_gets_tokenised_before_restore(self, plugin):
        """Fresh PII is replaced with a token; the token is then NOT restored."""
        plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT",)
        response = (
            "Der echte Ansprechpartner ist leaked@example.com. "
            "Bitte schreib zurück."
        )
        out = plugin.post_llm_response(
            response, session_id="sess-1", target_channel="telegram:TEST_CHAT",
        )
        # The fresh PII is now a token; the token does NOT appear in the
        # session mapping of sess-1 except as the new sanitisation entry
        # we just stored, so restoration would replace it with itself —
        # but the point is: the user never sees the leaked plaintext.
        assert "leaked@example.com" not in out
        # The token IS visible to the user (tokenised form of fresh PII).
        assert "TOKEN_EMAIL_" in out

    def test_non_allowed_channel_skips_restore_and_sanitises(self, plugin):
        """When the target channel is not allowed for restoration, the response
        must still be sanitised — that's the only thing that prevents write_file
        or terminal output from carrying raw PII."""
        response = "Critical leak: leaked@example.com appears here."
        out = plugin.post_llm_response(
            response, session_id="sess-1", target_channel="write_file",
        )
        # Restoration skipped → token survives in output (no leak of original).
        assert "leaked@example.com" not in out
        # The sanitised token is what survives.
        assert "TOKEN_EMAIL_" in out

    def test_disabled_plugin_returns_unchanged(self):
        config = PrivacyShieldConfig(
            enabled=False, mode="limited",
            encryption_key="x" * 32, storage_mode="memory",
        )
        p = PrivacyShieldPlugin(config=config)
        text = "leaked@example.com"
        assert p.post_llm_response(text, session_id="sess-1") == text

    def test_empty_text_short_circuits(self, plugin):
        assert plugin.post_llm_response("", session_id="sess-1") == ""

    def test_session_id_empty_keeps_sanitisation_safe(self, plugin):
        """Without a session_id the mapper lookup is empty, so all PII is fresh."""
        response = "Critical: leaked@example.com appears here."
        out = plugin.post_llm_response(
            response, session_id="", target_channel="write_file",
        )
        assert "leaked@example.com" not in out

    def test_fresh_pii_token_does_not_get_stored_to_mapper(self, plugin, monkeypatch):
        """Regression test for the FIX-1B design invariant.

        ``_sanitize_output_pii`` MUST NOT call ``mapper.store`` for the
        fresh mapping. If it did, the subsequent ``restore_text`` pass
        inside the same ``post_llm_response`` flow would resolve the
        newly-emitted token back to the original PII, defeating the
        sanitisation entirely. The user must see the token, not the
        raw value, in the final response.
        """
        store_calls: list[list[dict]] = []
        original_store = plugin.mapper.store

        def spy_store(mapping, session_id="", ttl_seconds=3600):
            store_calls.append(list(mapping))
            return original_store(mapping, session_id=session_id, ttl_seconds=ttl_seconds)

        monkeypatch.setattr(plugin.mapper, "store", spy_store)

        response = "Critical leak: leaked@example.com appears here."
        plugin.post_llm_response(
            response, session_id="sess-1", target_channel="telegram:TEST_CHAT",
        )

        # mapper.store MAY be called from pre_llm_call side; what we care
        # about is that any store done *during* post_llm_response must not
        # introduce the fresh-PII token. Verify by checking the response:
        out = plugin.post_llm_response(
            response, session_id="sess-1", target_channel="telegram:TEST_CHAT",
        )
        assert "leaked@example.com" not in out
        # And if mapper.store WAS called with the leaked value, then on
        # subsequent restore calls the token would resolve back. Verify
        # by storing a fake mapping manually and confirming the existing
        # flow doesn't auto-store on fresh paths:
        from privacy_shield.mapping_table import InMemoryMappingTable
        fresh_mapper = InMemoryMappingTable()
        plugin.mapper = fresh_mapper
        store_calls.clear()
        plugin.post_llm_response(
            response, session_id="sess-fresh", target_channel="telegram:TEST_CHAT",
        )
        # The mapper MUST be empty: fresh PII tokens never persisted.
        assert fresh_mapper.known_original_values("sess-fresh") == set()


# ── Class 5: known_original_values mapper method ─────────────────────────


class TestKnownOriginalValues:
    """The mapper helper that distinguishes fresh PII from placeholders."""

    def test_in_memory_returns_known_originals(self):
        m = InMemoryMappingTable()
        m.store(
            [{"original_hash": "h1", "original_value": "alice@x.com",
              "token": "TOKEN_EMAIL_a1b2c3d4e0_001", "type": "email"}],
            session_id="sess-1",
        )
        assert m.known_original_values("sess-1") == {"alice@x.com"}

    def test_in_memory_empty_session(self):
        m = InMemoryMappingTable()
        assert m.known_original_values("sess-empty") == set()
        assert m.known_original_values("") == set()

    def test_in_memory_excludes_expired(self, monkeypatch):
        """Mappings with expires_at in the past must be filtered out."""
        import time as _time
        m = InMemoryMappingTable()
        # Force ``time.time()`` to return a fixed base value, then jump
        # forward by 10s so the stored ``expires_at = base`` is in the past.
        base = 1_700_000_000.0
        current = [base]
        monkeypatch.setattr(_time, "time", lambda: current[0])
        m.store(
            [{"original_hash": "h1", "original_value": "alice@x.com",
              "token": "TOKEN_EMAIL_a1b2c3d4e0_001", "type": "email"}],
            session_id="sess-1",
            ttl_seconds=1,  # expires at base + 1
        )
        # Still alive at base + 0.5.
        current[0] = base + 0.5
        assert m.known_original_values("sess-1") == {"alice@x.com"}
        # Past expiry.
        current[0] = base + 5.0
        assert m.known_original_values("sess-1") == set()

    def test_in_memory_other_session_not_visible(self):
        m = InMemoryMappingTable()
        m.store(
            [{"original_hash": "h1", "original_value": "alice@x.com",
              "token": "TOKEN_EMAIL_a1b2c3d4e0_001", "type": "email"}],
            session_id="sess-A",
        )
        assert m.known_original_values("sess-B") == set()

    def test_disk_mapper_returns_known_originals(self, tmp_path):
        storage = tmp_path / "mappings.db"
        key = "x" * 32
        m = MappingTable(storage_path=str(storage), encryption_key=key)
        m.store(
            [{"original_hash": "h1", "original_value": "alice@x.com",
              "token": "TOKEN_EMAIL_a1b2c3d4e0_001", "type": "email"}],
            session_id="sess-1",
        )
        result = m.known_original_values("sess-1")
        assert "alice@x.com" in result
        m.close()

    def test_disk_mapper_empty_session(self, tmp_path):
        storage = tmp_path / "mappings.db"
        m = MappingTable(storage_path=str(storage), encryption_key="x" * 32)
        assert m.known_original_values("nonexistent-session") == set()
        assert m.known_original_values("") == set()
        m.close()


# ── Class 6: Hook registration ──────────────────────────────────────────


class TestHookRegistration:
    """The plugin must register the post_llm_call hook so Hermes can dispatch it."""

    def test_plugin_yaml_declares_post_llm_call(self):
        import yaml

        from pathlib import Path
        yaml_path = Path(__file__).resolve().parent.parent / "plugin.yaml"
        with open(yaml_path) as fh:
            data = yaml.safe_load(fh)
        assert "post_llm_call" in data["provides_hooks"], (
            "plugin.yaml must declare post_llm_call in provides_hooks"
        )
        # And it must carry a hook priority so the dispatcher can order it.
        assert "post_llm_call" in data["hook_priority"], (
            "plugin.yaml must set hook_priority.post_llm_call"
        )
        # Priority must match the existing hooks — we want to run AFTER
        # injection-shield's post_llm_call (which is at 100).
        assert data["hook_priority"]["post_llm_call"] >= 200


class TestPostLlmCallDispatchContract:
    """post_llm_call signature must accept the kwargs Hermes actually dispatches."""

    def test_signature_accepts_hermes_kwargs(self):
        """Hermes turn_finalizer dispatches these kwargs (see turn_finalizer.py):
        session_id, task_id, turn_id, user_message, assistant_response,
        conversation_history, model, platform.
        """
        import inspect

        sig = inspect.signature(PrivacyShieldPlugin.post_llm_call)
        params = sig.parameters
        # Required kwargs that must be accepted without TypeError.
        for name in ("assistant_response", "session_id", "model", "platform"):
            assert name in params, f"missing kwarg {name!r}"
        # The hook MUST accept arbitrary additional kwargs so future additive
        # fields in Hermes do not break registration.
        assert any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
        ), "post_llm_call must accept **kwargs"

    def test_handler_in_init_does_not_raise_with_real_kwargs(self, plugin):
        """Replicate the dispatch shape Hermes uses (with a real session)."""
        from privacy_shield.plugin import PrivacyShieldPlugin as PSP

        # Construct the inner adapter the way __init__.py does.
        def on_post_llm_call(
            *,
            assistant_response: str = "",
            session_id: str = "",
            model: str = "",
            platform: str = "",
            **kwargs,
        ) -> None:
            plugin.post_llm_call(
                assistant_response=assistant_response,
                session_id=session_id,
                model=model,
                platform=platform,
            )

        # Should not raise even with extra kwargs Hermes might add in future.
        on_post_llm_call(
            assistant_response="hi alice@x.com",
            session_id="sess-1",
            task_id="t-42",          # not in plugin signature
            turn_id=7,                # not in plugin signature
            user_message="orig msg",  # not in plugin signature
            conversation_history=[],  # not in plugin signature
            model="openai:gpt-4o",
            platform="telegram",
        )
