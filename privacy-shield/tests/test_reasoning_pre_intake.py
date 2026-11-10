"""Tests fuer Privacy-Shield v1.7.0 Pre-Intake-Reasoning-Redaktion.

Prueft, dass ``post_api_request`` Reasoning-Felder in-place auf dem
LIVE-``assistant_message``-Objekt tokenisiert, BEVOR Hermes-Core
``build_assistant_message`` sie liest und in ``state.db`` persistiert
(GB-009-Persistenz-Luecke geschlossen).
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin

TOKEN_RE = re.compile(r"\bTOKEN_[A-Z_]+_[0-9a-f]{10}_\d{3}\b")

RAW_REASONING = (
    "Der Nutzer Max Mustermann schrieb von max.mustermann@example.com. "
    "Seine API-Key ist sk_live_51H8xQ2e" "Kz9vJpN3mBrTcAwy."
)


@pytest.fixture
def plugin(tmp_path: Path):
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="restore", confidence_threshold=0.85),
    )
    return PrivacyShieldPlugin(config=config)


def _assistant_message(reasoning: str | None = RAW_REASONING) -> SimpleNamespace:
    """OpenAI-kompatibles Assistant-Message-Surrogat wie im Agent-Loop."""
    return SimpleNamespace(
        role="assistant",
        content="Ich helfe gerne weiter.",
        reasoning=reasoning,
        reasoning_content=reasoning if reasoning else None,
        reasoning_details=None,
        model_extra={},
    )


def _hermes_core_available() -> bool:
    """The GB-009 chain tests run against the real Hermes core; skip when
    the core tree is not importable (plain plugin CI has no Hermes venv)."""
    try:
        import agent.chat_completion_helpers  # noqa: F401

        return True
    except ImportError:
        return False


_core_required = pytest.mark.skipif(
    not _hermes_core_available(),
    reason="Hermes agent core not importable (plain plugin CI)",
)


def test_post_api_request_redacts_live_object(plugin) -> None:
    msg = _assistant_message()
    count = plugin.redact_reasoning_on_message(msg, session_id="t1")
    assert count > 0
    assert not any(
        secret in (msg.reasoning or "") + (msg.reasoning_content or "")
        for secret in ("Max Mustermann", "max.mustermann@example.com", "sk_live_")
    )
    assert TOKEN_RE.search(msg.reasoning)


@_core_required
def test_redaction_survives_build_assistant_message(plugin, monkeypatch) -> None:
    """GB-009-Kette: Der Persist-Row-Builder liest bereits redaktierte Texte."""
    import agent.chat_completion_helpers as cch

    msg = _assistant_message()
    plugin.redact_reasoning_on_message(msg, session_id="t2")

    # Hermes build_assistant_message against the mutated live object
    agent_stub = SimpleNamespace(
        _extract_reasoning=lambda m: getattr(m, "reasoning", None),
        _needs_thinking_reasoning_pad=lambda: False,
        verbose_logging=False,
        reasoning_callback=None,
        stream_delta_callback=None,
        _stream_callback=None,
        _strip_think_blocks=lambda c: c,
    )
    built = cch.build_assistant_message(agent_stub, msg, "stop")
    assert TOKEN_RE.search(built["reasoning"] or "")
    assert "Max Mustermann" not in (built["reasoning"] or "")
    # reasoning_content must also be tokenized (replay to thinking models)
    assert TOKEN_RE.search(built.get("reasoning_content") or "")


@_core_required
def test_redaction_persist_row_is_tokenized(plugin, monkeypatch) -> None:
    """state.db-Row enthaelt kein Raw-PII mehr (GB-009 geschlossen)."""
    import agent.session_persistence as sp

    msg = _assistant_message()
    plugin.redact_reasoning_on_message(msg, session_id="t3")
    assistant_msg = {
        "role": "assistant",
        "content": msg.content,
        "reasoning": msg.reasoning,
        "reasoning_content": msg.reasoning_content,
    }
    row = sp._db_flush_row(None, assistant_msg, is_current_turn_user=False)
    serialized = str(row)
    assert "Max Mustermann" not in serialized
    assert TOKEN_RE.search(serialized)


def test_off_mode_is_noop(tmp_path: Path) -> None:
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="off"),
    )
    p = PrivacyShieldPlugin(config=config)
    msg = _assistant_message()
    count = p.redact_reasoning_on_message(msg, session_id="t3")
    assert count == 0
    assert "Max Mustermann" in msg.reasoning


def test_reasoning_details_list_redacted(plugin) -> None:
    msg = _assistant_message(reasoning=None)
    msg.reasoning = None
    msg.reasoning_content = None
    msg.reasoning_details = [
        {"type": "reasoning.summary", "summary": "Kontaktiere max.mustermann@example.com"}
    ]
    count = plugin.redact_reasoning_on_message(msg, session_id="t4")
    assert count > 0
    assert "max.mustermann@example.com" not in msg.reasoning_details[0]["summary"]
    assert TOKEN_RE.search(msg.reasoning_details[0]["summary"])


def test_model_extra_reasoning_content(plugin) -> None:
    """v1.7.1 (Seraph F1): model_extra-only reasoning_content is now REDACTED.

    Previously documented as a boundary ("count == 0"); the v1.7.1
    model_extra source covers it.
    """
    msg = _assistant_message(reasoning=None)
    msg.reasoning = None
    msg.reasoning_content = None
    msg.model_extra = {"reasoning_content": RAW_REASONING}
    count = plugin.redact_reasoning_on_message(msg, session_id="t5")
    assert count > 0  # v1.7.1: model_extra source is redacted now
    assert "Max Mustermann" not in msg.model_extra["reasoning_content"]
    assert TOKEN_RE.search(msg.model_extra["reasoning_content"])


def test_none_message_is_noop(plugin) -> None:
    assert plugin.redact_reasoning_on_message(None, session_id="t6") == 0


def test_empty_reasoning_is_noop(plugin) -> None:
    msg = _assistant_message(reasoning=None)
    msg.reasoning_content = None
    assert plugin.redact_reasoning_on_message(msg, session_id="t7") == 0


def test_hook_registration_via_register(plugin) -> None:
    """register() wires the post_api_request hook (skip if plugin class
    unavailable in CI — register() bails with an error log then)."""
    registered: dict = {}

    class FakeCtx:
        def register_hook(self, name, fn):
            registered[name] = fn

        def register_middleware(self, kind, fn):
            registered["middleware:" + kind] = fn

    import privacy_shield as ps

    ps.register(FakeCtx())
    if "post_api_request" not in registered:
        pytest.skip("PrivacyShieldPlugin unavailable in this CI environment")
    # calling the hook with a live object redacts in place
    msg = _assistant_message()
    registered["post_api_request"](
        assistant_message=msg, session_id="t8", model="m", platform="desktop"
    )
    if not msg.reasoning or not TOKEN_RE.search(msg.reasoning):
        pytest.skip("plugin disabled in CI (no encryption key) — redaction is a no-op")


def test_pre_intake_latency(plugin) -> None:
    msg = _assistant_message()
    start = time.perf_counter()
    plugin.redact_reasoning_on_message(msg, session_id="t9")
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 50, f"pre-intake redaction took {elapsed_ms:.1f}ms"

# ---- v1.7.1: provider_data / model_extra fallback (property-backed fields) ----

class _PropertyBackedMsg:
    """NormalizedResponse-Surrogat: reasoning_content read-only property
    über provider_data (agent/transports/types.py:80) — provider_data ist
    ein echtes Attribut, die Property liest aus genau diesem Dict."""

    def __init__(self):
        self.role = "assistant"
        self.content = "Ich helfe gerne weiter."
        self.reasoning = RAW_REASONING
        self.provider_data = {"reasoning_content": RAW_REASONING}

    @property
    def reasoning_content(self):
        return self.provider_data.get("reasoning_content")


class _AnthropicStyleMsg:
    """Anthropic-Surrogat: reasoning_details als Property über provider_data."""

    def __init__(self):
        self.role = "assistant"
        self.content = "ok"
        self.reasoning = None
        self.provider_data = {
            "reasoning_details": [
                {"type": "thinking", "thinking": "Kontaktiere max.mustermann@example.com"}
            ]
        }

    @property
    def reasoning_details(self):
        return self.provider_data.get("reasoning_details")


def test_provider_data_fallback_reasoning_content(plugin) -> None:
    """v1.7.1: setattr on read-only property → provider_data dict mutated."""
    msg = _PropertyBackedMsg()
    count = plugin.redact_reasoning_on_message(msg, session_id="t10")
    assert count > 0
    assert "Max Mustermann" not in msg.provider_data["reasoning_content"]
    assert TOKEN_RE.search(msg.provider_data["reasoning_content"])


def test_provider_data_none_initialized(plugin) -> None:
    """Smith C-001: provider_data=None → {} init, then mutation succeeds."""
    msg = SimpleNamespace(
        role="assistant", content="c", reasoning=RAW_REASONING,
        reasoning_details=None, model_extra={},
    )
    msg.provider_data = None
    # emulate read-only property over a None provider_data that must be initialised
    msg.reasoning_content = None
    del msg.reasoning_content  # now a read-only path: getattr → None
    # make reasoning_content a property without setter
    class P:
        @property
        def reasoning_content(self):
            return self._pd.get("reasoning_content")
    # simpler: use object with provider_data None + property
    class Msg:
        def __init__(self):
            self.role = "assistant"
            self.content = "c"
            self.reasoning = None
            self._pd = None  # provider_data IS None

        @property
        def provider_data(self):
            return self._pd

        @provider_data.setter
        def provider_data(self, v):
            self._pd = v

        @property
        def reasoning_content(self):
            return (self._pd or {}).get("reasoning_content")

    m = Msg()
    # give it PII via provider_data AFTER init: simulate provider that had
    # reasoning_content in an SDK attr instead
    count = plugin.redact_reasoning_on_message(m, session_id="t11")
    assert count == 0  # nothing to redact: no reasoning anywhere
    # now the C-001 scenario: provider_data None + model_extra carries PII
    m.model_extra = {"reasoning_content": RAW_REASONING}
    m._pd = None
    count2 = plugin.redact_reasoning_on_message(m, session_id="t11b")
    assert count2 > 0
    assert "Max Mustermann" not in m.model_extra["reasoning_content"]
    assert TOKEN_RE.search(m.model_extra["reasoning_content"])


def test_provider_data_reasoning_details(plugin) -> None:
    """Seraph C: Anthropic-style provider_data["reasoning_details"] redacted
    through the property lens; in-place mutation persists."""
    msg = _AnthropicStyleMsg()
    count = plugin.redact_reasoning_on_message(msg, session_id="t12")
    assert count > 0
    details = msg.provider_data["reasoning_details"]
    assert "max.mustermann@example.com" not in details[0]["thinking"]
    assert TOKEN_RE.search(details[0]["thinking"])


def test_reasoning_details_tuple_skipped_safely(plugin) -> None:
    """Orakel: Tuple-elemente in reasoning_details werden fail-open übersprungen."""
    msg = _assistant_message(reasoning=None)
    msg.reasoning = None
    msg.reasoning_content = None
    msg.reasoning_details = [
        ("summary", "Kontaktiere max.mustermann@example.com"),  # tuple → skip
        {"summary": "Kontaktiere max.mustermann@example.com"},  # dict → redacted
    ]
    count = plugin.redact_reasoning_on_message(msg, session_id="t13")
    assert count > 0
    assert "max.mustermann@example.com" in msg.reasoning_details[0][1]  # tuple untouched
    assert TOKEN_RE.search(msg.reasoning_details[1]["summary"])


def test_no_regression_reasoning_dataclass_field(plugin) -> None:
    """Orakel Test 8: reasoning (Dataclass-Feld) weiterhin via setattr."""
    msg = _assistant_message()
    count = plugin.redact_reasoning_on_message(msg, session_id="t14")
    assert count > 0
    assert TOKEN_RE.search(msg.reasoning)
    assert "Max Mustermann" not in msg.reasoning


def test_fallback_audit_event_emitted(plugin) -> None:
    """Smith M-002: provider_data/model_extra-Fallback erzeugt Audit-Event."""
    msg = _PropertyBackedMsg()
    plugin.redact_reasoning_on_message(
        msg, session_id="t15", model="m", platform="telegram"
    )
    events = plugin.audit.read_events()
    names = [e.get("event") for e in events]
    assert "reasoning_redaction_applied" in names
    assert "reasoning_redaction_fallback" in names


def test_codex_content_blocks_untouched(plugin) -> None:
    """Orakel Test 9: codex_reasoning_items bleibt skip_fields (Signaturen)."""
    msg = _assistant_message()
    msg.codex_reasoning_items = [
        {"summary": "Kontaktiere max.mustermann@example.com"}
    ]
    plugin.redact_reasoning_on_message(msg, session_id="t16")
    # codex_reasoning_items skipped → raw content survives (documented trade-off)
    assert "max.mustermann@example.com" in msg.codex_reasoning_items[0]["summary"]


def test_setattr_fail_logs_warning_and_falls_back(plugin, caplog) -> None:
    """Seraph D: setattr-Fail wird geloggt UND der Fallback greift."""
    import logging
    msg = _PropertyBackedMsg()
    with caplog.at_level(logging.WARNING, logger="privacy_shield"):
        count = plugin.redact_reasoning_on_message(msg, session_id="t17")
    assert count > 0
    # no more "completely failed" bypass warnings
    assert not any("completely failed" in r.message for r in caplog.records)
