"""Tests fuer Privacy-Shield v1.6.1 Reasoning-In-Memory-Redaktion.

Diese Suite prueft, dass ``post_llm_call`` Reasoning-Felder in-place
im ``conversation_history``-Array tokenisiert und dass die Mutation auf
das Original-``messages``-Array durchschlaegt (Spike-001 Verhalten).
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest
from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin

TOKEN_RE = re.compile(r"\bTOKEN_[A-Z_]+_[0-9a-f]{10}_\d{3}\b")


@pytest.fixture
def plugin(tmp_path: Path):
    """Plugin im Reasoning-Restore-Modus mit memory mapping."""
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="restore", confidence_threshold=0.85),
    )
    return PrivacyShieldPlugin(config=config)


@pytest.fixture
def audit_plugin(tmp_path: Path):
    """Plugin im Reasoning-Audit-Modus."""
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="audit", confidence_threshold=0.85),
    )
    return PrivacyShieldPlugin(config=config)


@pytest.fixture
def off_plugin(tmp_path: Path):
    """Plugin mit Reasoning-Schutz ausgeschaltet."""
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="off"),
    )
    return PrivacyShieldPlugin(config=config)


# ---------------------------------------------------------------------------
# 1. Stolen-Thoughts-Beispiele
# ---------------------------------------------------------------------------


def test_reasoning_fake_api_key_tokenized(plugin):
    """Reasoning mit Fake-API-Key wird durch Token ersetzt."""
    api_key = "sk_live_51HvKx2X4QuN" "9WqT8vYzA3BcD5EfG6H7"
    history = [
        {
            "role": "assistant",
            "content": "OK, ich habe ueberlegt.",
            "reasoning": (
                f"Der User hat einen API-Key genannt: {api_key} "
                "ich sollte den nicht weiterschreiben."
            ),
        }
    ]
    # Spike-Beweis: messages enthaelt dieselben Dict-Objekte wie history.
    messages = history[:]

    plugin.post_llm_call(
        assistant_response="alles klar",
        session_id="sess-api-key",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    redacted = history[0]["reasoning"]
    assert api_key not in redacted
    assert TOKEN_RE.search(redacted), f"kein Token gefunden: {redacted!r}"
    assert history[0]["reasoning"] is messages[0]["reasoning"]
    assert plugin.mapper.known_original_values("sess-api-key")


def test_reasoning_email_tokenized(plugin):
    """Reasoning mit Email-Adresse wird tokenisiert."""
    history = [
        {
            "role": "assistant",
            "content": "Ich habe eine Antwort vorbereitet.",
            "reasoning": (
                "Ich sollte max.mustermann@example.com kontaktieren "
                "und nach dem Status fragen."
            ),
        }
    ]
    messages = history[:]

    plugin.post_llm_call(
        assistant_response="bereit",
        session_id="sess-email",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    redacted = history[0]["reasoning"]
    assert "max.mustermann@example.com" not in redacted
    assert TOKEN_RE.search(redacted), f"kein Token gefunden: {redacted!r}"
    assert history[0]["reasoning"] is messages[0]["reasoning"]


def test_reasoning_person_name_context_tokenized(plugin):
    """Reasoning mit Personenname + Kontext wird erkannt und tokenisiert."""
    history = [
        {
            "role": "assistant",
            "content": "Vorschlag erarbeitet.",
            "reasoning": (
                "Max Mustermann arbeitet bei der Firma GmbH und ist "
                "zustaendig fuer das Projekt Phoenix. Ich erwaehne ihn "
                "im Entwurf."
            ),
        }
    ]
    messages = history[:]

    plugin.post_llm_call(
        assistant_response="Vorschlag",
        session_id="sess-name",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    redacted = history[0]["reasoning"]
    assert "Max Mustermann" not in redacted
    assert TOKEN_RE.search(redacted), f"kein Token gefunden: {redacted!r}"
    assert history[0]["reasoning"] is messages[0]["reasoning"]


def test_reasoning_address_tokenized(plugin):
    """Reasoning mit deutscher Postanschrift wird tokenisiert."""
    history = [
        {
            "role": "assistant",
            "content": "Antwort formuliert.",
            "reasoning": (
                "Der Kunde wohnt in der Musterstrasse 12, 12345 Berlin. "
                "Ich sollte die Adresse nicht im Output wiederholen."
            ),
        }
    ]
    messages = history[:]

    plugin.post_llm_call(
        assistant_response="fertig",
        session_id="sess-address",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    redacted = history[0]["reasoning"]
    # Die PLZ+Stadt-Kombination sollte vom Detector erkannt werden.
    assert "12345 Berlin" not in redacted
    assert TOKEN_RE.search(redacted), f"kein Token gefunden: {redacted!r}"
    assert history[0]["reasoning"] is messages[0]["reasoning"]


def test_reasoning_login_path_with_token_tokenized(plugin):
    """Reasoning mit Anmelde-Pfad + Session-Token wird tokenisiert."""
    history = [
        {
            "role": "assistant",
            "content": "Ich habe einen Plan.",
            "reasoning": (
                "Login-Link: https://portal.example.com/login?token="
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                ".eyJzdWIiOiIxMjM0NTY3ODkw"
                " und es muss geheim bleiben."
            ),
        }
    ]
    messages = history[:]

    plugin.post_llm_call(
        assistant_response="Plan steht.",
        session_id="sess-login",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    redacted = history[0]["reasoning"]
    # JWT/Token-Substring sollte verschwinden.
    assert (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw" not in redacted
    )
    assert TOKEN_RE.search(redacted), f"kein Token gefunden: {redacted!r}"
    assert history[0]["reasoning"] is messages[0]["reasoning"]


# ---------------------------------------------------------------------------
# 2. Spike-Beweis: In-Place-Mutation schlaegt durch
# ---------------------------------------------------------------------------


def test_reasoning_mutation_reaches_original_messages_array(plugin):
    """Mutation in conversation_history wirkt auf das Original-messages-Array.

    Spike-001 Verdict PARTIAL: post_llm_call In-Place-Mutation wirkt auf
    Original-messages durch, aber ``_persist_session`` laeuft vor dem Hook.
    Dieser Test reproduziert den positiven Teil: die Mutation schlaegt durch.
    """
    shared_msg = {
        "role": "assistant",
        "content": "Ausgabe",
        "reasoning": "Ich schicke die Mail an leak@example.com.",
    }
    conversation_history = [shared_msg]
    messages = [shared_msg]  # identisches Objekt, kein klonen

    plugin.post_llm_call(
        assistant_response="Ausgabe",
        session_id="sess-shared",
        model="openai:gpt-4o",
        conversation_history=conversation_history,
    )

    # Beide Referenzen zeigen auf dasselbe mutierte Objekt.
    assert conversation_history[0] is messages[0]
    assert conversation_history[0]["reasoning"] is messages[0]["reasoning"]
    assert "leak@example.com" not in messages[0]["reasoning"]
    assert TOKEN_RE.search(messages[0]["reasoning"])


# ---------------------------------------------------------------------------
# 3. Modus-Verhalten
# ---------------------------------------------------------------------------


def test_reasoning_audit_mode_logs_but_does_not_mutate(audit_plugin):
    """Im Audit-Modus bleibt Reasoning unveraendert, aber Audit-Event wird geschrieben."""
    original = "Ich sollte alice@example.com benachrichtigen."
    history = [{"role": "assistant", "content": "x", "reasoning": original}]

    audit_plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-audit",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert history[0]["reasoning"] == original
    # Audit-Eintrag wurde geschrieben.
    assert audit_plugin.audit is not None
    events = audit_plugin.audit.read_events()
    assert any(e.get("source") == "reasoning_block" for e in events)


def test_reasoning_off_mode_leaves_text_untouched(off_plugin):
    """Im off-Modus passiert gar nichts."""
    original = "Ich sollte alice@example.com benachrichtigen."
    history = [{"role": "assistant", "content": "x", "reasoning": original}]

    off_plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-off",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert history[0]["reasoning"] == original


def test_reasoning_non_assistant_roles_are_skipped(plugin):
    """Nur Assistant-Nachrichten werden geredactet."""
    original = "Ich sollte alice@example.com benachrichtigen."
    history = [
        {"role": "user", "content": "x", "reasoning": original},
        {"role": "system", "content": "x", "reasoning": original},
    ]

    plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-roles",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert history[0]["reasoning"] == original
    assert history[1]["reasoning"] == original


# ---------------------------------------------------------------------------
# 4. Performance: Latenz pro Reasoning-Block < 50 ms
# ---------------------------------------------------------------------------


def test_reasoning_redaction_latency_under_50ms(plugin):
    """Ein Reasoning-Block mit PII sollte in unter 50 ms tokenisiert sein."""
    history = [
        {
            "role": "assistant",
            "content": "Antwort",
            "reasoning": "Email max.mustermann@example.com, Adresse 12345 Berlin.",
        }
    ]

    start = time.perf_counter()
    plugin.post_llm_call(
        assistant_response="Antwort",
        session_id="sess-perf",
        model="openai:gpt-4o",
        conversation_history=history,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    # CI runners spike well above the 50ms spec target; keep the strict
    # local limit, relax only inside CI (5x, same rationale as test_performance).
    limit = 250.0 if os.environ.get("PRIVACY_SHIELD_CI", "") else 50.0
    assert elapsed_ms < limit, (
        f"Reasoning-Redaktion zu langsam: {elapsed_ms:.2f} ms (limit {limit})"
    )
    assert TOKEN_RE.search(history[0]["reasoning"])


# ---------------------------------------------------------------------------
# 5. Audit-Log: source=reasoning_block + Limitation-Hinweis
# ---------------------------------------------------------------------------


def test_reasoning_audit_log_contains_source_and_limitation_note(plugin):
    """Audit-Log traegt source=reasoning_block und den Persistenz-Hinweis."""
    history = [
        {
            "role": "assistant",
            "content": "x",
            "reasoning": "Kontakt: max.mustermann@example.com",
        }
    ]

    plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-audit-note",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert plugin.audit is not None
    events = plugin.audit.read_events()
    reasoning_events = [e for e in events if e.get("source") == "reasoning_block"]
    assert reasoning_events, "keine reasoning_block Audit-Events"
    note = reasoning_events[0].get("note", "")
    assert "Persistenz-Limitation" in note
    assert "state.db" in note


# ---------------------------------------------------------------------------
# 6. Runtime-Guard: ungueltige / verschachtelte Strukturen
# ---------------------------------------------------------------------------


def test_reasoning_skip_fields_are_honored(plugin):
    """Felder in config.reasoning.skip_fields werden nicht tokenisiert."""
    plugin.config.reasoning.skip_fields = ["reasoning_content"]
    original = "Ich sollte alice@example.com benachrichtigen."
    history = [
        {
            "role": "assistant",
            "content": "x",
            "reasoning": original,
            "reasoning_content": original,
        }
    ]

    plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-skip",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert history[0]["reasoning"] != original
    assert history[0]["reasoning_content"] == original


def test_reasoning_codex_reasoning_items_are_redacted(plugin):
    """Nested codex_reasoning_items Text-Felder werden redactet, wenn nicht skipped."""
    plugin.config.reasoning.skip_fields = []
    history = [
        {
            "role": "assistant",
            "content": "x",
            "codex_reasoning_items": [
                {"type": "text", "text": "Kontakt: max.mustermann@example.com"},
                {"type": "tool_use", "reasoning": "Adresse 12345 Berlin"},
            ],
        }
    ]

    plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-codex",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert (
        "max.mustermann@example.com"
        not in history[0]["codex_reasoning_items"][0]["text"]
    )
    assert "12345 Berlin" not in history[0]["codex_reasoning_items"][1]["reasoning"]
    assert TOKEN_RE.search(history[0]["codex_reasoning_items"][0]["text"])


def test_reasoning_codex_reasoning_items_skipped_by_default(plugin):
    """Default skip_fields enthaelt codex_reasoning_items; diese bleiben unveraendert."""
    assert "codex_reasoning_items" in plugin.config.reasoning.skip_fields
    history = [
        {
            "role": "assistant",
            "content": "x",
            "codex_reasoning_items": [
                {"type": "text", "text": "Kontakt: max.mustermann@example.com"},
            ],
        }
    ]

    plugin.post_llm_call(
        assistant_response="x",
        session_id="sess-skip-default",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert (
        history[0]["codex_reasoning_items"][0]["text"]
        == "Kontakt: max.mustermann@example.com"
    )
