"""GB-010: last_reasoning-Leak-Schutz verifizieren.

Hermes-Core baut ``result["last_reasoning"]`` aus demselben
``messages``-Array, das Privacy-Shield in ``post_llm_call`` in-place
mutiert (siehe ``turn_finalizer.py:639``).  Diese Suite stellt sicher,

dass die Mutation das letzte Assistant-Reasoning erreicht und dass ein
simulierter ``last_reasoning``-Wert (über den messages-Pfad) ebenfalls
tokenisiert ist.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.token_validator import find_last_assistant_reasoning


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
# 1. Mutation erreicht letzte Assistant-Message
# ---------------------------------------------------------------------------


def test_last_reasoning_path_gets_tokenized(plugin):
    """``find_last_assistant_reasoning`` liefert nach dem Hook Token-Werte."""
    history = [
        {"role": "user", "content": "x"},
        {
            "role": "assistant",
            "content": "Antwort.",
            "reasoning": "Ich schicke die Mail an leak@example.com.",
        },
    ]

    plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    last_reasoning = find_last_assistant_reasoning(history)
    assert last_reasoning is not None
    assert "leak@example.com" not in last_reasoning
    assert TOKEN_RE.search(last_reasoning), f"kein Token: {last_reasoning!r}"


def test_last_reasoning_simulates_hermes_core_result(plugin):
    """``result["last_reasoning"]``, wie Hermes-Core es aus messages liest, ist tokenisiert."""
    history = [
        {"role": "user", "content": "x"},
        {
            "role": "assistant",
            "content": "Antwort.",
            "reasoning": "Max Mustermann wohnt in 12345 Berlin.",
        },
    ]

    plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010-sim",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    # Simuliere Hermes-Core turn_finalizer.py:636-640.
    last_reasoning = None
    for msg in reversed(history):
        if msg.get("role") == "user":
            break
        if msg.get("role") == "assistant" and msg.get("reasoning"):
            last_reasoning = msg["reasoning"]
            break

    assert last_reasoning is not None
    assert "Max Mustermann" not in last_reasoning
    assert "12345 Berlin" not in last_reasoning
    assert TOKEN_RE.search(last_reasoning), f"kein Token: {last_reasoning!r}"


# ---------------------------------------------------------------------------
# 2. Defensive Warnung bei fehlender Mutation
# ---------------------------------------------------------------------------


def test_off_mode_does_not_log_leak_warning(off_plugin, caplog):
    """``reasoning.mode=off`` überspringt Tokenisierung absichtlich — der
    GB-010-Verifier darf dann keinen False-Positive-Leak-Warning loggen
    (Boy-Who-Cried-Wolf-Bug, siehe t_8402d518 Bug A)."""
    caplog.set_level(logging.WARNING)
    history = [
        {"role": "user", "content": "x"},
        {
            "role": "assistant",
            "content": "Antwort.",
            "reasoning": "Ich schicke die Mail an leak@example.com.",
        },
    ]

    off_plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010-off",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert not any(
        "last_reasoning-Leak" in record.message
        for record in caplog.records
        if record.levelno >= logging.WARNING
    )


def test_restore_mode_does_not_log_leak_warning(plugin, caplog):
    """Im Restore-Modus wurde die Mutation erfolgreich durchgeführt."""
    caplog.set_level(logging.WARNING)
    history = [
        {"role": "user", "content": "x"},
        {
            "role": "assistant",
            "content": "Antwort.",
            "reasoning": "Ich schicke die Mail an leak@example.com.",
        },
    ]

    plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010-ok",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert not any(
        "last_reasoning-Leak" in record.message
        for record in caplog.records
        if record.levelno >= logging.WARNING
    )


# ---------------------------------------------------------------------------
# 3. Edge: leere / ungültige Strukturen
# ---------------------------------------------------------------------------


def test_no_assistant_reasoning_no_leak_warning(plugin, caplog):
    """Wenn es kein Assistant-Reasoning gibt, wird keine Warnung geloggt."""
    caplog.set_level(logging.WARNING)
    history = [
        {"role": "user", "content": "x"},
        {"role": "assistant", "content": "Antwort."},
    ]

    plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010-empty",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    assert not any(
        "last_reasoning-Leak" in record.message
        for record in caplog.records
        if record.levelno >= logging.WARNING
    )


def test_non_dict_messages_are_skipped(plugin, caplog):
    """``find_last_assistant_reasoning`` überspringt Nicht-Dict-Einträge."""
    caplog.set_level(logging.WARNING)
    history = [
        None,
        {"role": "user", "content": "x"},
        {
            "role": "assistant",
            "content": "Antwort.",
            "reasoning": "Ich schicke die Mail an leak@example.com.",
        },
    ]

    plugin.post_llm_call(
        assistant_response="Antwort.",
        session_id="sess-gb010-mixed",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    last_reasoning = find_last_assistant_reasoning(history)
    assert last_reasoning is not None
    assert "leak@example.com" not in last_reasoning
    assert TOKEN_RE.search(last_reasoning)
