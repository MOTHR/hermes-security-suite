"""GB-010 Mode-Guard: bei ``reasoning.mode=off`` darf der defensive
Verifier keine "Reasoning-Hook hat nicht gegriffen"-Warning loggen.

Reproduziert Bug A aus t_8402d518: mode=off überspringt die Tokenisierung
absichtlich — die darauffolgende GB-010-Warnung war ein False-Positive,
der echte Reasoning-Leaks maskieren kann (Boy-Who-Cried-Wolf).
"""

from __future__ import annotations

import logging
from pathlib import Path

from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin


def _plugin(tmp_path: Path) -> PrivacyShieldPlugin:
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        reasoning=ReasoningBlockConfig(mode="off"),
    )
    return PrivacyShieldPlugin(config=config)


def test_gb010_mode_off_no_warning(tmp_path: Path, caplog):
    """post_llm_call mit reasoning-haltiger History: KEINE Hook-Warning."""
    caplog.set_level(logging.WARNING)
    plugin = _plugin(tmp_path)
    assert plugin.config.reasoning.mode == "off"

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
        session_id="sess-gb010-mode-off",
        model="openai:gpt-4o",
        conversation_history=history,
    )

    warnings = [
        record.message
        for record in caplog.records
        if record.levelno >= logging.WARNING
    ]
    assert not any(
        "Reasoning-Hook hat nicht gegriffen" in msg for msg in warnings
    ), f"False-Positive-Warning geloggt: {warnings!r}"