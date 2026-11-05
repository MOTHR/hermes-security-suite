"""Spec v1.1 Section 4c — block-signal contract tests.

strict/paranoid blocks are returned as ``{"blocked": True,
"block_reason": ...}`` instead of raised, because the Core hook
dispatcher swallows every exception inside pre_llm_call hooks. The
Core override-capture consumes the signal and hard-fails the turn
before the API call. Also asserts the audit event written alongside
the block.

Provider bypass note (pre-existing design): local Ollama calls are
skipped entirely by ``_should_bypass`` BEFORE any mode logic, so a
strict/paranoid block only fires on non-bypassed (cloud) providers.
"""

import json
from pathlib import Path

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin


def _read_audit_lines(path: Path) -> list[dict]:
    lines: list[dict] = []
    if not path.exists():
        return lines
    for raw in path.read_text().splitlines():
        raw = raw.strip()
        if raw:
            lines.append(json.loads(raw))
    return lines


def _plugin(tmp_path: Path, mode: str) -> PrivacyShieldPlugin:
    config = PrivacyShieldConfig(
        enabled=True,
        mode=mode,
        encryption_key="x" * 32,
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        audit_jsonl_enabled=True,
    )
    return PrivacyShieldPlugin(config=config)


class TestBlockSignal:
    def test_strict_cloud_returns_block_signal(self, tmp_path: Path):
        plugin = _plugin(tmp_path, "strict")
        result = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-bs", "provider": "openai"},
        )
        assert isinstance(result, dict)
        assert result["blocked"] is True
        assert "strict mode" in result["block_reason"]
        # No sanitized replacement rides along with a block.
        assert "user_message" not in result

    def test_paranoid_cloud_returns_block_signal(self, tmp_path: Path):
        plugin = _plugin(tmp_path, "paranoid")
        result = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-bs", "provider": "openai"},
        )
        assert isinstance(result, dict) and result["blocked"] is True
        assert "paranoid mode" in result["block_reason"]

    def test_local_provider_bypass_stays_untouched(self, tmp_path: Path):
        """Pre-existing bypass contract: ollama calls skip the shield."""
        plugin = _plugin(tmp_path, "strict")
        result = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-bs", "provider": "ollama"},
        )
        assert result is None

    def test_pseudonymize_mode_not_blocked(self, tmp_path: Path):
        plugin = _plugin(tmp_path, "limited")
        result = plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-bs", "provider": "openai"},
        )
        assert result is not None
        assert result.get("blocked") is not True
        assert "TOKEN_EMAIL_" in result["user_message"]

    def test_block_writes_audit_event(self, tmp_path: Path):
        plugin = _plugin(tmp_path, "paranoid")
        plugin.pre_llm_call(
            "email: alice@example.com",
            context={"session_id": "sess-audit", "provider": "openai"},
        )
        events = _read_audit_lines(tmp_path / "audit.jsonl")
        blocked = [e for e in events if e["event"] == "llm_call_blocked"]
        assert len(blocked) == 1
        assert blocked[0]["mode"] == "paranoid"
        assert blocked[0]["masked_count_bucket"] == "1-1"
        assert "email" in blocked[0]["pii_types"]