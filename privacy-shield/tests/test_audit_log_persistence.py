"""FIX-PS3: persistenter Audit-Trail (JSONL, chmod 600).

Akzeptanzkriterien für BUTLER-PS-2 HIGH:

- ``PrivacyShieldPlugin.pre_llm_call`` schreibt ein Audit-Event in das
  JSONL-Audit-File sobald Tokens maskiert wurden.
- ``PrivacyShieldPlugin.post_llm_call`` schreibt ein Audit-Event sobald
  frische PII im LLM-Response erkannt wurde.
- Das Audit-File hat nach jedem Schreibvorgang chmod 600.
- Der Audit-Logger ist side-channel-safe: count bucket, type samples
  (max 3), SHA-256-prefixed session_id_hash, kein Klartext-PII.

Jeder Test räumt das File im Fixture auf, damit er isoliert läuft.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

import pytest

from privacy_shield.audit import (
    AuditLogger,
    _bucket_count,
    hash_session_key,
)
from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin


# ── Helpers ─────────────────────────────────────────────────────────────


def _make_plugin(tmp_path: Path) -> PrivacyShieldPlugin:
    """Build a PrivacyShieldPlugin whose audit file lives in tmp_path.

    This keeps the test fully isolated from the on-disk workspace file
    while exercising the full production code path (real
    ``pre_llm_call`` / ``post_llm_call``, real ``AuditLogger``).
    """
    audit_path = tmp_path / "audit.jsonl"
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="x" * 32,
        storage_mode="memory",
        audit_jsonl_path=str(audit_path),
        audit_jsonl_enabled=True,
    )
    return PrivacyShieldPlugin(config=config)


def _read_audit_lines(path: Path) -> list[dict]:
    """Read every JSONL line from the audit file."""
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def _file_mode(path: Path) -> int:
    """Return the POSIX mode bits for the file."""
    return stat.S_IMODE(os.stat(path).st_mode)


# ── Class 1: AuditLogger unit tests ──────────────────────────────────────


class TestAuditLoggerWrites:
    """Direct unit tests for ``AuditLogger``: file creation, mode, content."""

    def test_creates_file_with_chmod_600(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        assert logger.log(event="test_event", masked_count=1)
        assert path.exists()
        # The file must be owner-readable + owner-writable, nothing else.
        assert _file_mode(path) == 0o600

    def test_creates_parent_dir_with_chmod_700(self, tmp_path: Path):
        path = tmp_path / "nested" / "deeper" / "audit.jsonl"
        AuditLogger(str(path))
        # mkdir -p + chmod 700 must have happened.
        assert path.parent.exists()
        assert _file_mode(path.parent) == 0o700

    def test_appends_jsonl_one_object_per_line(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        logger.log(event="evt_a", masked_count=1)
        logger.log(event="evt_b", masked_count=5)
        logger.log(event="evt_c", masked_count=42)
        lines = _read_audit_lines(path)
        assert [e["event"] for e in lines] == ["evt_a", "evt_b", "evt_c"]
        # Every line is a parseable JSON object on its own.
        with path.open("r", encoding="utf-8") as fh:
            raw_lines = [ln for ln in fh.read().split("\n") if ln.strip()]
        assert len(raw_lines) == 3

    def test_session_id_is_hashed_and_truncated(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        logger.log(event="x", session_id="session-with-secret-12345")
        event = _read_audit_lines(path)[0]
        # Raw session id must NEVER leak into the audit log.
        assert "session-with-secret" not in event["session_id_hash"]
        assert event["session_id_hash"] == hash_session_key(
            "session-with-secret-12345"
        )
        assert len(event["session_id_hash"]) == 16

    def test_count_is_bucketed_not_plaintext(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        logger.log(event="x", masked_count=42)
        event = _read_audit_lines(path)[0]
        # The raw integer must not appear; only the bucket string.
        assert event["masked_count_bucket"] == _bucket_count(42)
        assert "42" not in event["masked_count_bucket"]

    def test_pii_types_capped_at_three_and_deduped(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        logger.log(
            event="x",
            pii_types=["email", "phone", "email", "ssn", "iban"],
        )
        event = _read_audit_lines(path)[0]
        assert event["pii_types"] == ["email", "phone", "ssn"]

    def test_fail_soft_when_dir_unwritable(self, tmp_path: Path):
        # Build a path whose parent is a *file* (mkdir fails).  Audit
        # logging must return False but never raise — the hot-path is
        # contract-bound to never throw out of the audit call.
        blocker = tmp_path / "blocker"
        blocker.write_text("not-a-directory")
        path = blocker / "audit.jsonl"
        logger = AuditLogger(str(path))
        # We do not assert the return value here: it depends on the
        # filesystem but log() must never raise.
        try:
            logger.log(event="x")
        except Exception as exc:  # pragma: no cover - defensive
            pytest.fail(f"AuditLogger.log must not raise, got {exc!r}")


# ── Class 2: plugin integration tests ───────────────────────────────────


class TestPluginEmitsAuditEvents:
    """pre_llm_call + post_llm_call write audit events when triggered."""

    def test_pre_llm_call_writes_pseudonymization_event(self, tmp_path: Path):
        plugin = _make_plugin(tmp_path)
        result = plugin.pre_llm_call(
            prompt="Email: foo@example.com und Telefon +49 30 1234567",
            context={
                "session_id": "sess-A",
                "model": "openai:gpt-4o",
                "platform": "telegram",
            },
        )
        # Sanity: pseudonymization actually happened.
        assert result is not None and "foo@example.com" not in result["user_message"]

        path = Path(plugin.config.audit_jsonl_path)
        events = _read_audit_lines(path)
        assert len(events) == 1
        evt = events[0]
        assert evt["event"] == "pseudonymization_applied"
        assert evt["mode"] == "limited"
        assert evt["session_id_hash"] == hash_session_key("sess-A")
        assert evt["model"] == "openai:gpt-4o"
        assert evt["platform"] == "telegram"
        # Side-channel safety on the audit line.
        assert "foo@example.com" not in json.dumps(evt)
        assert "+49 30 1234567" not in json.dumps(evt)
        assert "sess-A" not in json.dumps(evt)

    def test_pre_llm_call_no_audit_when_no_pii(self, tmp_path: Path):
        plugin = _make_plugin(tmp_path)
        plugin.pre_llm_call(
            prompt="Just talking about the weather.",
            context={"session_id": "sess-clean", "model": "openai:gpt-4o"},
        )
        # No detection → no audit line (we only log after pseudonymisation).
        assert _read_audit_lines(Path(plugin.config.audit_jsonl_path)) == []

    def test_post_llm_call_writes_output_pii_event(self, tmp_path: Path):
        plugin = _make_plugin(tmp_path)
        plugin.post_llm_call(
            assistant_response="Antwort mit leak: hallo@example.com",
            session_id="sess-B",
            model="openai:gpt-4o",
            platform="telegram",
        )
        path = Path(plugin.config.audit_jsonl_path)
        events = _read_audit_lines(path)
        assert len(events) == 1
        evt = events[0]
        assert evt["event"] == "output_pii_detected"
        assert evt["mode"] == "limited"
        assert evt["session_id_hash"] == hash_session_key("sess-B")
        assert evt["pii_types"]  # at least one type
        # Side-channel safety.
        assert "hallo@example.com" not in json.dumps(evt)

    def test_post_llm_call_no_audit_on_clean_response(self, tmp_path: Path):
        plugin = _make_plugin(tmp_path)
        plugin.post_llm_call(
            assistant_response="Alles klar, keine PII.",
            session_id="sess-clean",
            model="openai:gpt-4o",
        )
        assert _read_audit_lines(Path(plugin.config.audit_jsonl_path)) == []

    def test_post_llm_call_paranoid_still_writes_audit_before_raise(
        self, tmp_path: Path
    ):
        """Even in paranoid mode the audit event must persist before raising."""
        config = PrivacyShieldConfig(
            enabled=True,
            mode="paranoid",
            encryption_key="x" * 32,
            storage_mode="memory",
            audit_jsonl_path=str(tmp_path / "audit.jsonl"),
            audit_jsonl_enabled=True,
        )
        plugin = PrivacyShieldPlugin(config=config)
        with pytest.raises(PermissionError):
            plugin.post_llm_call(
                assistant_response="leak: foo@bar.com",
                session_id="sess-X",
                model="openai:gpt-4o",
            )
        events = _read_audit_lines(tmp_path / "audit.jsonl")
        assert len(events) == 1
        assert events[0]["event"] == "output_pii_detected"
        assert events[0]["mode"] == "paranoid"


# ── Class 3: file-permission contract ────────────────────────────────────


class TestAuditFilePermissions:
    """The audit file is owner-only on every write path."""

    def test_chmod_600_after_each_write(self, tmp_path: Path):
        logger = AuditLogger(str(tmp_path / "audit.jsonl"))
        for i in range(3):
            logger.log(event="evt", masked_count=i)
            assert _file_mode(tmp_path / "audit.jsonl") == 0o600

    def test_chmod_600_repaired_on_init_if_file_existed_loose(
        self, tmp_path: Path
    ):
        path = tmp_path / "audit.jsonl"
        path.write_text('{"event":"legacy"}\n')
        os.chmod(path, 0o644)  # simulate pre-FIX-PS3 deployment
        AuditLogger(str(path))
        assert _file_mode(path) == 0o600


# ── Class 4: rotate-on-growth ───────────────────────────────────────────


class TestAuditRotate:
    """The audit file self-rotates past ``_MAX_AUDIT_EVENTS`` entries."""

    def test_caps_log_size_at_max_events(self, tmp_path: Path):
        from privacy_shield.audit import _MAX_AUDIT_EVENTS

        path = tmp_path / "audit.jsonl"
        logger = AuditLogger(str(path))
        # Write more than the cap.
        for i in range(_MAX_AUDIT_EVENTS + 50):
            assert logger.log(event="evt", masked_count=i)
        events = _read_audit_lines(path)
        # After rotate, the file holds at most the cap.
        assert len(events) <= _MAX_AUDIT_EVENTS
        # And the newest entries are preserved (FIFO drop).
        assert events[-1]["masked_count_bucket"] == _bucket_count(
            _MAX_AUDIT_EVENTS + 49
        )
