"""Tests for the Privacy-Shield audit PDF export (v1.4.0).

Covers:

* Empty audit log → cover + empty summary
* 100 events → PDF smaller than 5 MiB
* pypdf text extraction contains all EU AI Act article mappings
* SHA-256 signature is deterministic for the same input
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from privacy_shield.audit_pdf import (
    ReportPeriod,
    generate_audit_pdf,
    generate_audit_report,
    load_article_mapping,
    load_audit_events,
    summarize_events,
)

pytest.importorskip("pypdf")
from pypdf import PdfReader


def _extract_pdf_text(path: Path) -> str:
    reader = PdfReader(str(path))
    parts: list[str] = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            parts.append(text)
    return "\n".join(parts)


def _write_audit_log(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n")


def _sample_event(offset: int = 0, pii: bool = True, blocked: bool = False) -> dict:
    base_ts = datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    event = {
        "ts": base_ts + offset,
        "event": "blocked_action" if blocked else "pseudonymization_applied",
        "session_id_hash": "a" * 16,
        "mode": "limited",
        "model": "openai:gpt-4o",
        "platform": "telegram",
    }
    if pii:
        event["pii_types"] = ["email"]
        event["masked_count_bucket"] = "1-10"
    return event


class TestAuditEventHelpers:
    def test_load_empty_log(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        path.write_text("", encoding="utf-8")
        assert load_audit_events(path) == []

    def test_load_and_filter_by_period(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        events = [
            _sample_event(0),
            {**_sample_event(86400), "ts": datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()},
        ]
        _write_audit_log(path, events)
        period = ReportPeriod(
            date(2026, 8, 1),
            date(2026, 8, 31),
        )
        loaded = load_audit_events(path, period=period)
        assert len(loaded) == 1
        assert loaded[0]["event"] == "pseudonymization_applied"

    def test_summarize_counts(self):
        events = [
            _sample_event(0, pii=True, blocked=False),
            _sample_event(1, pii=True, blocked=False),
            _sample_event(2, pii=False, blocked=True),
        ]
        summary = summarize_events(events)
        assert summary == {"total_calls": 3, "pii_detections": 2, "blocked_actions": 1}


class TestAuditPdfExport:
    def test_empty_log_generates_cover_and_summary(self, tmp_path: Path):
        out = tmp_path / "empty.pdf"
        signature = generate_audit_pdf(
            out,
            events=[],
            period=ReportPeriod(
                date(2026, 8, 1),
                date(2026, 8, 31),
            ),
            user_hash="user-deadbeef",
        )
        assert out.exists()
        text = _extract_pdf_text(out)
        assert "Hermes Privacy-Shield" in text
        assert "2026-08-01 — 2026-08-31" in text
        assert "user-deadbeef" in text
        assert "Total Calls" in text
        assert "0" in text
        assert signature

    def test_hundred_events_pdf_under_5mb(self, tmp_path: Path):
        out = tmp_path / "hundred.pdf"
        events = [_sample_event(i) for i in range(100)]
        generate_audit_pdf(
            out,
            events=events,
            period=ReportPeriod(
                date(2026, 8, 1),
                date(2026, 8, 31),
            ),
            user_hash="user-abc123",
        )
        assert out.exists()
        assert out.stat().st_size < 5 * 1024 * 1024

    def test_article_mappings_readable_in_pdf(self, tmp_path: Path):
        out = tmp_path / "articles.pdf"
        articles = load_article_mapping()
        generate_audit_pdf(
            out,
            events=[_sample_event(0)],
            period=ReportPeriod(
                date(2026, 8, 1),
                date(2026, 8, 31),
            ),
            user_hash="user-articles",
            articles=articles,
        )
        text = _extract_pdf_text(out)
        assert "Article 9" in text
        assert "Article 11" in text
        assert "Article 12" in text
        assert "Article 14" in text
        assert "Risk Management" in text
        assert "Quality Management" in text
        assert "Record-Keeping" in text
        assert "Human Oversight" in text

    def test_signature_is_deterministic(self, tmp_path: Path):
        out1 = tmp_path / "sig1.pdf"
        out2 = tmp_path / "sig2.pdf"
        events = [_sample_event(0), _sample_event(1)]
        period = ReportPeriod(
            date(2026, 8, 1),
            date(2026, 8, 31),
        )
        sig1 = generate_audit_pdf(out1, events, period, "user-x")
        sig2 = generate_audit_pdf(out2, events, period, "user-x")
        assert sig1 == sig2
        assert len(sig1) == 64
        # verify hash is hex sha256
        int(sig1, 16)

    def test_cli_helper_filters_by_date(self, tmp_path: Path):
        log_path = tmp_path / "audit.jsonl"
        events = [
            _sample_event(0),
            {**_sample_event(1), "ts": datetime(2026, 9, 15, tzinfo=timezone.utc).timestamp()},
        ]
        _write_audit_log(log_path, events)
        out = tmp_path / "cli.pdf"
        sig = generate_audit_report(
            log_path=log_path,
            output_path=out,
            from_date="2026-08-01",
            to_date="2026-08-31",
            user_hash="user-cli",
        )
        text = _extract_pdf_text(out)
        assert sig
        assert "pseudonymization_applied" in text
        # only the August event is present
        assert text.count("pseudonymization_applied") == 1

    def test_yaml_mapping_loads_from_disk(self, tmp_path: Path):
        yaml_path = tmp_path / "audit_articles.yaml"
        yaml_path.write_text(
            "articles:\n  art_9:\n    title: \"Article 9 — Custom\"\n    description: \"Custom evidence\"\n",
            encoding="utf-8",
        )
        mapping = load_article_mapping(yaml_path)
        assert mapping["art_9"]["title"] == "Article 9 — Custom"


class TestReportSignature:
    def test_signature_changes_when_user_hash_changes(self, tmp_path: Path):
        events = [_sample_event(0)]
        period = ReportPeriod(
            date(2026, 8, 1),
            date(2026, 8, 31),
        )
        sig_a = generate_audit_pdf(tmp_path / "a.pdf", events, period, "user-a")
        sig_b = generate_audit_pdf(tmp_path / "b.pdf", events, period, "user-b")
        assert sig_a != sig_b
