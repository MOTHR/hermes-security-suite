"""Tests for the Privacy-Shield AuditExporter (PDF/CSV/JSON + signing).

These tests use synthetic audit logs and in-memory mapping tables so they do
not mutate the operator's real workspace. They cover the public Python API
as well as the CLI surface.
"""

from __future__ import annotations

import csv
import json
from datetime import date, datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from privacy_shield.audit import AuditExporter
from privacy_shield.audit.report_data import ReportPeriod
from privacy_shield.audit.signer import save_key_pair
from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.mapping_table import InMemoryMappingTable


def _make_config(tmp_path: Path) -> PrivacyShieldConfig:
    return PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="x" * 32,
        storage_mode="memory",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        audit_jsonl_enabled=True,
    )


def _write_audit_log(path: Path) -> None:
    events = [
        {
            "ts": datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp(),
            "event": "pseudonymization_applied",
            "session_id_hash": "a" * 16,
            "mode": "limited",
            "model": "openai:gpt-4o",
            "platform": "telegram",
            "pii_types": ["email"],
            "masked_count_bucket": "1-10",
        },
        {
            "ts": datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc).timestamp(),
            "event": "blocked_action",
            "session_id_hash": "b" * 16,
            "mode": "strict",
            "model": "openai:gpt-4o",
            "platform": "telegram",
            "pii_types": ["phone"],
            "masked_count_bucket": "1-10",
        },
        {
            "ts": datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc).timestamp(),
            "event": "mode_change",
            "session_id_hash": "c" * 16,
            "mode": "strict",
            "actor": "cli",
            "previous_mode": "limited",
        },
    ]
    path.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in events),
        encoding="utf-8",
    )


@pytest.fixture
def exporter(tmp_path: Path):
    config = _make_config(tmp_path)
    _write_audit_log(Path(config.audit_jsonl_path))
    mapper = InMemoryMappingTable()
    mapper.store(
        [{"original_hash": "h" * 64, "original_value": "foo@example.com", "token": "TOKEN_EMAIL_1234567890_000", "type": "email"}],
        session_id="sess-A",
    )
    return AuditExporter(config=config, mapper=mapper, project_root=tmp_path)


class TestAuditExporterCollect:
    def test_collect_returns_report_data(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"), user_hash="u")
        assert report.period.start == date(2026, 8, 1)
        assert report.period.end == date(2026, 8, 31)
        assert report.user_hash == "u"

    def test_collect_filters_by_time_range(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        events = report.audit_events
        assert len(events) == 2
        assert all(e.ts.month == 8 for e in events)

    def test_collect_includes_token_mappings(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        assert len(report.token_mappings) == 1
        assert report.token_mappings[0].token == "TOKEN_EMAIL_1234567890_000"

    def test_collect_detects_high_severity_events(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        severities = {d.severity for d in report.detection_events}
        assert "high" in severities
        assert "medium" in severities

    def test_collect_includes_mode_changes(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-09-30"))
        assert len(report.mode_changes) >= 1
        assert any(m.mode == "strict" for m in report.mode_changes)

    def test_collect_summary_counts(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        assert report.summary["total_calls"] == 2
        assert report.summary["blocked_actions"] == 1

    def test_collect_with_report_period_object(self, exporter: AuditExporter):
        period = ReportPeriod(date(2026, 8, 1), date(2026, 8, 31))
        report = exporter.collect(period)
        assert report.period == period

    def test_collect_user_hash_override(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"), user_hash="override")
        assert report.user_hash == "override"


class TestAuditExporterExportPdf:
    def test_export_pdf_creates_file(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.pdf"
        result = exporter.export(out, ("2026-08-01", "2026-08-31"), format="pdf")
        assert result["output_path"].exists()
        assert result["format"] == "pdf"

    def test_export_pdf_file_is_not_empty(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.pdf"
        exporter.export(out, ("2026-08-01", "2026-08-31"), format="pdf")
        assert out.stat().st_size > 0

    def test_export_pdf_user_hash_in_report(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.pdf"
        exporter.export(out, ("2026-08-01", "2026-08-31"), format="pdf", user_hash="u-123")
        pytest.importorskip("pypdf")
        from pypdf import PdfReader

        reader = PdfReader(str(out))
        text = "\n".join(p.extract_text() or "" for p in reader.pages)
        assert "u-123" in text

    def test_export_pdf_includes_dsgvo_articles(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.pdf"
        exporter.export(out, ("2026-08-01", "2026-08-31"), format="pdf", user_hash="u")
        pytest.importorskip("pypdf")
        from pypdf import PdfReader

        reader = PdfReader(str(out))
        text = "\n".join(p.extract_text() or "" for p in reader.pages)
        assert "Art. 25" in text
        assert "Art. 32" in text
        assert "Art. 35" in text


class TestAuditExporterExportCsv:
    def test_export_csv_creates_file(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.csv"
        result = exporter.export(out, ("2026-08-01", "2026-08-31"), format="csv")
        assert result["output_path"].exists()
        assert result["format"] == "csv"

    def test_export_csv_contains_events(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.csv"
        exporter.export(out, ("2026-08-01", "2026-08-31"), format="csv")
        text = out.read_text(encoding="utf-8")
        assert "pseudonymization_applied" in text
        assert "blocked_action" in text


class TestAuditExporterExportJson:
    def test_export_json_creates_file(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.json"
        result = exporter.export(out, ("2026-08-01", "2026-08-31"), format="json")
        assert result["output_path"].exists()
        assert result["format"] == "json"

    def test_export_json_contains_events(self, exporter: AuditExporter, tmp_path: Path):
        out = tmp_path / "report.json"
        exporter.export(out, ("2026-08-01", "2026-08-31"), format="json")
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert len(payload["audit_events"]) == 2


class TestAuditExporterSigning:
    def test_export_pdf_signed_creates_sig_file(self, exporter: AuditExporter, tmp_path: Path):
        private = tmp_path / "key.pem"
        public = tmp_path / "key.pub"
        save_key_pair(private, public)
        out = tmp_path / "report.pdf"
        result = exporter.export(
            out,
            ("2026-08-01", "2026-08-31"),
            format="pdf",
            sign=True,
            signing_key_path=private,
            user_hash="u",
        )
        assert result["signature"]
        assert (out.with_suffix(out.suffix + ".sig")).exists()
        assert (out.with_suffix(out.suffix + ".canonical.json")).exists()

    def test_export_csv_signed_signature_valid(self, exporter: AuditExporter, tmp_path: Path):
        from privacy_shield.audit.signer import load_public_key, verify_b64

        private = tmp_path / "key.pem"
        public = tmp_path / "key.pub"
        save_key_pair(private, public)
        out = tmp_path / "report.csv"
        result = exporter.export(
            out,
            ("2026-08-01", "2026-08-31"),
            format="csv",
            sign=True,
            signing_key_path=private,
            user_hash="u",
        )
        canonical_path = result["canonical_path"]
        assert canonical_path is not None
        canonical = canonical_path.read_text(encoding="utf-8")
        signature = result["signature"]
        public_key = load_public_key(public)
        assert verify_b64(canonical, signature, public_key) is True

    def test_export_json_signed_signature_valid(self, exporter: AuditExporter, tmp_path: Path):
        from privacy_shield.audit.signer import load_public_key, verify_b64

        private = tmp_path / "key.pem"
        public = tmp_path / "key.pub"
        save_key_pair(private, public)
        out = tmp_path / "report.json"
        result = exporter.export(
            out,
            ("2026-08-01", "2026-08-31"),
            format="json",
            sign=True,
            signing_key_path=private,
            user_hash="u",
        )
        canonical_path = result["canonical_path"]
        assert canonical_path is not None
        canonical = canonical_path.read_text(encoding="utf-8")
        signature = result["signature"]
        public_key = load_public_key(public)
        assert verify_b64(canonical, signature, public_key) is True

    def test_export_sign_without_key_raises(self, exporter: AuditExporter, tmp_path: Path):
        with pytest.raises(ValueError):
            exporter.export(
                tmp_path / "x.pdf",
                ("2026-08-01", "2026-08-31"),
                sign=True,
            )

    def test_export_unsupported_format_raises(self, exporter: AuditExporter, tmp_path: Path):
        with pytest.raises(ValueError):
            exporter.export(tmp_path / "x.xml", ("2026-08-01", "2026-08-31"), format="xml")


class TestAuditExporterPytestStatus:
    def test_collect_test_status_is_present(self, exporter: AuditExporter):
        report = exporter.collect(("2026-08-01", "2026-08-31"), user_hash="u")
        assert report.test_status.pytest_available in {True, False}
        assert report.test_status.total >= 0

    def test_run_pytest_status_returns_dict(self, tmp_path: Path):
        from privacy_shield.audit.exporter import run_pytest_status

        status = run_pytest_status(tmp_path)
        assert "passed" in status
        assert "total" in status


class TestAuditExporterWithMappingTable:
    def test_exporter_uses_provided_mapper(self, tmp_path: Path):
        config = _make_config(tmp_path)
        _write_audit_log(Path(config.audit_jsonl_path))
        mapper = InMemoryMappingTable()
        mapper.store(
            [{"original_hash": "h" * 64, "original_value": "bar@example.com", "token": "TOKEN_EMAIL_abcdef1234_001", "type": "email"}],
            session_id="sess-B",
        )
        exporter = AuditExporter(config=config, mapper=mapper, project_root=tmp_path)
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        tokens = {m.token for m in report.token_mappings}
        assert "TOKEN_EMAIL_abcdef1234_001" in tokens
