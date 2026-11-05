"""Tests for the audit CSV and JSON renderers.

These tests exercise ``render_csv`` and ``render_json`` with synthetic
``ReportData`` objects. They do not depend on the real audit log or mapping
table and run entirely inside ``tmp_path``.
"""

from __future__ import annotations

import csv
import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from privacy_shield.audit.csv_renderer import (
    period_from_strings,
    render_csv,
    render_json,
    report_to_json,
)
from privacy_shield.audit.report_data import (
    AuditEvent,
    ComplianceArticle,
    DetectionEvent,
    ModeChange,
    ReportData,
    ReportPeriod,
    TestStatus,
    TokenMapping,
)


def _make_report(**overrides):
    period = ReportPeriod(date(2026, 8, 1), date(2026, 8, 31))
    return ReportData(
        period=period,
        user_hash="user-deadbeef",
        generated_at=datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc),
        audit_events=[
            AuditEvent(
                ts=datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc),
                event="pseudonymization_applied",
                session_id_hash="a" * 16,
                mode="limited",
                model="openai:gpt-4o",
                platform="telegram",
                pii_types=["email"],
                masked_count_bucket="1-10",
                severity="medium",
            ),
        ],
        token_mappings=[
            TokenMapping(
                original_hash="h" * 64,
                token="TOKEN_EMAIL_1234567890_000",
                type="email",
                created_at=datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp(),
                session_id="sess-A",
            ),
        ],
        detection_events=[
            DetectionEvent(
                ts=datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc),
                severity="medium",
                event="pseudonymization_applied",
                pii_types=["email"],
                session_id_hash="a" * 16,
                mode="limited",
            ),
        ],
        mode_changes=[
            ModeChange(
                ts=datetime(2026, 8, 15, 9, 0, 0, tzinfo=timezone.utc),
                mode="limited",
                actor="cli",
                session_id_hash="a" * 16,
            ),
        ],
        test_status=TestStatus(
            passed=599,
            failed=0,
            skipped=0,
            total=599,
            coverage_percent=87.5,
            pytest_available=True,
        ),
        eu_ai_act_articles=[
            ComplianceArticle(
                key="art_9",
                title="Article 9",
                description="Risk management.",
                regulation="EU AI Act",
            ),
        ],
        dsgvo_articles=[
            ComplianceArticle(
                key="art_25",
                title="Art. 25",
                description="Privacy by design.",
                regulation="DSGVO",
            ),
        ],
        summary={"total_calls": 1, "pii_detections": 1},
        signature="sig-placeholder",
    )


def _read_csv_sections(path: Path):
    """Return a dict mapping section name to list of rows."""
    sections: dict[str, list[list[str]]] = {}
    current: list[list[str]] = []
    current_name = ""
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if row and row[0].startswith("# section"):
                if current_name:
                    sections[current_name] = current
                current_name = row[1]
                current = []
            else:
                current.append(row)
        if current_name:
            sections[current_name] = current
    return sections


class TestRenderCsv:
    def test_csv_file_created(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        assert out.exists()

    def test_csv_contains_metadata_section(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        assert "metadata" in sections
        assert ["period", "2026-08-01 — 2026-08-31"] in sections["metadata"]

    def test_csv_contains_user_hash(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        text = out.read_text(encoding="utf-8")
        assert "user-deadbeef" in text

    def test_csv_contains_token_mapping_row(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("token_mappings", [])
        assert any("TOKEN_EMAIL_1234567890_000" in ",".join(r) for r in rows)

    def test_csv_contains_audit_event_row(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("audit_events", [])
        assert any("pseudonymization_applied" in ",".join(r) for r in rows)

    def test_csv_contains_detection_event_row(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("detection_events", [])
        assert any("medium" in ",".join(r) for r in rows)

    def test_csv_contains_mode_change_row(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("mode_changes", [])
        assert any("cli" in ",".join(r) for r in rows)

    def test_csv_contains_compliance_articles(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("compliance_articles", [])
        assert any("Article 9" in ",".join(r) for r in rows)
        assert any("Art. 25" in ",".join(r) for r in rows)

    def test_csv_contains_test_status(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("test_status", [])
        assert any("passed" in ",".join(r) for r in rows)
        assert any("599" in ",".join(r) for r in rows)

    def test_csv_contains_signature(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("signature", [])
        assert any("sig-placeholder" in ",".join(r) for r in rows)

    def test_csv_empty_report_renders(self, tmp_path: Path):
        report = _make_report()
        report.audit_events = []
        report.token_mappings = []
        report.detection_events = []
        report.mode_changes = []
        out = tmp_path / "empty.csv"
        render_csv(report, out)
        assert out.exists()

    def test_csv_multiple_pii_types_joined_with_semicolon(self, tmp_path: Path):
        report = _make_report()
        report.audit_events[0].pii_types = ["email", "phone", "iban"]
        out = tmp_path / "report.csv"
        render_csv(report, out)
        sections = _read_csv_sections(out)
        rows = sections.get("audit_events", [])
        assert any("email;phone;iban" in ",".join(r) for r in rows)

    def test_csv_created_at_is_float(self, tmp_path: Path):
        out = tmp_path / "report.csv"
        render_csv(_make_report(), out)
        sections = _read_csv_sections(out)
        rows = sections.get("token_mappings", [])
        data_rows = [r for r in rows if r and r[0].startswith("h")]
        assert data_rows
        assert data_rows[0][3].replace(".", "").isdigit() or data_rows[0][3][0].isdigit()


class TestRenderJson:
    def test_json_file_created(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        assert out.exists()

    def test_json_roundtrip(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["user_hash"] == "user-deadbeef"
        assert payload["summary"]["total_calls"] == 1

    def test_json_contains_audit_events(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert len(payload["audit_events"]) == 1
        assert payload["audit_events"][0]["event"] == "pseudonymization_applied"

    def test_json_contains_token_mappings(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["token_mappings"][0]["token"] == "TOKEN_EMAIL_1234567890_000"

    def test_json_contains_detection_events(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["detection_events"][0]["severity"] == "medium"

    def test_json_contains_mode_changes(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["mode_changes"][0]["actor"] == "cli"

    def test_json_contains_compliance_articles(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        eu_keys = {a["key"] for a in payload["eu_ai_act_articles"]}
        dsgvo_keys = {a["key"] for a in payload["dsgvo_articles"]}
        assert "art_9" in eu_keys
        assert "art_25" in dsgvo_keys

    def test_json_contains_test_status(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["test_status"]["passed"] == 599
        assert payload["test_status"]["coverage_percent"] == 87.5

    def test_json_datetimes_are_iso_strings(self, tmp_path: Path):
        out = tmp_path / "report.json"
        render_json(_make_report(), out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["generated_at"] == "2026-08-22T12:00:00+00:00"

    def test_json_empty_report_roundtrip(self, tmp_path: Path):
        report = _make_report()
        report.audit_events = []
        report.token_mappings = []
        report.detection_events = []
        report.mode_changes = []
        out = tmp_path / "empty.json"
        render_json(report, out)
        payload = json.loads(out.read_text(encoding="utf-8"))
        assert payload["audit_events"] == []


class TestReportToJson:
    def test_report_to_json_is_deterministic(self):
        report = _make_report()
        j1 = report_to_json(report)
        j2 = report_to_json(report)
        assert j1 == j2

    def test_report_to_json_sorted_keys(self):
        report = _make_report()
        j = report_to_json(report)
        assert j.startswith('{"audit_events":') or j.startswith('{"detection_events":')
        # sorted keys means the first key is alphabetically first

    def test_report_to_json_signature_field_present(self):
        report = _make_report()
        report.signature = "abc"
        j = report_to_json(report)
        assert '"signature": "abc"' in j


class TestPeriodFromStrings:
    def test_period_from_strings_parses_dates(self):
        period = period_from_strings("2026-08-01", "2026-08-31")
        assert period.start == date(2026, 8, 1)
        assert period.end == date(2026, 8, 31)

    def test_period_from_strings_invalid_date_raises(self):
        with pytest.raises(ValueError):
            period_from_strings("not-a-date", "2026-08-31")

    def test_period_iso_range(self):
        period = ReportPeriod(date(2026, 8, 1), date(2026, 8, 31))
        assert period.iso_range() == "2026-08-01 — 2026-08-31"
