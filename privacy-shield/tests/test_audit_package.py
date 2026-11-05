"""Tests for the ``privacy_shield.audit`` package public API and backward
compatibility after the v1.4.0 package restructure.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from privacy_shield import audit as audit_package
from privacy_shield.audit import (
    AuditExporter,
    AuditLogger,
    _bucket_count,
    _MAX_AUDIT_EVENTS,
    generate_signing_key,
    hash_session_key,
)
from privacy_shield.audit.csv_renderer import period_from_strings, render_csv
from privacy_shield.audit.pdf_renderer import render_pdf
from privacy_shield.audit.report_data import AuditEvent, ReportData
from privacy_shield.audit.signer import save_key_pair
from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.mapping_table import InMemoryMappingTable


class TestAuditPackageExports:
    def test_audit_logger_is_exported(self):
        assert AuditLogger is not None
        assert hasattr(AuditLogger, "log")

    def test_legacy_helpers_exported(self):
        assert callable(hash_session_key)
        assert callable(_bucket_count)
        assert isinstance(_MAX_AUDIT_EVENTS, int)
        assert _MAX_AUDIT_EVENTS > 0

    def test_new_exports_present(self):
        assert callable(AuditExporter)
        assert callable(generate_signing_key)


class TestBucketCount:
    @pytest.mark.parametrize(
        ("count", "expected"),
        [
            (0, "0"),
            (5, "1-10"),
            (15, "1-100"),
            (150, "1-1000"),
            (1500, "10000+"),
        ],
    )
    def test_bucket_count_values(self, count: int, expected: str):
        assert _bucket_count(count) == expected


class TestHashSessionKey:
    def test_deterministic_and_distinct(self):
        h1 = hash_session_key("session-abc")
        h2 = hash_session_key("session-abc")
        h3 = hash_session_key("session-xyz")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) >= 8


class TestRenderersWithSignature:
    def _empty_report(self, signature: str | None) -> ReportData:
        return ReportData(
            period=period_from_strings("2026-08-01", "2026-08-31"),
            user_hash="u",
            generated_at=datetime.now(tz=timezone.utc),
            audit_events=[],
            token_mappings=[],
            detection_events=[],
            mode_changes=[],
            test_status=audit_package.report_data.TestStatus(),
            eu_ai_act_articles=[],
            dsgvo_articles=[],
            signature=signature,
        )

    def test_render_pdf_with_signature(self, tmp_path: Path):
        out = tmp_path / "signed.pdf"
        sig = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w=="
        render_pdf(self._empty_report(sig), out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_render_csv_with_signature(self, tmp_path: Path):
        out = tmp_path / "signed.csv"
        sig = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5fYGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T19vf4+fr7/P3+/w=="
        render_csv(self._empty_report(sig), out)
        assert out.exists()
        text = out.read_text(encoding="utf-8")
        assert "signature" in text

    def test_render_csv_without_signature(self, tmp_path: Path):
        out = tmp_path / "unsigned.csv"
        render_csv(self._empty_report(None), out)
        assert out.exists()


class TestAuditEventDefaults:
    def test_defaults(self):
        e = AuditEvent(ts=datetime.now(tz=timezone.utc), event="x")
        assert e.session_id_hash == ""
        assert e.mode == ""
        assert e.severity == "info"
        assert e.pii_types == []


class TestAuditExporterDefaults:
    def test_default_user_hash_is_unknown(self, tmp_path: Path):
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="x" * 32,
            storage_mode="memory",
            audit_jsonl_path=str(tmp_path / "audit.jsonl"),
            audit_jsonl_enabled=True,
        )
        Path(config.audit_jsonl_path).write_text("", encoding="utf-8")
        exporter = AuditExporter(config=config, mapper=InMemoryMappingTable(), project_root=tmp_path)
        report = exporter.collect(("2026-08-01", "2026-08-31"))
        assert report.user_hash == "unknown"


class TestSignerKeyPair:
    def test_save_and_load(self, tmp_path: Path):
        private = tmp_path / "k.pem"
        public = tmp_path / "k.pub"
        save_key_pair(private, public)
        from privacy_shield.audit.signer import load_private_key, load_public_key

        assert load_private_key(private)
        assert load_public_key(public)


class TestCollectorHelpers:
    def test_load_article_mapping_default(self):
        from privacy_shield.audit.collector import load_article_mapping

        articles = load_article_mapping()
        keys = {a.key for a in articles}
        assert "art_9" in keys
        assert "art_25" in keys
        assert "art_32" in keys
        assert "art_35" in keys

    def test_detection_event_severity_mapping(self):
        from privacy_shield.audit.collector import _event_severity

        assert _event_severity("blocked_action") == "high"
        assert _event_severity("output_pii_detected") == "high"
        assert _event_severity("pseudonymization_applied") == "medium"
        assert _event_severity("mode_change") == "info"
        assert _event_severity("restore") == "low"
        assert _event_severity("unknown") == "info"
