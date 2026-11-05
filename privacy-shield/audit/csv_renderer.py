"""CSV and JSON renderers for Privacy-Shield audit reports.

The CSV format is machine-readable and keeps all sections in one file
(metadata, summary, token mappings, events, detections, mode changes,
compliance articles, test status, signature). The JSON format is a direct
serialisation of the ``ReportData`` dataclass.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

from .report_data import ComplianceArticle, ReportData, ReportPeriod


class _DateTimeEncoder(json.JSONEncoder):
    """Serialise ``date`` and ``datetime`` objects as ISO 8601 strings."""

    def default(self, o: Any) -> Any:
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        if isinstance(o, Path):
            return str(o)
        return super().default(o)


def _format_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def render_csv(report: ReportData, output_path: Path) -> None:
    """Write ``report`` to ``output_path`` as a single multi-section CSV.

    Each section is introduced by a ``# <section>`` comment row. The
    metadata / summary / test-status / signature sections have key/value
    columns; list sections have their own header row.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)

        writer.writerow(["# section", "metadata"])
        writer.writerow(["period", report.period.iso_range()])
        writer.writerow(["user_hash", report.user_hash])
        writer.writerow(["generated_at", _format_ts(report.generated_at)])
        writer.writerow([])

        writer.writerow(["# section", "summary"])
        writer.writerow(["key", "value"])
        for key, value in report.summary.items():
            writer.writerow([key, str(value)])
        writer.writerow([])

        writer.writerow(["# section", "token_mappings"])
        writer.writerow(["original_hash", "token", "type", "created_at", "session_id"])
        for m in report.token_mappings:
            writer.writerow([m.original_hash, m.token, m.type, m.created_at, m.session_id])
        writer.writerow([])

        writer.writerow(["# section", "audit_events"])
        writer.writerow(
            ["timestamp", "event", "session_id_hash", "mode", "model", "platform", "pii_types", "count_bucket", "severity", "owasp_risk", "atlas_technique"]
        )
        for e in report.audit_events:
            writer.writerow(
                [
                    _format_ts(e.ts),
                    e.event,
                    e.session_id_hash,
                    e.mode,
                    e.model,
                    e.platform,
                    ";".join(e.pii_types),
                    e.masked_count_bucket,
                    e.severity,
                    e.owasp_risk,
                    e.atlas_technique,
                ]
            )
        writer.writerow([])

        writer.writerow(["# section", "detection_events"])
        writer.writerow(["timestamp", "severity", "event", "pii_types", "session_id_hash", "mode"])
        for d in report.detection_events:
            writer.writerow(
                [
                    _format_ts(d.ts),
                    d.severity,
                    d.event,
                    ";".join(d.pii_types),
                    d.session_id_hash,
                    d.mode,
                ]
            )
        writer.writerow([])

        writer.writerow(["# section", "mode_changes"])
        writer.writerow(["timestamp", "mode", "actor", "session_id_hash"])
        for mode_change in report.mode_changes:
            writer.writerow([_format_ts(mode_change.ts), mode_change.mode, mode_change.actor, mode_change.session_id_hash])
        writer.writerow([])

        writer.writerow(["# section", "compliance_articles"])
        writer.writerow(["key", "regulation", "title", "description"])
        for a in report.eu_ai_act_articles + report.dsgvo_articles:
            writer.writerow([a.key, a.regulation, a.title, a.description])
        writer.writerow([])

        writer.writerow(["# section", "test_status"])
        writer.writerow(["key", "value"])
        writer.writerow(["passed", report.test_status.passed])
        writer.writerow(["failed", report.test_status.failed])
        writer.writerow(["skipped", report.test_status.skipped])
        writer.writerow(["total", report.test_status.total])
        writer.writerow(["coverage_percent", report.test_status.coverage_percent if report.test_status.coverage_percent is not None else ""])
        writer.writerow(["pytest_available", report.test_status.pytest_available])
        writer.writerow([])

        writer.writerow(["# section", "signature"])
        writer.writerow(["signature", report.signature or ""])


def render_json(report: ReportData, output_path: Path) -> None:
    """Write ``report`` to ``output_path`` as pretty-printed JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(report)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, cls=_DateTimeEncoder),
        encoding="utf-8",
    )


def report_to_json(report: ReportData) -> str:
    """Return the canonical JSON representation of ``report`` (used by the signer)."""
    return json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, cls=_DateTimeEncoder)


def period_from_strings(start: str, end: str) -> ReportPeriod:
    """Parse ``YYYY-MM-DD`` strings into a ``ReportPeriod``."""
    from datetime import datetime as _datetime

    return ReportPeriod(
        _datetime.strptime(start, "%Y-%m-%d").date(),
        _datetime.strptime(end, "%Y-%m-%d").date(),
    )
