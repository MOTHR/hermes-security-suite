"""PDF renderer for Privacy-Shield audit reports.

Uses ``reportlab`` to produce a tamper-evident compliance PDF. The report
contains:

* Cover page (title, period, hashed user id, generation timestamp)
* Executive summary (total calls, PII detections, blocks, restores, mode changes)
* Token-mapping table (timestamp, type, original_hash, session_id)
* Detection-event table with severity
* Mode-change table
* EU AI Act article mapping
* DSGVO article mapping (Art. 25, 32, 35)
* Test-status box
* Integrity section with SHA-256 canonical hash + optional Ed25519 signature
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .report_data import ComplianceArticle, ReportData, ReportPeriod

__all__ = [
    "ReportPeriod",
    "generate_audit_pdf",
    "generate_audit_report",
    "load_article_mapping",
    "load_audit_events",
    "render_pdf",
    "summarize_events",
]


# ── Backward-compatible helpers kept from the original audit_pdf.py ─────────


def _event_timestamp(event: dict[str, Any]) -> datetime:
    ts = event.get("ts")
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _fmt_timestamp(event: dict[str, Any]) -> str:
    try:
        return _event_timestamp(event).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        return str(event.get("ts", ""))


def _pprint_list(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value) if value is not None else ""


def _parse_date(value: str) -> date:
    from datetime import datetime as _datetime

    return _datetime.strptime(value, "%Y-%m-%d").date()  # noqa: DTZ007


# ── Compliance article sources ─────────────────────────────────────────────


def _default_eu_ai_act_articles() -> dict[str, dict[str, str]]:
    return {
        "art_9": {
            "title": "Article 9 — Risk Management System",
            "description": (
                "High-risk events and blocked actions demonstrate identification "
                "and mitigation of risks before provider egress."
            ),
        },
        "art_11": {
            "title": "Article 11 — Quality Management",
            "description": (
                "PII detection rate, bucketed counts and runtime metadata "
                "demonstrate systematic quality control."
            ),
        },
        "art_12": {
            "title": "Article 12 — Record-Keeping / Logging",
            "description": (
                "Every audit event is timestamped and hashed, providing a "
                "non-repudiable trail."
            ),
        },
        "art_14": {
            "title": "Article 14 — Human Oversight",
            "description": (
                "Approval and human-review events document meaningful human "
                "control over high-impact decisions."
            ),
        },
    }


def _default_dsgvo_articles() -> dict[str, dict[str, str]]:
    return {
        "art_25": {
            "title": "Art. 25 DSGVO — Data Protection by Design and by Default",
            "description": (
                "Privacy-Shield pseudonymises PII before it leaves the local "
                "trust boundary, implementing technical measures by design."
            ),
        },
        "art_32": {
            "title": "Art. 32 DSGVO — Security of Processing",
            "description": (
                "AES-256-GCM encrypted mapping tables, bucketed audit logs and "
                "Ed25519-signed reports demonstrate integrity and confidentiality."
            ),
        },
        "art_35": {
            "title": "Art. 35 DSGVO — Data Protection Impact Assessment",
            "description": (
                "Detection-event severity, mode-change history and compliance "
                "article mapping provide evidence for DPIA documentation."
            ),
        },
    }


def load_article_mapping(config_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Load article mapping from YAML or return the built-in default.

    Returns a flat dict keyed by ``art_*`` so the existing
    ``tests/test_audit_pdf.py`` contract continues to work.
    """
    if config_path is None:
        config_path = Path(__file__).resolve().parent.parent / "config" / "audit_articles.yaml"

    default = {**_default_eu_ai_act_articles(), **_default_dsgvo_articles()}
    if not config_path.exists():
        return default

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return default

    raw = data.get("articles")
    if not isinstance(raw, dict):
        return default

    merged = dict(default)
    for key, value in raw.items():
        if isinstance(value, dict):
            merged[key] = {
                "title": str(value.get("title", "")),
                "description": str(value.get("description", "")),
            }
    return merged


# ── Report hash / signature helpers ────────────────────────────────────────


def _canonical_dict(report: ReportData) -> dict[str, Any]:
    """Return a JSON-serialisable, deterministic dict for hashing/signing."""
    from dataclasses import asdict
    from .csv_renderer import _DateTimeEncoder

    # Round-trip through JSON normalises datetimes and lists deterministically.
    canonical = json.loads(json.dumps(asdict(report), cls=_DateTimeEncoder, sort_keys=True))
    # generation timestamp must not affect the canonical hash; otherwise two
    # exports of the same source data would produce different signatures.
    canonical.pop("generated_at", None)
    return canonical  # type: ignore[no-any-return]


def _report_signature(report: ReportData) -> str:
    """Deterministic SHA-256 over the canonical report payload."""
    payload = json.dumps(_canonical_dict(report), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Table builders ─────────────────────────────────────────────────────────


def _styled_table(rows: list[list[str]], *, repeat_rows: int = 1, col_widths: list[float] | None = None) -> Table:
    if col_widths:
        table = Table(rows, colWidths=col_widths, repeatRows=repeat_rows)
    else:
        table = Table(rows, repeatRows=repeat_rows)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f7")]),
            ]
        )
    )
    return table


def _build_event_table(events: list[Any]) -> Table:
    headers = [
        "Timestamp",
        "Event",
        "Session Hash",
        "Mode",
        "PII Types",
        "Model",
        "Platform",
        "Count",
        "Severity",
        "OWASP",
        "ATLAS",
    ]
    rows: list[list[str]] = [headers]
    for e in events:
        rows.append(
            [
                e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                e.event,
                e.session_id_hash[:16],
                e.mode,
                ", ".join(e.pii_types),
                e.model,
                e.platform,
                e.masked_count_bucket,
                e.severity,
                e.owasp_risk or "—",
                e.atlas_technique or "—",
            ]
        )
    return _styled_table(rows)


def _build_token_mapping_table(mappings: list[Any]) -> Table:
    headers = ["Timestamp", "Type", "Original Hash", "Token", "Session ID"]
    rows: list[list[str]] = [headers]
    for m in mappings:
        from datetime import datetime as _datetime

        ts = _datetime.fromtimestamp(m.created_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        rows.append([ts, m.type, m.original_hash, m.token, m.session_id])
    return _styled_table(rows)


def _build_detection_event_table(events: list[Any]) -> Table:
    headers = ["Timestamp", "Severity", "Event", "PII Types", "Session Hash", "Mode"]
    rows: list[list[str]] = [headers]
    for d in events:
        rows.append(
            [
                d.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
                d.severity,
                d.event,
                ", ".join(d.pii_types),
                d.session_id_hash[:16],
                d.mode,
            ]
        )
    return _styled_table(rows)


def _build_mode_change_table(changes: list[Any]) -> Table:
    headers = ["Timestamp", "Mode", "Actor", "Session Hash"]
    rows: list[list[str]] = [headers]
    for c in changes:
        rows.append([c.ts.strftime("%Y-%m-%d %H:%M:%S UTC"), c.mode, c.actor, c.session_id_hash[:16]])
    return _styled_table(rows)


def _build_article_table(articles: list[ComplianceArticle]) -> Table:
    headers = ["Article", "Title", "Compliance Evidence"]
    rows: list[list[str]] = [headers]
    for a in articles:
        rows.append([a.key, a.title, a.description])
    return _styled_table(rows, col_widths=[3 * cm, 5 * cm, 10 * cm])


def _build_summary_table(summary: dict[str, int]) -> Table:
    rows = [["Metric", "Value"]]
    for key, value in summary.items():
        rows.append([key.replace("_", " ").title(), str(value)])
    return _styled_table(rows, col_widths=[6 * cm, 4 * cm])


# ── Main render function ────────────────────────────────────────────────────


def render_pdf(report: ReportData, output_path: Path) -> None:
    """Render ``report`` to ``output_path`` as a PDF."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if report.signature is None:
        report.signature = ""
    report_hash = _report_signature(report)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []

    # Cover
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("<b>Hermes Privacy-Shield</b>", styles["Title"]))
    story.append(Paragraph("DSGVO & EU AI Act Compliance Audit Report", styles["Title"]))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(f"Period: {report.period.iso_range()}", styles["Normal"]))
    story.append(Paragraph(f"User Hash: {report.user_hash}", styles["Normal"]))
    story.append(
        Paragraph(
            f"Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 1 * cm))

    # Summary
    story.append(Paragraph("<b>Executive Summary</b>", styles["Heading2"]))
    story.append(_build_summary_table(report.summary))
    story.append(Spacer(1, 0.5 * cm))

    # Test status
    story.append(Paragraph("<b>Test Status</b>", styles["Heading2"]))
    ts = report.test_status
    test_rows = [
        ["Metric", "Value"],
        ["Passed", str(ts.passed)],
        ["Failed", str(ts.failed)],
        ["Skipped", str(ts.skipped)],
        ["Total", str(ts.total)],
        ["Coverage", f"{ts.coverage_percent:.1f}%" if ts.coverage_percent is not None else "not measured"],
    ]
    story.append(_styled_table(test_rows, col_widths=[6 * cm, 4 * cm]))
    story.append(Spacer(1, 0.5 * cm))

    # Token mappings
    story.append(Paragraph("<b>Token Mappings</b>", styles["Heading2"]))
    if report.token_mappings:
        story.append(_build_token_mapping_table(report.token_mappings))
    else:
        story.append(Paragraph("No token mappings stored for the selected period.", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Detection events
    story.append(Paragraph("<b>Detection Events</b>", styles["Heading2"]))
    if report.detection_events:
        story.append(_build_detection_event_table(report.detection_events))
    else:
        story.append(Paragraph("No detection events recorded for the selected period.", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Mode changes
    story.append(Paragraph("<b>Mode Changes</b>", styles["Heading2"]))
    if report.mode_changes:
        story.append(_build_mode_change_table(report.mode_changes))
    else:
        story.append(Paragraph("No mode changes recorded for the selected period.", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Compliance mappings
    story.append(Paragraph("<b>EU AI Act Article Mapping</b>", styles["Heading2"]))
    story.append(_build_article_table(report.eu_ai_act_articles))
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("<b>DSGVO Article Mapping</b>", styles["Heading2"]))
    story.append(_build_article_table(report.dsgvo_articles))
    story.append(Spacer(1, 0.5 * cm))

    # Audit events
    story.append(Paragraph("<b>Raw Audit Events</b>", styles["Heading2"]))
    if report.audit_events:
        story.append(_build_event_table(report.audit_events))
    else:
        story.append(Paragraph("No audit events recorded for the selected period.", styles["Normal"]))
    story.append(Spacer(1, 0.5 * cm))

    # Integrity footer
    story.append(Paragraph("<b>Report Integrity</b>", styles["Heading2"]))
    story.append(
        Paragraph(
            f"SHA-256 canonical report hash: <font name='Courier' size='9'>{report_hash}</font>",
            styles["Normal"],
        )
    )
    if report.signature:
        story.append(
            Paragraph(
                f"Ed25519 signature (base64): <font name='Courier' size='8'>{report.signature}</font>",
                styles["Normal"],
            )
        )
    story.append(
        Paragraph(
            "The SHA-256 hash is computed over the canonical, sorted, JSON-serialised "
            "report payload. Re-running the export on the same source data yields the same hash. "
            "The Ed25519 signature proves that this exact report was produced by the holder "
            "of the corresponding private key.",
            styles["Normal"],
        )
    )

    doc.build(story)


# ── Backward-compatible wrappers used by legacy tests and scripts ──────────


def summarize_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """Compute summary counters from raw audit-event dicts.

    Kept for backward compatibility with ``tests/test_audit_pdf.py``.
    """
    total = len(events)
    pii = 0
    blocked = 0
    for e in events:
        if e.get("pii_types") or e.get("masked_count_bucket", "0") != "0":
            pii += 1
        if e.get("event") == "blocked_action":
            blocked += 1
    return {"total_calls": total, "pii_detections": pii, "blocked_actions": blocked}


def load_audit_events(
    log_path: Path,
    period: ReportPeriod | None = None,
) -> list[dict[str, Any]]:
    """Read raw audit events from a JSONL file, kept for backward compatibility."""
    from .collector import collect_audit_events

    if not log_path.exists():
        return []
    audit_events = collect_audit_events(log_path, period)
    # Return dicts shaped like the original format for tests that expect them.
    result: list[dict[str, Any]] = []
    for e in audit_events:
        item: dict[str, Any] = {
            "ts": e.ts.timestamp(),
            "event": e.event,
            "session_id_hash": e.session_id_hash,
            "mode": e.mode,
            "model": e.model,
            "platform": e.platform,
            "pii_types": e.pii_types,
            "masked_count_bucket": e.masked_count_bucket,
            "severity": e.severity,
        }
        item.update(e.extras)
        result.append(item)
    return result


def generate_audit_pdf(
    output_path: Path,
    events: list[dict[str, Any]],
    period: ReportPeriod,
    user_hash: str,
    articles: dict[str, dict[str, Any]] | None = None,
) -> str:
    """Backward-compatible PDF renderer returning a deterministic SHA-256 hash.

    Maps the legacy article-dict shape into the new ``ComplianceArticle``
    dataclass and produces the same report sections the original generator
    produced, plus the new DSGVO and signature sections.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if articles is None:
        articles = load_article_mapping()

    from .collector import collect_audit_events
    from .report_data import ComplianceArticle, DetectionEvent, ReportData, TestStatus

    # Convert legacy raw events into the new structured shape.
    raw_log = output_path.with_suffix(".jsonl")
    raw_log.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) for e in events),
        encoding="utf-8",
    )
    audit_events = collect_audit_events(raw_log, period)
    raw_log.unlink(missing_ok=True)

    detection_events = [
        DetectionEvent(
            ts=e.ts,
            severity=e.severity,
            event=e.event,
            pii_types=e.pii_types,
            session_id_hash=e.session_id_hash,
            mode=e.mode,
        )
        for e in audit_events
        if e.event == "blocked_action"
    ]

    # Convert legacy article dict into ComplianceArticle instances.
    eu_articles: list[ComplianceArticle] = []
    dsgvo_articles: list[ComplianceArticle] = []
    for key, value in articles.items():
        article = ComplianceArticle(
            key=key,
            title=str(value.get("title", "")),
            description=str(value.get("description", "")),
            regulation=(
                "DSGVO"
                if key.startswith("art_2") or key.startswith("art_3") or key == "art_35"
                else "EU AI Act"
            ),
        )
        if article.regulation == "DSGVO":
            dsgvo_articles.append(article)
        else:
            eu_articles.append(article)

    report = ReportData(
        period=period,
        user_hash=user_hash,
        generated_at=datetime.now(tz=timezone.utc),
        audit_events=audit_events,
        token_mappings=[],
        detection_events=detection_events,
        mode_changes=[],
        test_status=TestStatus(),
        eu_ai_act_articles=eu_articles,
        dsgvo_articles=dsgvo_articles,
        summary=summarize_events(events),
    )
    render_pdf(report, output_path)
    return _report_signature(report)


def generate_audit_report(
    log_path: Path,
    output_path: Path,
    from_date: str,
    to_date: str,
    user_hash: str,
    articles: dict[str, dict[str, Any]] | None = None,
) -> str:
    """High-level helper used by the legacy CLI."""
    period = ReportPeriod(_parse_date(from_date), _parse_date(to_date))
    events = load_audit_events(log_path, period=period)
    return generate_audit_pdf(output_path, events, period, user_hash, articles=articles)
