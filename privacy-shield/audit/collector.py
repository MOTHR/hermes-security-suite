"""Collect, normalise and enrich data for the Privacy-Shield audit report.

This module reads the JSONL audit log, scans the mapping table, derives
detection events + mode changes, and (optionally) runs the local pytest
suite to obtain live test status. All enrichment is side-effect free apart
from the optional subprocess call to ``pytest``.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any

import yaml

from ..config import PrivacyShieldConfig, load_config
from ..mapping_table import InMemoryMappingTable, MappingTable

from .report_data import (
    AuditEvent,
    ComplianceArticle,
    DetectionEvent,
    ModeChange,
    ReportData,
    ReportPeriod,
    TestStatus,
    TokenMapping,
)

logger = logging.getLogger("privacy_shield.audit.collector")


# ── Severity mapping ───────────────────────────────────────────────────────

_EVENT_SEVERITY: dict[str, str] = {
    "blocked_action": "high",
    "output_pii_detected": "high",
    "strict_mode_block": "high",
    "paranoid_mode_block": "high",
    "pseudonymization_applied": "medium",
    "restore": "low",
    "mode_change": "info",
    "approval_required": "medium",
    "approval_granted": "low",
    "approval_denied": "low",
    "human_review": "low",
}


def _event_severity(event_name: str) -> str:
    return _EVENT_SEVERITY.get(event_name, "info")


# ── Date / event helpers ───────────────────────────────────────────────────


def _parse_event_timestamp(raw: Any) -> datetime:
    """Convert the JSONL ``ts`` field to an aware UTC datetime."""
    if isinstance(raw, (int, float)):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            pass
    # Malformed legacy data falls back to epoch so the report still renders.
    return datetime.fromtimestamp(0, tz=timezone.utc)


def _date_to_datetime(d: date, *, end_of_day: bool = False) -> datetime:
    """Return ``d`` as a UTC datetime (start or end of day)."""
    if end_of_day:
        return datetime.combine(d, time.max, tzinfo=timezone.utc)
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def _load_jsonl_events(path: Path) -> list[dict[str, Any]]:
    """Read all JSONL lines, skipping corrupt ones."""
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Cannot read audit log %s: %s", path, exc)
    return events


# ── Public collectors ─────────────────────────────────────────────────────


def collect_audit_events(
    log_path: Path,
    period: ReportPeriod | None = None,
) -> list[AuditEvent]:
    """Load audit events and optionally filter to ``period``."""
    raw = _load_jsonl_events(log_path)
    events: list[AuditEvent] = []
    for item in raw:
        ts = _parse_event_timestamp(item.get("ts"))
        if period is not None:
            start = _date_to_datetime(period.start)
            end = _date_to_datetime(period.end, end_of_day=True)
            if not (start <= ts <= end):
                continue
        events.append(
            AuditEvent(
                ts=ts,
                event=str(item.get("event", "")),
                session_id_hash=str(item.get("session_id_hash", "")),
                mode=str(item.get("mode", "")),
                model=str(item.get("model", "")),
                platform=str(item.get("platform", "")),
                pii_types=list(item.get("pii_types", [])) if item.get("pii_types") else [],
                masked_count_bucket=str(item.get("masked_count_bucket", "0")),
                severity=_event_severity(str(item.get("event", ""))),
                owasp_risk=str(item.get("owasp_risk", "")),
                atlas_technique=str(item.get("atlas_technique", "")),
                extras={k: v for k, v in item.items() if k not in _CANONICAL_KEYS},
            )
        )
    events.sort(key=lambda e: e.ts)
    return events


_CANONICAL_KEYS: frozenset[str] = frozenset(
    {"ts", "event", "session_id_hash", "mode", "model", "platform",
     "pii_types", "masked_count_bucket", "owasp_risk", "atlas_technique"}
)


def collect_token_mappings(mapper: MappingTable | InMemoryMappingTable) -> list[TokenMapping]:
    """Return all stored token mappings in report shape."""
    try:
        rows = mapper.list_all()
    except Exception as exc:
        logger.warning("Cannot list token mappings: %s", exc)
        return []
    mappings: list[TokenMapping] = []
    for row in rows:
        mappings.append(
            TokenMapping(
                original_hash=str(row.get("original_hash", "")),
                token=str(row.get("token", "")),
                type=str(row.get("type", "")),
                created_at=float(row.get("created_at", 0) or 0),
                session_id=str(row.get("session_id", "")),
            )
        )
    mappings.sort(key=lambda m: m.created_at)
    return mappings


def collect_detection_events(audit_events: list[AuditEvent]) -> list[DetectionEvent]:
    """Derive detection / block / restore events from the audit log."""
    detections: list[DetectionEvent] = []
    for e in audit_events:
        if e.severity in {"high", "medium"} or e.event in {"restore", "blocked_action", "output_pii_detected"}:
            detections.append(
                DetectionEvent(
                    ts=e.ts,
                    severity=e.severity,
                    event=e.event,
                    pii_types=e.pii_types,
                    session_id_hash=e.session_id_hash,
                    mode=e.mode,
                )
            )
    return detections


def collect_mode_changes(audit_events: list[AuditEvent]) -> list[ModeChange]:
    """Extract explicit mode-change events and infer changes from mode field deltas."""
    changes: list[ModeChange] = []
    last_mode: str | None = None
    for e in audit_events:
        if e.event == "mode_change":
            actor = str(e.extras.get("actor", "system"))
            changes.append(
                ModeChange(ts=e.ts, mode=e.mode or "unknown", actor=actor, session_id_hash=e.session_id_hash)
            )
            last_mode = e.mode or "unknown"
            continue
        if e.mode and e.mode != last_mode:
            changes.append(
                ModeChange(ts=e.ts, mode=e.mode, actor="inferred", session_id_hash=e.session_id_hash)
            )
            last_mode = e.mode
    return changes


def collect_test_status(
    project_root: Path | None = None,
    *,
    timeout: float = 120.0,
) -> TestStatus:
    """Run the local pytest suite and return a status snapshot.

    If ``coverage.py`` is installed, an additional ``coverage json`` run is
    performed to obtain a coverage percentage. Failures are reported, not
    raised, so a broken test environment does not block report generation.

    When called from inside a pytest run, we return a dummy snapshot to avoid
    recursive pytest invocations in CI/test environments.
    """
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return TestStatus(pytest_available=True, passed=0, failed=0, skipped=0, total=0)

    project_root = project_root or Path.cwd()
    status = TestStatus(pytest_available=False)

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q", "--tb=no"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        status.pytest_available = True
        # pytest -q final line looks like: "599 passed in 11.25s"
        summary = result.stdout.strip().splitlines()
        if summary:
            last = summary[-1]
            status.passed = _extract_count(last, "passed")
            status.failed = _extract_count(last, "failed")
            status.skipped = _extract_count(last, "skipped")
            status.total = status.passed + status.failed + status.skipped
        else:
            status.total = 0
    except Exception as exc:
        logger.warning("Could not collect pytest status: %s", exc)
        return status

    if status.total > 0:
        try:
            coverage_percent = _collect_coverage(project_root, timeout=timeout)
            if coverage_percent is not None:
                status.coverage_percent = coverage_percent
        except Exception as exc:
            logger.debug("Coverage collection skipped: %s", exc)

    return status


def _extract_count(line: str, token: str) -> int:
    import re

    m = re.search(rf"(\d+)\s+{re.escape(token)}(?:\s|\D|$)", line)
    return int(m.group(1)) if m else 0


def _collect_coverage(project_root: Path, timeout: float) -> float | None:
    """Run ``coverage json`` and return the total coverage percentage."""
    try:
        import coverage  # noqa: F401
    except ImportError:
        return None

    # Run pytest under coverage if no data file exists.
    data_file = project_root / ".coverage"
    if not data_file.exists():
        subprocess.run(
            [sys.executable, "-m", "coverage", "run", "--source=.", "-m", "pytest", "tests/", "-q", "--tb=no"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    result = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "-o", "-"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0 or not result.stdout:
        return None
    try:
        payload = json.loads(result.stdout)
        totals = payload.get("totals", {})
        return float(totals.get("percent_covered", 0.0))
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


# ── Compliance article mapping ───────────────────────────────────────────────


def _default_eu_ai_act_articles() -> list[ComplianceArticle]:
    return [
        ComplianceArticle(
            key="art_9",
            title="Article 9 — Risk Management System",
            description=(
                "High-risk events and blocked actions demonstrate identification "
                "and mitigation of risks before provider egress."
            ),
            regulation="EU AI Act",
        ),
        ComplianceArticle(
            key="art_11",
            title="Article 11 — Quality Management",
            description=(
                "PII detection rate, bucketed counts and runtime metadata "
                "demonstrate systematic quality control."
            ),
            regulation="EU AI Act",
        ),
        ComplianceArticle(
            key="art_12",
            title="Article 12 — Record-Keeping / Logging",
            description=(
                "Every audit event is timestamped and hashed, providing a "
                "non-repudiable trail."
            ),
            regulation="EU AI Act",
        ),
        ComplianceArticle(
            key="art_14",
            title="Article 14 — Human Oversight",
            description=(
                "Approval and human-review events document meaningful human "
                "control over high-impact decisions."
            ),
            regulation="EU AI Act",
        ),
    ]


def _default_dsgvo_articles() -> list[ComplianceArticle]:
    return [
        ComplianceArticle(
            key="art_25",
            title="Art. 25 DSGVO — Data Protection by Design and by Default",
            description=(
                "Privacy-Shield pseudonymises PII before it leaves the local "
                "trust boundary, implementing technical measures by design."
            ),
            regulation="DSGVO",
        ),
        ComplianceArticle(
            key="art_32",
            title="Art. 32 DSGVO — Security of Processing",
            description=(
                "AES-256-GCM encrypted mapping tables, bucketed audit logs and "
                "Ed25519-signed reports demonstrate integrity and confidentiality."
            ),
            regulation="DSGVO",
        ),
        ComplianceArticle(
            key="art_35",
            title="Art. 35 DSGVO — Data Protection Impact Assessment",
            description=(
                "Detection-event severity, mode-change history and compliance "
                "article mapping provide evidence for DPIA documentation."
            ),
            regulation="DSGVO",
        ),
    ]


def load_article_mapping(config_path: Path | None = None) -> list[ComplianceArticle]:
    """Load article mapping from YAML or fall back to the built-in defaults.

    The YAML file may contain either ``articles`` (flat list with
    ``regulation`` field) or the legacy ``articles`` dict plus
    ``eu_ai_act_articles`` / ``dsgvo_articles`` sections.
    """
    if config_path is None:
        config_path = Path(__file__).with_name("config") / "audit_articles.yaml"

    default = _default_eu_ai_act_articles() + _default_dsgvo_articles()
    if not config_path.exists():
        return default

    try:
        with config_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return default

    articles: list[ComplianceArticle] = []
    raw_articles = data.get("articles")
    if isinstance(raw_articles, dict):
        # Legacy structured dict keyed by art_9, art_11, art_25, etc.
        for key, value in raw_articles.items():
            if not isinstance(value, dict):
                continue
            regulation = "EU AI Act" if key.startswith("art_") and int(key.split("_")[-1]) < 25 else "DSGVO"
            articles.append(
                ComplianceArticle(
                    key=key,
                    title=str(value.get("title", "")),
                    description=str(value.get("description", "")),
                    regulation=regulation,
                )
            )
    elif isinstance(raw_articles, list):
        for item in raw_articles:
            if isinstance(item, dict):
                articles.append(
                    ComplianceArticle(
                        key=str(item.get("key", "")),
                        title=str(item.get("title", "")),
                        description=str(item.get("description", "")),
                        regulation=str(item.get("regulation", "EU AI Act")),
                    )
                )

    if articles:
        # Ensure the three DSGVO articles are present even if the YAML omits them.
        existing_keys = {a.key for a in articles}
        for default_article in _default_dsgvo_articles():
            if default_article.key not in existing_keys:
                articles.append(default_article)
        return articles
    return default


# ── Summary and mapping-table factory ──────────────────────────────────────


def summarise_events(events: list[AuditEvent]) -> dict[str, int]:
    """Compute report summary counters."""
    total = len(events)
    pii = 0
    blocked = 0
    restores = 0
    mode_changes = 0
    for e in events:
        if e.pii_types or e.masked_count_bucket != "0":
            pii += 1
        if e.event == "blocked_action":
            blocked += 1
        if e.event == "restore":
            restores += 1
        if e.event == "mode_change":
            mode_changes += 1
    return {
        "total_calls": total,
        "pii_detections": pii,
        "blocked_actions": blocked,
        "restore_events": restores,
        "mode_change_events": mode_changes,
    }


def _build_mapper(config: PrivacyShieldConfig) -> MappingTable | InMemoryMappingTable:
    """Return a mapping table handle for the configured storage mode."""
    if config.storage_mode == "memory":
        return InMemoryMappingTable()
    return MappingTable(
        storage_path=config.storage_path,
        encryption_key=config.encryption_key,
    )


# ── Orchestrator ───────────────────────────────────────────────────────────


def collect_report_data(
    config: PrivacyShieldConfig,
    period: ReportPeriod,
    user_hash: str,
    *,
    project_root: Path | None = None,
    article_config_path: Path | None = None,
    mapper: MappingTable | InMemoryMappingTable | None = None,
) -> ReportData:
    """Collect a complete ``ReportData`` object for the requested period."""
    audit_path = Path(os.path.expanduser(config.audit_jsonl_path))
    audit_events = collect_audit_events(audit_path, period)
    mapper = mapper or _build_mapper(config)
    token_mappings = collect_token_mappings(mapper)
    detection_events = collect_detection_events(audit_events)
    mode_changes = collect_mode_changes(audit_events)
    test_status = collect_test_status(project_root)
    articles = load_article_mapping(article_config_path)
    eu_articles = [a for a in articles if a.regulation == "EU AI Act"]
    dsgvo_articles = [a for a in articles if a.regulation == "DSGVO"]
    return ReportData(
        period=period,
        user_hash=user_hash,
        generated_at=datetime.now(tz=timezone.utc),
        audit_events=audit_events,
        token_mappings=token_mappings,
        detection_events=detection_events,
        mode_changes=mode_changes,
        test_status=test_status,
        eu_ai_act_articles=eu_articles or _default_eu_ai_act_articles(),
        dsgvo_articles=dsgvo_articles or _default_dsgvo_articles(),
        summary=summarise_events(audit_events),
    )
