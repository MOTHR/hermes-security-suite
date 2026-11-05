"""Shared data classes for the Privacy-Shield audit export pipeline.

These dataclasses are deliberately plain (no rendering / I/O logic) so that
PDF, CSV, JSON and signing modules can all operate on the same shape without
circular imports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True)
class ReportPeriod:
    """Inclusive ISO date range shown on the cover page and used for filtering."""

    start: date
    end: date

    def iso_range(self) -> str:
        return f"{self.start.isoformat()} — {self.end.isoformat()}"


@dataclass
class AuditEvent:
    """One row from the JSONL audit log, normalised for the report."""

    ts: datetime
    event: str
    session_id_hash: str = ""
    mode: str = ""
    model: str = ""
    platform: str = ""
    pii_types: list[str] = field(default_factory=list)
    masked_count_bucket: str = "0"
    severity: str = "info"
    owasp_risk: str = ""
    atlas_technique: str = ""
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenMapping:
    """One token-to-original-hash mapping entry from the mapping table."""

    original_hash: str
    token: str
    type: str
    created_at: float
    session_id: str


@dataclass
class DetectionEvent:
    """Derived detection / block / restore event with explicit severity."""

    ts: datetime
    severity: str
    event: str
    pii_types: list[str]
    session_id_hash: str
    mode: str


@dataclass
class ModeChange:
    """A documented operating-mode transition."""

    ts: datetime
    mode: str
    actor: str
    session_id_hash: str


@dataclass
class TestStatus:
    """Runtime test-status snapshot (collected via ``pytest`` if available)."""

    __test__ = False  # pytest: not a test class

    passed: int = 0
    failed: int = 0
    skipped: int = 0
    total: int = 0
    coverage_percent: float | None = None
    pytest_available: bool = True


@dataclass
class ComplianceArticle:
    """Regulatory article mapping shown in compliance sections."""

    key: str
    title: str
    description: str
    regulation: str  # e.g. "EU AI Act", "DSGVO"


@dataclass
class ReportData:
    """Canonical payload for all audit-export renderers and the signer."""

    period: ReportPeriod
    user_hash: str
    generated_at: datetime
    audit_events: list[AuditEvent]
    token_mappings: list[TokenMapping]
    detection_events: list[DetectionEvent]
    mode_changes: list[ModeChange]
    test_status: TestStatus
    eu_ai_act_articles: list[ComplianceArticle]
    dsgvo_articles: list[ComplianceArticle]
    summary: dict[str, int] = field(default_factory=dict)
    signature: str | None = None
