"""Backward-compatible shim for the old ``privacy_shield.audit_pdf`` module.

In v1.4.0 the PDF renderer moved into ``privacy_shield.audit.pdf_renderer``.
Existing callers (CLI, scripts, tests) can keep importing from
``privacy_shield.audit_pdf``; this module re-exports the public surface.
"""

from __future__ import annotations

from privacy_shield.audit.pdf_renderer import (
    ReportPeriod,
    generate_audit_pdf,
    generate_audit_report,
    load_article_mapping,
    load_audit_events,
    render_pdf,
    summarize_events,
)
from privacy_shield.audit.report_data import ComplianceArticle, ReportData

__all__ = [
    "ComplianceArticle",
    "ReportData",
    "ReportPeriod",
    "generate_audit_pdf",
    "generate_audit_report",
    "load_article_mapping",
    "load_audit_events",
    "render_pdf",
    "summarize_events",
]
