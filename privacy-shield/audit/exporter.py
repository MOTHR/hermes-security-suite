"""Main exporter class and CLI helpers for Privacy-Shield audit reports."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import PrivacyShieldConfig, load_config
from ..mapping_table import InMemoryMappingTable, MappingTable

from .collector import collect_report_data, collect_test_status
from .csv_renderer import period_from_strings, render_csv, render_json, report_to_json
from .pdf_renderer import render_pdf
from .report_data import ReportData, ReportPeriod
from .signer import load_private_key, sign_b64


class AuditExporter:
    """High-level Privacy-Shield audit exporter.

    Usage::

        exporter = AuditExporter(session=current_session)
        exporter.export(
            output_path="audit.pdf",
            time_range=("2026-08-01", "2026-08-31"),
            sign=True,
            format="pdf",
            signing_key_path=Path.home() / ".hermes" / "keys" / "audit-signing-key.pem",
        )
    """

    def __init__(
        self,
        *,
        config: PrivacyShieldConfig | None = None,
        mapper: MappingTable | InMemoryMappingTable | None = None,
        project_root: Path | None = None,
    ):
        self.config = config or load_config()
        self.audit_path = Path(os.path.expanduser(self.config.audit_jsonl_path))
        self.mapper = mapper or _build_mapper(self.config)
        self.project_root = project_root or Path.cwd()

    def collect(
        self,
        time_range: tuple[str, str] | ReportPeriod,
        *,
        user_hash: str | None = None,
        article_config_path: Path | None = None,
    ) -> ReportData:
        """Collect a complete ``ReportData`` for ``time_range``.

        ``time_range`` may be a tuple of ``YYYY-MM-DD`` strings or a
        ``ReportPeriod``.
        """
        if isinstance(time_range, ReportPeriod):
            period = time_range
        else:
            period = period_from_strings(time_range[0], time_range[1])
        return collect_report_data(
            self.config,
            period,
            user_hash or "unknown",
            project_root=self.project_root,
            article_config_path=article_config_path,
            mapper=self.mapper,
        )

    def sign_report(self, report: ReportData, signing_key_path: Path) -> tuple[str, str]:
        """Sign the canonical JSON of ``report`` and store the signature.

        Returns the base64 signature and the canonical JSON string that was signed.
        """
        private_key = load_private_key(signing_key_path)
        canonical = report_to_json(report)
        signature = sign_b64(canonical, private_key)
        report.signature = signature
        return signature, canonical

    def export(
        self,
        output_path: str | Path,
        time_range: tuple[str, str] | ReportPeriod,
        *,
        sign: bool = False,
        format: str = "pdf",  # noqa: A002 - format is the CLI/API keyword in the task
        signing_key_path: str | Path | None = None,
        article_config_path: Path | None = None,
        user_hash: str | None = None,
    ) -> dict[str, Any]:
        """Render the audit report to ``output_path``.

        Returns a dict with ``output_path``, ``signature`` and ``format``.
        When ``sign=True`` a detached signature file ``<output>.sig`` is
        also written.
        """
        report = self.collect(time_range, user_hash=user_hash, article_config_path=article_config_path)
        if user_hash is not None:
            report.user_hash = user_hash

        signature: str | None = None
        canonical: str | None = None
        if sign:
            if signing_key_path is None:
                raise ValueError("sign=True requires signing_key_path")
            signature, canonical = self.sign_report(report, Path(signing_key_path))

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fmt = format.lower()
        if fmt == "pdf":
            render_pdf(report, out)
        elif fmt == "csv":
            render_csv(report, out)
        elif fmt == "json":
            render_json(report, out)
        else:
            raise ValueError(f"Unsupported format: {format!r} (expected pdf, csv, json)")

        canonical_path: Path | None = None
        if sign and signature and canonical:
            sig_path = out.with_suffix(out.suffix + ".sig")
            sig_path.write_text(signature, encoding="utf-8")
            canonical_path = out.with_suffix(out.suffix + ".canonical.json")
            canonical_path.write_text(canonical, encoding="utf-8")

        return {
            "output_path": out,
            "signature": signature,
            "format": fmt,
            "canonical_path": canonical_path if (sign and signature) else None,
        }


def _build_mapper(config: PrivacyShieldConfig) -> MappingTable | InMemoryMappingTable:
    if config.storage_mode == "memory":
        return InMemoryMappingTable()
    return MappingTable(
        storage_path=config.storage_path,
        encryption_key=config.encryption_key,
    )


def run_pytest_status(project_root: Path | None = None) -> dict[str, Any]:
    """Standalone helper to obtain the current pytest/coverage snapshot."""
    status = collect_test_status(project_root)
    return {
        "passed": status.passed,
        "failed": status.failed,
        "skipped": status.skipped,
        "total": status.total,
        "coverage_percent": status.coverage_percent,
        "pytest_available": status.pytest_available,
    }
