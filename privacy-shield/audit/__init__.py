"""Privacy-Shield Audit-Logger (FIX-PS3).

Schreibt DSGVO-konforme Audit-Events in eine JSONL-Datei mit chmod 600
(Owner-read/write only). Die Datei liegt im Workspace des aktiven Profils
und dient als persistenter Nachweis dafür, welche Detections / Maskierungen
Privacy-Shield in welcher Session ausgelöst hat.

Design-Prinzipien (FIX-PS3 / BUTLER-PS-2 HIGH):

1. **Bucketed + side-channel safe**: niemals Roh-PII-Werte, Roh-Counts
   oder Roh-Session-IDs. Stattdessen:
   - ``masked_count`` -> ``masked_count_bucket`` via ``_bucket_count``
   - ``session_id``   -> ``session_id_hash`` (sha256-prefix)
   - ``pii_types``    -> max 3 type labels (kein plaintext)
2. **Append-only JSONL** (eine Zeile pro Event), atomar pro Zeile
   (write+fsync) damit ein Crash mitten im Append keine korrupte Zeile
   hinterlässt.
3. **chmod 600 / 700** — die Datei selbst ist 600, das Verzeichnis 700.
   Falls die Datei bereits mit lockeren Rechten existiert (z.B. ältere
   privacy-shield-audit.jsonl aus früheren Bug-1699-Repairs), werden die
   Rechte beim Init korrigiert.
4. **Fail-soft** — wenn die Datei nicht beschrieben werden kann (read-only
   FS, fehlende Permissions), wird ein ``logger.error`` emittiert, der
   Detektions-Pfad läuft trotzdem weiter. Audit-Verlust darf niemals den
   Schutz vor PII-Egress kompromittieren.
5. **Retention-friendly** — die JSONL-Datei kann von einem externen
   Cron (``scripts/rotate_audit.py``, siehe CHANGELOG) rotiert werden;
   der Logger selbst hält sie aber klein, indem er nur die strukturierten
   Felder schreibt.

Format-Spezifikation (eine Zeile pro Event)::

    {"ts": 1700000000.123, "event": "pseudonymization_applied",
     "session_id_hash": "ab12cd34...", "mode": "limited",
     "masked_count_bucket": "1-10", "pii_types": ["email", "phone"],
     "model": "openai:gpt-4o", "platform": "telegram"}

Felder sind immer JSON-serialisierbar; ``pii_types`` ist eine Liste von
Strings (max 3 Einträge, deterministisch dedupliziert).

.. note::

   This module was converted into a sub-package in Privacy-Shield v1.4.0
   so that the audit export pipeline (PDF/CSV/JSON, signing, collectors)
   can live under ``privacy_shield.audit.*`` while keeping the legacy
   ``from privacy_shield.audit import AuditLogger`` import working.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("privacy_shield.audit")

# Hard-coded retention cap: keep last 10 000 events.  Older entries are
# pruned opportunistically on append when the file exceeds this limit.
# Rotation is intentionally cheap (single file rewrite) so audit does not
# become a hot-path concern for the PII pipeline.
_MAX_AUDIT_EVENTS = 10_000


def hash_session_key(session_id: str) -> str:
    """Return a stable, side-channel-safe identifier for ``session_id``.

    Privacy-Shield never writes the raw session id to the audit log:
    callers may pass through user-identifying tokens, and even a session
    label can leak enough metadata to correlate two requests against the
    same conversation. We hash with sha256 and truncate to 16 hex
    chars (64 bits) — plenty for de-duplication, no useful correlation.
    """
    if not session_id:
        return ""
    import hashlib

    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]


def _bucket_count(count: int) -> str:
    """Magnitude bucket matching ``PrivacyShieldPlugin._bucket_count``.

    Keeping the same shape ensures that an operator reviewing the
    log file and one reviewing the in-process logger see identical
    count semantics.
    """
    if count <= 0:
        return "0"
    if count == 1:
        return "1-1"
    if count <= 10:
        return "1-10"
    if count <= 100:
        return "1-100"
    if count <= 1000:
        return "1-1000"
    return "10000+"


class AuditLogger:
    """JSONL audit-log writer for Privacy-Shield events.

    Usage::

        logger = AuditLogger("/path/to/audit.jsonl")
        logger.log(
            event="pseudonymization_applied",
            session_id="abc-123",
            masked_count=4,
            pii_types=["email", "phone"],
            mode="limited",
            model="openai:gpt-4o",
            platform="telegram",
        )

    All keyword arguments are optional except ``event``. Unrecognised
    keyword arguments are still written into the JSON line, which makes
    the logger easy to extend without an interface change.
    """

    def __init__(self, log_path: str | os.PathLike[str] | None = None):
        self.log_path = Path(
            os.path.expanduser(log_path)
            if log_path
            else "~/.hermes/profiles/default/workspace/privacy-shield-audit.jsonl"
        )
        self._ensure_dir()
        self._ensure_perms()

    # ------------------------------------------------------------------ I/O
    def _ensure_dir(self) -> None:
        """Create the audit-log directory (parents=True) with chmod 700.

        ``exist_ok=True`` so concurrent invocations do not race; chmod is
        re-applied after ``mkdir`` because on POSIX ``mkdir`` honours
        ``mode=`` only when the directory is freshly created.
        """
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.log_path.parent, 0o700)
        except OSError as exc:
            logger.error(
                "Privacy-Shield audit: cannot prepare log dir %s (%s); "
                "audit logging will degrade to logger.warning only.",
                self.log_path.parent,
                exc,
            )

    def _ensure_perms(self) -> None:
        """Tighten chmod 600 on the audit file if it already exists.

        Older deployments (pre-FIX-PS3) may have produced a file with
        looser permissions through the bug-1699 corruption window; we
        repair that here on every plugin init so the audit trail
        converges to the documented 600 within one process start.
        """
        if not self.log_path.exists():
            return
        try:
            os.chmod(self.log_path, 0o600)
        except OSError as exc:
            logger.warning(
                "Privacy-Shield audit: cannot chmod 600 on %s (%s)",
                self.log_path,
                exc,
            )

    def _rotate_if_overgrown(self) -> None:
        """Trim the JSONL file when it crosses ``_MAX_AUDIT_EVENTS``.

        Cheap implementation: read all lines, drop oldest until under
        the cap, rewrite atomically (write to tmp, rename).  Done on
        the same thread that just appended — acceptable here because
        the audit path is not on a tight latency loop (the PII
        pseudonymiser already dominates) and 10 000 lines is small.
        """
        try:
            with self.log_path.open("r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return
        if len(lines) <= _MAX_AUDIT_EVENTS:
            return
        keep = lines[-_MAX_AUDIT_EVENTS:]
        tmp = self.log_path.with_suffix(self.log_path.suffix + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8") as fh:
                fh.writelines(keep)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.log_path)
        except OSError as exc:
            logger.warning(
                "Privacy-Shield audit: rotate failed on %s (%s); "
                "log will keep growing until next rotate.",
                self.log_path,
                exc,
            )

    def log(
        self,
        event: str,
        *,
        session_id: str | None = None,
        masked_count: int | None = None,
        pii_types: list[str] | None = None,
        mode: str | None = None,
        model: str | None = None,
        platform: str | None = None,
        **extras: Any,
    ) -> bool:
        """Append one JSONL event. Returns True on success, False on failure.

        The function is **never allowed to raise** — audit failures must
        not break the PII pseudonymisation hot-path. Callers should treat
        a False return value as "audit unavailable for this event" and
        continue.

        v1.4.1+: automatically injects ``owasp_risk`` and ``atlas_technique``
        based on the event name via :mod:`owasp_atlas_mapping`.
        """
        try:
            # Import here to avoid circular dependencies at module load time.
            from .owasp_atlas_mapping import get_mapping

            mapping = get_mapping(event)

            entry: dict[str, Any] = {
                "ts": time.time(),
                "event": event,
            }
            if session_id is not None:
                entry["session_id_hash"] = hash_session_key(session_id)
            if masked_count is not None:
                entry["masked_count_bucket"] = _bucket_count(masked_count)
            if pii_types:
                # Dedupe + cap at 3 type labels (side-channel discipline).
                entry["pii_types"] = list(dict.fromkeys(pii_types))[:3]
            if mode is not None:
                entry["mode"] = mode
            if model is not None:
                entry["model"] = model
            if platform is not None:
                entry["platform"] = platform
            # v1.4.1 — OWASP/ATLAS auto-mapping
            if mapping.owasp_risk:
                entry["owasp_risk"] = mapping.owasp_risk
            if mapping.atlas_technique:
                entry["atlas_technique"] = mapping.atlas_technique
            for key, value in extras.items():
                if key in entry:
                    continue  # never overwrite canonical fields
                entry[key] = value

            line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(self.log_path, 0o600)

            # Rotate opportunistically (cheap when under cap).
            self._rotate_if_overgrown()
            return True
        except OSError as exc:
            logger.error(
                "Privacy-Shield audit: cannot append event %r (%s); "
                "PII protection continues without persistence.",
                event,
                exc,
            )
            return False
        except (TypeError, ValueError) as exc:
            logger.error(
                "Privacy-Shield audit: cannot serialise event %r (%s); "
                "PII protection continues without persistence.",
                event,
                exc,
            )
            return False

    # ------------------------------------------------------------------ Read
    def read_events(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Read back audit events (for tests / operator tooling).

        Returns events in append order.  Skips lines that fail JSON
        parsing (those would only appear if an external process
        appended non-JSONL data; the logger itself never produces them).
        """
        if not self.log_path.exists():
            return []
        try:
            with self.log_path.open("r", encoding="utf-8") as fh:
                raw = fh.readlines()
        except OSError as exc:
            logger.warning(
                "Privacy-Shield audit: cannot read %s (%s)",
                self.log_path,
                exc,
            )
            return []
        events: list[dict[str, Any]] = []
        for line in raw:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if limit is not None:
            return events[-limit:]
        return events

    def clear(self) -> None:
        """Remove the audit file. Test-only helper."""
        try:
            if self.log_path.exists():
                self.log_path.unlink()
        except OSError as exc:
            logger.warning(
                "Privacy-Shield audit: cannot remove %s (%s)",
                self.log_path,
                exc,
            )


# v1.4.0: re-export the audit-export pipeline so callers can use
# ``from privacy_shield.audit import AuditExporter`` etc.
from .csv_renderer import period_from_strings, render_csv, render_json, report_to_json
from .exporter import AuditExporter, run_pytest_status
from .owasp_atlas_mapping import (
    OwaspAtlasMapping,
    all_mappings,
    atlas_coverage_summary,
    enrich_event,
    get_mapping,
    mappings_by_atlas,
    mappings_by_owasp,
    owasp_coverage_summary,
)
from .pdf_renderer import (
    ReportPeriod,
    generate_audit_pdf,
    generate_audit_report,
    load_article_mapping,
    load_audit_events,
    render_pdf,
    summarize_events,
)
from .signer import (
    AuditSignatureError,
    generate_signing_key,
    load_private_key,
    load_public_key,
    save_key_pair,
    sign,
    sign_b64,
    verify,
    verify_b64,
)

__all__ = [
    "AuditExporter",
    "AuditLogger",
    "AuditSignatureError",
    "OwaspAtlasMapping",
    "ReportPeriod",
    "all_mappings",
    "atlas_coverage_summary",
    "enrich_event",
    "generate_audit_pdf",
    "generate_audit_report",
    "generate_signing_key",
    "get_mapping",
    "hash_session_key",
    "load_article_mapping",
    "load_audit_events",
    "load_private_key",
    "load_public_key",
    "mappings_by_atlas",
    "mappings_by_owasp",
    "owasp_coverage_summary",
    "period_from_strings",
    "render_csv",
    "render_json",
    "render_pdf",
    "report_to_json",
    "run_pytest_status",
    "save_key_pair",
    "sign",
    "sign_b64",
    "summarize_events",
    "verify",
    "verify_b64",
]
