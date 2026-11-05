"""EmailDetector — extracted Email sub-detector (FIX-PS4 / MORPH-PS-1).

Wraps the hardened email scanner from ``regex_detector._scan_emails`` so it
fits into the new :class:`BaseDetector` / :class:`DetectorChain` pattern
without touching the legacy monolithic :class:`RegexPIIDetector`.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector


class EmailDetector(BaseDetector):
    """Detect RFC-5322-simplified email addresses."""

    @property
    def name(self) -> str:
        return "email"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        # Imported lazily to keep the import graph small and to avoid a
        # circular dependency (regex_detector imports from extended_patterns).
        from .regex_detector import _scan_emails, normalize_text

        normalized = normalize_text(text)
        raw_matches = _scan_emails(normalized)
        matches: list[dict[str, Any]] = []
        for m in raw_matches:
            # _scan_emails already returns PIIMatch (dataclass) — convert to
            # the canonical dict schema expected by DetectorChain.
            matches.append(
                {
                    "type": m.type,
                    "value": m.value,
                    "start": m.start,
                    "end": m.end,
                    "confidence": getattr(m, "confidence", 1.0),
                    "rule": getattr(m, "rule", "regex:email"),
                }
            )
        return matches
