"""Adapter exposing the legacy :class:`RegexPIIDetector` as a :class:`BaseDetector`.

Keeps the 47-pattern Phase-4 sweep (code-context penalty, base64 heuristic,
BIP39 seed-phrase detector, context-leak heuristics, …) accessible via the
new :class:`DetectorChain` API without code duplication.

New code should prefer :func:`privacy_shield.detectors.chain_factory.build_default_chain`
which composes independent sub-detectors.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector


class LegacyRegexDetectorAdapter(BaseDetector):
    """Wrap a ``RegexPIIDetector`` so it fits into a :class:`DetectorChain`."""

    def __init__(self, legacy_detector: Any):
        self._legacy = legacy_detector

    @property
    def name(self) -> str:
        return "regex_pii_legacy"

    @property
    def legacy(self) -> Any:
        """The wrapped :class:`RegexPIIDetector` (escape hatch for tests)."""
        return self._legacy

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        raw_matches = self._legacy.scan(text)
        return [
            {
                "type": m.type,
                "value": m.value,
                "start": m.start,
                "end": m.end,
                "confidence": getattr(m, "confidence", 1.0),
                "rule": getattr(m, "rule", f"regex:{m.type}"),
            }
            for m in raw_matches
        ]


__all__ = ["LegacyRegexDetectorAdapter"]
