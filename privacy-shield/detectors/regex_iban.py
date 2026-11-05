"""IBANDetector — extracted IBAN sub-detector with mod-97 validation.

Mirrors the legacy ``regex_detector._mod97_check`` validator so the standalone
``BaseDetector`` API emits the same canonical dict schema the legacy
:class:`RegexPIIDetector` produces.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .regex_detector import _IBAN_RE, _mod97_check


class IBANDetector(BaseDetector):
    """Detect IBANs (DE + EU) and validate them with the ISO-13616 mod-97 algorithm."""

    @property
    def name(self) -> str:
        return "iban"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        matches: list[dict[str, Any]] = []
        for m in _IBAN_RE.finditer(text):
            value = m.group(0)
            if not _mod97_check(value):
                continue
            matches.append(
                {
                    "type": "iban",
                    "value": value,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 1.0,
                    "rule": "regex:iban",
                }
            )
        return matches
