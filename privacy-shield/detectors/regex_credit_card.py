"""CreditCardDetector — extracted credit-card sub-detector with Luhn validation.

ReDoS-hardened: uses the same coarse pre-filter + exact non-backtracking
final pattern + Luhn check as the legacy ``regex_detector`` credit-card path.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .regex_detector import _CC_FINAL, _CC_PRE, _is_credit_card


class CreditCardDetector(BaseDetector):
    """Detect credit-card numbers (Luhn-validated)."""

    @property
    def name(self) -> str:
        return "credit_card"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        matches: list[dict[str, Any]] = []
        for m in _CC_PRE.finditer(text):
            candidate = m.group(0)
            if not _CC_FINAL.fullmatch(candidate):
                continue
            if not _is_credit_card(candidate):
                continue
            matches.append(
                {
                    "type": "credit_card",
                    "value": candidate,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 1.0,
                    "rule": "regex:credit_card",
                }
            )
        return matches
