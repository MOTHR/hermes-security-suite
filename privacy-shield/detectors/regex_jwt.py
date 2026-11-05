"""JWTDetector — extracted JWT sub-detector (FIX-PS4).

Wraps ``regex_detector._JWT_RE`` (imported from ``extended_patterns``) so the
standalone ``BaseDetector`` API emits the same canonical dict schema the
legacy :class:`RegexPIIDetector` produces.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .extended_patterns import _JWT_RE


class JWTDetector(BaseDetector):
    """Detect JSON Web Tokens (header.payload.signature)."""

    @property
    def name(self) -> str:
        return "jwt"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        matches: list[dict[str, Any]] = []
        for m in _JWT_RE.finditer(text):
            matches.append(
                {
                    "type": "jwt",
                    "value": m.group(0),
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 1.0,
                    "rule": "regex:jwt",
                }
            )
        return matches
