"""Detect zero-width Unicode characters (steganography).

ARCH-1 (FIX-2D): ``check`` now accepts the standard ``context``
kwarg so this detector can sit in a :class:`DetectorChain` that
calls ``detector.check(text, context)``. The detector ignores
``context`` — it only inspects the surface text — but the signature
match is required for chain composition.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector

ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-Width Space
    "\u200c",  # Zero-Width Non-Joiner
    "\u200d",  # Zero-Width Joiner
    "\ufeff",  # BOM / Zero-Width No-Break Space
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u2060",  # Word Joiner
}


class ZeroWidthDetector(BaseDetector):
    """Detect zero-width characters that can hide instructions in plain sight.

    The ``context`` kwarg is accepted for ``BaseDetector`` signature
    compatibility but is not consulted — every zero-width hit is
    equally suspicious regardless of source.
    """

    @property
    def name(self) -> str:
        return "zero_width"

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        """Return list of {type, char, position, severity}.

        ``context`` is accepted for :class:`BaseDetector` chain
        compatibility and otherwise ignored.
        """
        violations: list[dict[str, Any]] = []
        for i, ch in enumerate(text):
            if ch in ZERO_WIDTH_CHARS:
                violations.append({
                    "type": "zero_width",
                    "char": repr(ch),
                    "position": i,
                    "severity": "low",
                })
        return violations

