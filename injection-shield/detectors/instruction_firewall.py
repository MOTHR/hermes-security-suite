"""Layer 2: Instruction firewall — anti-injection pattern detection.

ARCH-1 (FIX-2D) refactor. Wraps :class:`InjectionPatternDetector` so
the firewall is a first-class chain component. The regex logic
(30+ patterns, normalisation, token masking) lives in
``injection_patterns.py`` and is reused verbatim — no behavioural
change, only a structural one.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .injection_patterns import InjectionPatternDetector


class InstructionFirewall(BaseDetector):
    """Layer 2 detector — scan text for prompt-injection patterns.

    Delegates to the existing :class:`InjectionPatternDetector` for
    backwards compatibility with the test suite and the Privacy-Shield
    token-masking behaviour. Adding a new pattern is a one-line change
    in ``injection_patterns.INJECTION_PATTERNS`` — no plugin changes
    required.
    """

    def __init__(self) -> None:
        self._detector = InjectionPatternDetector()

    @property
    def name(self) -> str:
        return "instruction_firewall"

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        return self._detector.check(text, context)
