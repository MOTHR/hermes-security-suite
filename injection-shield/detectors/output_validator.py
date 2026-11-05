"""Layer 3: Output validator — user-action directives in text.

ARCH-1 (FIX-2D) refactor. Wraps :class:`InjectionPatternDetector`'s
``check_for_user_actions`` so action directives (click here, send to
email, rotate your API key) get their own slot in the
:class:`DetectorChain`. The regex set is reused from
``injection_patterns.USER_ACTION_PATTERNS`` for the same reason as
:mod:`instruction_firewall`.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .injection_patterns import InjectionPatternDetector


class OutputValidator(BaseDetector):
    """Layer 3 detector — scan text for user-action directives.

    Returns violations shaped like
    ``{"type": "user_action", "pattern_idx": N, "match": ..., "severity": "medium"}``
    so the existing audit-log redactor and Telegram alerter keep
    working unchanged.
    """

    def __init__(self) -> None:
        self._detector = InjectionPatternDetector()

    @property
    def name(self) -> str:
        return "output_validator"

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        return self._detector.check_for_user_actions(text, context)
