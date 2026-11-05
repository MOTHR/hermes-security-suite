"""Base class and Chain-of-Responsibility for defense-layer detectors.

ARCH-1 (FIX-2D) — the previous plugin had all 4 defense layers as
methods on a single ``InjectionShieldPlugin`` class. This module
extracts each layer into an independent, single-responsibility
component that implements :class:`BaseDetector`. The
:class:`DetectorChain` composes them so a crash in one detector
cannot block the rest of the pipeline (fail-separate).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Abstract base class for every defense-layer detector.

    A detector is a single-responsibility component: it inspects a
    chunk of text (with optional ``context`` metadata) and returns a
    list of violation dicts. It must NEVER raise into the caller's
    pipeline — :class:`DetectorChain` wraps ``check`` in a try/except
    so a buggy detector logs and is skipped instead of taking the
    whole shield down.
    """

    @abstractmethod
    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        """Return violations for ``text``.

        Args:
            text: the text to scan.
            context: optional metadata about the text origin (e.g.
                ``{"source": "tool"}`` for tool output). Detectors
                MAY ignore unknown context keys.

        Returns:
            A list of violation dicts. The exact schema is per-detector
            but every violation SHOULD include ``type`` and
            ``severity`` so the audit log can fingerprint it.
        """

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable detector name for audit logs and repr."""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<{self.__class__.__name__} name={self.name}>"


class DetectorChain:
    """Chain-of-Responsibility that runs detectors in order.

    The chain enforces **fail-separate** semantics: a detector that
    raises an exception is logged at WARNING level and skipped, but
    later detectors still run and their violations are aggregated.
    This is critical for defense-in-depth — a bug in one layer
    (e.g. a regex blow-up on adversarial input) must never take the
    whole shield offline.
    """

    def __init__(self, detectors: list[BaseDetector]) -> None:
        self.detectors = list(detectors)

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        """Run every detector and return the merged violation list."""
        violations: list[dict[str, Any]] = []
        for detector in self.detectors:
            try:
                violations.extend(detector.check(text, context))
            except Exception as exc:  # noqa: BLE001 - fail-separate is the contract
                # Log and skip — do NOT let one bad detector block the chain.
                logger.warning(
                    "DetectorChain: detector %s failed: %s",
                    getattr(detector, "name", repr(detector)),
                    exc,
                )
        return violations

    def __len__(self) -> int:
        return len(self.detectors)

    def __iter__(self):
        return iter(self.detectors)
