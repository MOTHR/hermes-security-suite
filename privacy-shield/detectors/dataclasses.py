"""Shared detector dataclasses for Privacy-Shield.

Morpheus R5 (MORPH-PS-4): ``PIIMatch`` previously lived in
``detectors/regex_detector.py``, which forced
``detectors/context_leak_detector.py`` to use a function-local
``_get_pii_match_class()`` lazy import to break a circular
``regex_detector ↔ context_leak_detector`` import chain.

The fix is mechanical: lift the dataclass to its own leaf module
that depends on nothing but stdlib so both detectors can import it
directly.  ``regex_detector`` re-exports the symbol for backward
compatibility with the test suite and external callers.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PIIMatch:
    """A detected PII entity in text.

    Attributes
    ----------
    type:
        Match category — e.g. ``"email"``, ``"phone"``, ``"crypto_btc"``,
        ``"jwt"``.  Used as the token ``TYPE`` segment and as the
        audit-log explainability tag.
    value:
        The matched substring (the raw PII, before pseudonymisation).
    start:
        Character offset of the match in the original text (inclusive).
    end:
        Character offset of the match in the original text (exclusive).
    confidence:
        Detector confidence in the range 0.0..1.0.  Regex hits are
        deterministic and emit ``1.0``; heuristic / context-leak hits
        emit values in ``(0.0, 1.0)`` so downstream filtering can
        drop low-confidence noise without losing high-signal PII.
    rule:
        Explainability tag — e.g. ``"regex:email"``,
        ``"name:firstname_whitelist"``,
        ``"context_leak:unique_role"``.  Surface this in audit logs so
        operators can trace which detector fired for any given match.
    """

    type: str
    value: str
    start: int
    end: int
    confidence: float = 1.0
    rule: str = ""


__all__ = ["PIIMatch"]
