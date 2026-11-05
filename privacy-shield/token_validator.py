"""GB-010 defensive helpers for reasoning redaction verification.

Hermes-Core builds ``result["last_reasoning"]`` from the same
``messages`` array that Privacy-Shield mutates in-place during
``post_llm_call`` (Spike-001).  These small validators let the hook
confirm that the mutation actually reached the last assistant message
and that no obvious raw PII survived.
"""

from __future__ import annotations

import re
from typing import Any


# Fast check for a Privacy-Shield token shape, e.g. TOKEN_EMAIL_abc123_001.
_TOKEN_RE = re.compile(r"\bTOKEN_[A-Z_]+_[0-9a-f]{10}_\d{3}\b")

# Minimal sanity check: does the text still contain something that looks
# like an email address?  This is intentionally cheap — we only need to
# catch the "hook did not run at all" case, not reproduce the full detector.
_EMAIL_RE = re.compile(r"\b[^@\s]+@[^@\s]+\.[^@\s]+\b")


def contains_privacy_shield_token(text: str | None) -> bool:
    """Return True if *text* contains at least one Privacy-Shield token."""
    if not isinstance(text, str) or not text:
        return False
    return bool(_TOKEN_RE.search(text))


def has_raw_pii(text: str | None) -> bool:
    """Return True if *text* still looks like it contains raw email PII.

    This is a defensive smoke test, not a replacement for the full
    detector.  It is used to warn operators when the post_llm_call hook
    appears not to have tokenised the last reasoning block.
    """
    if not isinstance(text, str) or not text:
        return False
    return bool(_EMAIL_RE.search(text))


def find_last_assistant_reasoning(messages: list[Any]) -> str | None:
    """Return the ``reasoning`` value of the most recent assistant message.

    Mirrors the logic in Hermes-Core ``turn_finalizer.py`` that builds
    ``result["last_reasoning"]``.
    """
    if not messages:
        return None
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "user":
            break
        if msg.get("role") == "assistant":
            reasoning = msg.get("reasoning")
            if isinstance(reasoning, str) and reasoning:
                return reasoning
    return None
