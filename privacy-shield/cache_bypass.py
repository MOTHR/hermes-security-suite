"""CacheBypassInjector — prepend ephemeral cache-bypass markers.

Morpheus R5 (MORPH-PS-3, REFACTOR-2 + REFACTOR-3 partial):
:class:`PrivacyShieldPlugin` previously held ``_add_cache_bypass_tag``
as a private method that prepended a session-unique marker so Hermes'
per-conversation cache key changed every turn.  This module packages
the logic in a small dedicated class so the plugin keeps only the
high-level hook orchestration.

The class is intentionally tiny: the marker format is a frozen list
of three formats (bracket, key-value, HTML comment) so at least one
survives provider-side normalization that strips single markers.
"""

from __future__ import annotations

import time
from typing import Any


class CacheBypassInjector:
    """Prepend a session-unique cache-bypass marker to *text*.

    The marker changes every turn, so Hermes' per-conversation cache
    key (which is derived from the message content) cannot reuse a
    previous turn's pseudonymized content verbatim.  That would
    otherwise leak tokenized PII into the cache and back to a later
    request that legitimately should not see it.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def inject(self, text: str, ctx: dict[str, Any]) -> str:
        """Return *text* prefixed with a fresh cache-bypass marker.

        No-op when ``enabled`` is False.  Always returns a string
        (never ``None``) so callers can use the result as a drop-in
        replacement.
        """
        if not self._enabled:
            return text

        session_id = ctx.get("session_id", "")
        timestamp = time.time()
        short = session_id[:8]
        markers = [
            f"[Privacy-Shield Session:{session_id}:{timestamp}]",
            f"[PS:{short}:{timestamp}]",
            f"<!-- privacy-shield session={short} ts={timestamp} -->",
        ]
        return "\n".join(markers) + "\n" + text


__all__ = ["CacheBypassInjector"]
