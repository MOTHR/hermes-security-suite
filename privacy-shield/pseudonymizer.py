"""Deterministic Pseudonymizer — Phase 1.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 5.5

Token styles:
- Text prompts: ``{PREFIX}_{TYPE}_{HASH}_{COUNTER}``
  (e.g. ``TOKEN_EMAIL_a1b2c3d4e5_001`` — deterministic, referential)
- Code contexts: ``[REDACTED:type]`` (non-reversible, syntax-safe)

Determinism: same input → same token within same session.

SMELL-4 (Morpheus R5): module docstring previously showed the obsolete
``EMAIL_001`` / ``PHONE_002`` format from Phase 1.  The actual token
shape is now ``{PREFIX}_{TYPE}_{HASH}_{COUNTER}`` (Phase 4 / FIX-4A),
and is documented inline on the class below.
"""

from __future__ import annotations

import hashlib
import secrets
from collections import OrderedDict
from typing import Any

from . import COUNTER_DIGITS, DEFAULT_HASH_LENGTH
from .detectors.dataclasses import PIIMatch
from .metrics import record_cache_hit, record_cache_miss, record_masking


class Pseudonymizer:
    """Deterministic PII pseudonymization.

    Token format: {PREFIX}_{TYPE}_{HASH}_{COUNTER} for text contexts.
    [REDACTED:type] for code contexts.

    Tokens are deterministic per (session_id, pii_type, value) tuple using a
    truncated SHA-256 hash over a per-session salt, plus a monotonically
    increasing per-session counter as suffix. The counter makes hash collisions
    within a session mathematically impossible (each token gets a unique
    counter), while the 10-hex hash keeps tokens visually compact.

    ``HASH_LENGTH`` and ``COUNTER_DIGITS`` are kept here as class attributes
    so older callers that referenced them via the class still work, but the
    CANONICAL source of truth is ``privacy_shield.DEFAULT_HASH_LENGTH`` and
    ``privacy_shield.COUNTER_DIGITS`` (re-exported at package import time).
    Other plugins (e.g. ``injection_shield``) MUST import from
    ``privacy_shield`` directly so the contract stays locked to a single
    place. See ``privacy_shield/__init__.py`` (FIX-XPLUGIN-TOKEN) for the
    full contract + migration history.
    """

    # Class-level constants. Reference the canonical module-level values
    # imported from ``privacy_shield.__init__`` so any future change to
    # the contract flows through automatically.
    HASH_LENGTH = DEFAULT_HASH_LENGTH
    COUNTER_DIGITS = COUNTER_DIGITS
    MAX_TOKEN_COUNTER = 10**COUNTER_DIGITS - 1  # 999 inclusive
    DEFAULT_MAX_CACHE_SIZE = 10_000  # ~1–2 MB memory budget at ~200 B/entry
    DEFAULT_MAX_SESSION_SALTS = 1_000  # ~16 KB memory budget (16 bytes * 1000)

    def __init__(
        self,
        token_style: str = "deterministic",
        token_prefix: str = "TOKEN",
        max_cache_size: int | None = None,
        max_session_salts: int | None = None,
    ):
        self.token_style = token_style
        self.token_prefix = token_prefix
        # Bound memory growth in long sessions with LRU eviction.
        self.max_cache_size = max(
            1,
            max_cache_size
            if max_cache_size is not None
            else self.DEFAULT_MAX_CACHE_SIZE,
        )
        # Bound the number of tracked session salts/counters. When the cap is
        # reached the least-recently-used session is evicted together with all
        # of its cached tokens — preventing unbounded memory growth in
        # long-running services that see many short-lived sessions.
        self.max_session_salts = max(
            1,
            max_session_salts
            if max_session_salts is not None
            else self.DEFAULT_MAX_SESSION_SALTS,
        )
        # Cache key: (session_id, pii_type, value) -> token
        self._token_cache: OrderedDict[tuple[str, str, str], str] = OrderedDict()
        # Per-session random salt prevents cross-session collisions and
        # guarantees that identical values in different sessions tokenize
        # independently even if the short hash should ever collide.
        # OrderedDict gives us LRU semantics via move_to_end / popitem(last=False).
        self._session_salts: OrderedDict[str, bytes] = OrderedDict()
        # Per-session deterministic counter makes same-session collisions
        # impossible: every newly created token gets a unique suffix within the
        # session. We still keep the 10-hex hash for URL-friendliness and so
        # identical values can be recognized as matching tokens in different
        # sessions (with different salts the hash part already differs).
        # Same LRU semantics as the salts.
        self._session_counters: OrderedDict[str, int] = OrderedDict()

    def _get_session_salt(self, session_id: str) -> bytes:
        """Lazy-generate a persistent per-session salt with LRU eviction.

        When the number of tracked sessions reaches ``max_session_salts`` the
        least-recently-used session is evicted together with all of its cached
        tokens.  Eviction ensures cross-cache consistency: a session that has
        been forgotten cannot leave orphan tokens in ``_token_cache``.
        """
        if session_id in self._session_salts:
            # Promote to most-recently-used on every access.
            self._session_salts.move_to_end(session_id)
            return self._session_salts[session_id]

        # Evict the LRU session when the cap is reached. We must also evict
        # the counter for the same session and drop its cached tokens so the
        # three dictionaries stay consistent.
        if len(self._session_salts) >= self.max_session_salts:
            evicted_session, _ = self._session_salts.popitem(last=False)
            self._session_counters.pop(evicted_session, None)
            self._evict_session_tokens(evicted_session)

        # Generiere neuen Salt
        salt = secrets.token_bytes(16)
        self._session_salts[session_id] = salt
        return salt

    def _evict_session_tokens(self, session_id: str) -> int:
        """Drop all cached tokens for ``session_id``. Returns count removed."""
        removed = 0
        for key in list(self._token_cache.keys()):
            if key[0] == session_id:
                del self._token_cache[key]
                removed += 1
        return removed

    def _next_session_counter(self, session_id: str) -> int:
        """Return the next deterministic counter value for a session.

        Counters are tracked in ``_session_counters`` (OrderedDict, LRU).
        If the session was previously evicted from ``_session_salts`` it will
        be re-added here — eviction guarantees both dictionaries stay in
        lock-step.
        """
        if session_id in self._session_counters:
            # Promote to MRU on access.
            self._session_counters.move_to_end(session_id)
        else:
            # Session not tracked yet: ensure we are within the cap before
            # adding a new entry.  In normal flow this is a no-op because
            # ``_get_session_salt`` has just registered the same session.
            if len(self._session_counters) >= self.max_session_salts:
                evicted_session, _ = self._session_counters.popitem(last=False)
                # Mirror eviction in the salts dict if it still holds the entry
                # (defensive — typically already evicted by salt lookup).
                self._session_salts.pop(evicted_session, None)
                self._evict_session_tokens(evicted_session)
        counter = self._session_counters.get(session_id, 0)
        self._session_counters[session_id] = (
            (counter + 1) % (self.MAX_TOKEN_COUNTER + 1)
            if counter < self.MAX_TOKEN_COUNTER
            else 0
        )
        return counter

    def _make_token(self, pii_type: str, value: str, session_id: str = "") -> str:
        """Generate a deterministic token for a PII value.

        Same value always produces the same token within the same session.
        Different sessions produce independent token strings for the same value.
        """
        effective_session = session_id or "_default"
        cache_key = (effective_session, pii_type, value)
        if cache_key in self._token_cache:
            # Promote to most-recently-used on every access.
            self._token_cache.move_to_end(cache_key)
            # Also promote the owning session so LRU eviction reflects actual
            # session activity, not just new-token creation. Without this a
            # session that only re-uses existing tokens would still be
            # evicted as the LRU once a new session is added.
            if effective_session in self._session_salts:
                self._session_salts.move_to_end(effective_session)
            if effective_session in self._session_counters:
                self._session_counters.move_to_end(effective_session)
            record_cache_hit()
            return self._token_cache[cache_key]

        record_cache_miss()

        # Per-session salt + session/type/value in the hash input makes
        # collisions across sessions computationally infeasible. The session
        # counter suffix guarantees that collisions within a session are
        # impossible, too.
        salt = self._get_session_salt(effective_session)
        h = hashlib.sha256(
            salt + f"{effective_session}:{pii_type}:{value}".encode()
        ).hexdigest()
        short_hash = h[: self.HASH_LENGTH]
        counter = self._next_session_counter(effective_session)
        token = f"{self.token_prefix}_{pii_type.upper()}_{short_hash}_{counter:0{self.COUNTER_DIGITS}d}"

        # Evict least-recently-used entry when the cache is full.
        if len(self._token_cache) >= self.max_cache_size:
            self._token_cache.popitem(last=False)

        self._token_cache[cache_key] = token
        return token

    def clear_cache(self) -> None:
        """Hard reset of all internal caches.

        Clears the token cache AND the per-session salts and counters.  Tests
        and cold starts rely on this being a complete reset; partial resets
        would leave stale salts in memory and waste the LRU budget.
        """
        self._token_cache.clear()
        self._session_salts.clear()
        self._session_counters.clear()

    def close_session(self, session_id: str) -> int:
        """Best-effort crypto-shred: drop the per-session salt, counter and tokens.

        Returns the number of cached tokens removed for the session.
        """
        removed = self._evict_session_tokens(session_id)
        self._session_salts.pop(session_id, None)
        self._session_counters.pop(session_id, None)
        return removed

    def _make_redacted(self, pii_type: str) -> str:
        """Generate a [REDACTED:type] marker for code contexts."""
        return f"[REDACTED:{pii_type}]"

    def replace(
        self,
        text: str,
        matches: list[PIIMatch],
        *,
        code_context: bool = False,
        session_id: str = "",
    ) -> tuple[str, list[dict[str, Any]]]:
        """Replace PII matches with tokens.

        Args:
            text: Original text
            matches: Detected PII matches (sorted by position)
            code_context: If True, use [REDACTED:type] instead of tokens
            session_id: Session identifier for token scope isolation

        Returns:
            (sanitized_text, mapping_list)
            mapping_list: [{"original_hash": sha256, "token": "EMAIL_a1b2c3d4", "type": "email"}, ...]
        """
        if not matches:
            return text, []

        # Build replacement from end to start to preserve offsets
        result = list(text)
        mapping = []

        for match in reversed(matches):
            if code_context:
                token = self._make_redacted(match.type)
            else:
                token = self._make_token(match.type, match.value, session_id=session_id)

            # Replace in text
            result[match.start : match.end] = token

            # Record mapping
            original_hash = hashlib.sha256(match.value.encode()).hexdigest()
            mapping.append(
                {
                    "original_hash": original_hash,
                    "original_value": match.value,
                    "token": token,
                    "type": match.type,
                }
            )

        # Reverse mapping back to original order
        mapping.reverse()

        if mapping:
            record_masking(len(mapping))

        return "".join(result), mapping

    def is_code_context(self, text: str) -> bool:
        """Heuristic: detect if text is code (not natural language).

        Simple heuristic: high density of special characters,
        indentation patterns, or common code keywords.
        """
        if not text:
            return False

        # Code indicators
        code_indicators = [
            "def ",
            "class ",
            "import ",
            "from ",
            "return ",
            "function ",
            "const ",
            "let ",
            "var ",
            "if (",
            "for (",
            "while (",
            "#!/",
            "```",
        ]
        indicator_count = sum(1 for ind in code_indicators if ind in text)

        # High ratio of special chars suggests code
        special_chars = sum(1 for c in text if c in "{}[]();:=<>|&!@#$%^*/\\")
        special_ratio = special_chars / max(len(text), 1)

        return indicator_count >= 2 or special_ratio > 0.15

    def restore(self, text: str, mapping: list[dict[str, Any]]) -> str:
        """Restore tokens in text back to original PII values.

        Uses the mapping list produced by ``replace``. Tokens that are not
        found in the mapping are left unchanged. Replacement is performed
        from end to start so that earlier token lengths do not shift later
        matches.
        """
        if not text or not mapping:
            return text

        result = list(text)
        for entry in reversed(mapping):
            token = entry.get("token", "")
            original = entry.get("original_value", "")
            if not token or not original:
                continue
            # Find all non-overlapping occurrences of this token in the current
            # text, scanning from the end so positions remain stable.
            token_len = len(token)
            i = len(result) - token_len
            while i >= 0:
                if "".join(result[i : i + token_len]) == token:
                    result[i : i + token_len] = original
                    # After replacement, position i is before the original value;
                    # continue scanning before the inserted text.
                    i = i - 1
                    continue
                i -= 1

        return "".join(result)
