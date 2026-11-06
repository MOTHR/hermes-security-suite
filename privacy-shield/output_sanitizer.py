"""OutputSanitizer — LLM-response PII sanitization.

Morpheus R5 (MORPH-PS-3, REFACTOR-2): :class:`PrivacyShieldPlugin`
previously held ``_sanitize_output_pii`` and ``_mask_tokens`` as
private methods.  This module packages them in a dedicated class so
the plugin keeps only the high-level hook orchestration.

Behaviour is preserved byte-for-byte: the post-LLM hook still
short-circuits on empty / disabled, masks existing tokens with
whitespace so the detector does not re-tokenise them, then applies
the confidence partition + known-values filter to drop round-trip
mappings, and finally pseudonymises the truly-fresh PII.

The class deliberately does **not** store the result back into the
mapping table — that would let the subsequent restore pass undo the
sanitisation.  The behaviour matches the inline comment in the
original ``_sanitize_output_pii`` and the Morpheus R5 review note on
``SEC-4``.
"""

from __future__ import annotations

import re
from typing import Any, Optional


class OutputSanitizer:
    """Sanitize fresh PII in an LLM response.

    Two filters prevent the false-positive cascade where an emitted
    token is itself scanned and re-tokenised:

    1. :meth:`_mask_tokens` replaces existing
       ``{PREFIX}_{TYPE}_{HASH}_{COUNTER}`` spans with whitespace
       before the detector runs.  The regex detector sees only the
       gaps; the response length is preserved.
    2. The session-mapping lookup excludes values that were already
       pseudonymised upstream, so they survive the scan and reach
       :meth:`MappingTable.restore_text` unchanged.
    """

    def __init__(
        self,
        detector: Any,
        pseudonymizer: Any,
        mapper: Any,
        *,
        partition_by_confidence: Any,
    ) -> None:
        self._detector = detector
        self._pseudonymizer = pseudonymizer
        self._mapper = mapper
        self._partition_by_confidence = partition_by_confidence

    def sanitize(
        self,
        text: Optional[str],
        session_id: str = "",
        fresh_tokens: Optional[set[str]] = None,
    ) -> tuple[Optional[str], int]:
        """Sanitize fresh PII in *text* and return ``(text, count)``.

        Returns ``(text, 0)`` when there is nothing to do (empty
        text, no detections, no high-confidence detections, or all
        hits are round-trip mappings).  When fresh PII is found the
        sanitized text is returned and *count* is the number of
        tokens it now contains.

        NOTE: We deliberately do NOT call ``mapper.store()`` here.
        Storing the fresh mapping would let the subsequent
        restore_text pass resolve the token back to the original
        PII, defeating the sanitisation.  The user must see the
        token, not the raw value.

        v1.7.6 (FIX-1B): when *fresh_tokens* is a set (the optional out
        param), the tokens minted in THIS call are reported to the caller
        so the residual-restore pass (restore-miss placeholder / splice
        repair) leaves them untouched — they are intentionally
        unresolvable and must stay visible.  The existing 2-tuple return
        contract is unchanged.
        """
        if not text:
            return text, 0

        token_re = self._mapper.token_pattern
        masked, _spans = self._mask_tokens(text, token_re)

        pii_hits = self._detector.scan(masked)
        if not pii_hits:
            return text, 0

        # Confidence partition: drop low-confidence hits (audit-only).
        masked_hits, _dropped = self._partition_by_confidence(pii_hits)
        if not masked_hits:
            return text, 0

        # Drop hits whose original value already has a token in this
        # session — those are the "round-trip" cases, not fresh leaks.
        known = (
            self._mapper.known_original_values(session_id)
            if session_id
            else set()
        )
        fresh_hits = [m for m in masked_hits if m.value not in known]
        if not fresh_hits:
            return text, 0

        sanitized, _mapping = self._pseudonymizer.replace(
            text, fresh_hits, session_id=session_id
        )
        if fresh_tokens is not None:
            fresh_tokens.update(
                entry["token"]
                for entry in _mapping
                if entry.get("token")
            )
        return sanitized, len(fresh_hits)

    @staticmethod
    def _mask_tokens(
        text: str, token_re: "re.Pattern[str]"
    ) -> tuple[str, list[tuple[int, int]]]:
        """Replace every ``token_re`` match in *text* with whitespace.

        The whitespace mask preserves offsets so the regex detector
        and the surrounding code can still index into the original
        text by character position.  Returns ``(masked_text, spans)``
        where each span is ``(start, end)`` of a replaced token in
        the original (unmasked) text.
        """
        if not text:
            return text, []

        spans: list[tuple[int, int]] = []

        def _blank(match: "re.Match[str]") -> str:
            spans.append((match.start(), match.end()))
            return " " * (match.end() - match.start())

        masked = token_re.sub(_blank, text)
        return masked, spans


__all__ = ["OutputSanitizer"]
