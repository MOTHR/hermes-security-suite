"""Layer 1: Content tagger — mark untrusted tool output.

ARCH-1 (FIX-2D) refactor. Previously this logic lived as an inline
``if tool_name in UNTRUSTED_SOURCES or tool_name.startswith(MCP_PREFIX)``
branch inside ``plugin.py``. Extracting it into a detector makes the
tagging step testable in isolation and lets new source-classes
(untrusted MCP outputs, fetched web pages, …) plug into the same
chain without touching ``plugin.py``.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .homoglyph_map import HOMOGLYPHS as _HOMOGLYPHS  # GENERATED — do not hand-edit

# v0.6.0 (G-001, Agent-Smith review): tools that fetch external content or
# execute arbitrary code produce attacker-influencable output — treat as
# untrusted. Matching is case-insensitive (G-002: "Browser_navigate" bypass).
UNTRUSTED_SOURCES = {
    "web_extract",
    "web_search",
    "read_file",
    "search_files",
    "execute_code",
    "fetch_url",
    "download_file",
    "api_call",
}
MCP_PREFIX = "mcp__"

# DG-001 (Smith wave-2): homoglyph/zero-width/whitespace bypasses.
# Cyrillic/Greek lookalikes NFKD does NOT fold are covered by the generated
# ``_HOMOGLYPHS`` map (TR39 confusables + reviewed gap-fill extensions, see
# ``scripts/generate_homoglyph_map.py`` and ``data/confusables.txt``; Orakel
# W2-1 follow-up t_cb41d625). Mixed-script names like
# 'w\u0435b_\u0435xtr\u0430ct'/'w\u0435b\u0432_extract' still hit the untrusted set.
_STRIP_CHARS = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x00}
_TO_UNDERSCORE = {0x20, 0x09}  # space/tab inside tool names


def is_untrusted_source(source: str) -> bool:
    """Return True if ``source`` is an untrusted tool/MCP name.

    Exposed so callers (e.g. ``plugin.py``'s ``post_tool_call`` hook)
    can apply the *same* policy the detector uses when deciding
    whether to wrap the tool result. Keeping the predicate next to
    the detector prevents the two from drifting.
    """
    if not source:
        return False
    source = str(source)
    for glyph, ascii_eq in _HOMOGLYPHS.items():
        source = source.replace(chr(glyph), ascii_eq)
    for codepoint in _STRIP_CHARS:
        source = source.replace(chr(codepoint), "")
    for codepoint in _TO_UNDERSCORE:
        source = source.replace(chr(codepoint), "_")
    import unicodedata
    source = unicodedata.normalize("NFKD", source).lower()
    # DG-001: zero-width/space variants compare separator-insensitively
    # against the set ("web\u200bextract" == "web_extract" for policy).
    stripped = source.replace("_", "")
    if stripped in {s.replace("_", "") for s in UNTRUSTED_SOURCES}:
        return True
    return source.startswith((MCP_PREFIX, "browser"))


class ContentTagger(BaseDetector):
    """Layer 1 detector — flag content originating from untrusted sources.

    The detector itself does NOT rewrite the text; it emits a
    violation record so the audit log knows the message should be
    wrapped in ``<untrusted_tool_result>`` tags downstream. The
    actual wrapping is performed by the ``post_tool_call`` hook in
    ``plugin.py`` using the same predicate
    :func:`is_untrusted_source`.
    """

    @property
    def name(self) -> str:
        return "content_tagger"

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        """Return a single ``untrusted_content`` violation if context.source is untrusted.

        ``text`` is accepted for signature compatibility but the
        detector only inspects ``context["source"]``. This keeps the
        chain uniform — every detector takes ``(text, context)`` —
        while still doing the right thing semantically.
        """
        if not context:
            return []
        source = context.get("source")
        if not source or not is_untrusted_source(source):
            return []
        return [
            {
                "type": "untrusted_content",
                "source": source,
                "tag": "<untrusted_tool_result>",
                "severity": "info",
            }
        ]
