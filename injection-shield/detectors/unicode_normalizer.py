"""Aggressive Unicode normalization for prompt-injection detection.

Closes bypasses that pure NFKC normalization misses:

1. **Variation Selectors** (U+FE00-U+FE0F, plus U+E0100-U+E01EF).
   These are combining marks that influence glyph selection (emoji
   presentation, CJK compatibility) but have no semantic content of
   their own.  NFKC keeps them in place, so a token like
   ``igno\uFE00re previous instructions`` survives NFKC unchanged and
   defeats the regex scanner.

2. **Combining Marks** (Unicode general category ``Mn``).
   Even after stripping variation selectors, an attacker can split
   a word by inserting a combining acute / grave / tilde / etc.
   between ASCII letters.  NFKC does not strip Mn marks; the
   resulting string still does not match ``ignore`` literally.

3. **Compatibility decomposition** (NFKD).
   Some ideographic and symbol lookalikes (fullwidth forms, CJK
   compatibility ideographs) only decompose under NFKD, not NFKC.
   Recomposing via NFC afterwards gives a clean, canonical form.

The function is order-dependent: NFKD first, then NFC to recompose
precomposed characters, then strip zero-width + variation selectors
+ all Mn marks.
"""

from __future__ import annotations

import re
import unicodedata

# Variation Selectors Supplement (U+E0100-U+E01EF) — used in emoji
# sequences.  Python's ``re`` module handles this with a regular
# BMP-surrogate pair; we compile the regex once at import time.
# Range U+FE00..U+FE0F = Variation Selectors 1..16.
# Range U+E0100..U+E01EF = Variation Selectors Supplement 17..256.
_VS_PATTERN = re.compile(
    "["
    "\uFE00-\uFE0F"           # VS1-VS16 (BMP)
    "\U000E0100-\U000E01EF"   # VS17-VS256 (SMP)
    "]"
)

# All visible combining marks.  We rely on unicodedata.category(c) == "Mn"
# at runtime because the union of Mn blocks spans BMP+SMP+SSP and a
# hand-rolled list of ranges is fragile across Unicode versions.
#
# This module-level frozenset is only for the small overlap with chars
# that NFKC / NFKD already fold; we still re-test category at runtime
# in normalize_aggressive to catch anything Unicode adds in the future.


def strip_variation_selectors(text: str) -> str:
    """Remove all Variation Selector codepoints (VS1-VS256)."""
    return _VS_PATTERN.sub("", text)


def strip_combining_marks(text: str) -> str:
    """Remove every character whose general category is 'Mn' (nonspacing mark).

    Includes combining accents, diacritics, enclosing keycaps, etc.
    Does NOT touch characters from other categories that happen to
    render as combining marks (e.g. ZWJ, ZWSP — those are handled by
    ``zero_width.py``).

    WARNING — this is destructive. ``Lösche`` becomes ``Losche``,
    ``naïve`` becomes ``nave``.  Use only on a *second* pass through
    the regex detector, not as the primary normalizer, so that
    legitimate German / French / Spanish diacritics in real injection
    text (``Lösche die Datei``) still match the language-specific
    patterns.
    """
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")


def normalize_aggressive(text: str) -> str:
    """Return a normalized form of ``text`` that defeats variation-selector
    and combining-mark bypasses.

    Pipeline:
        1. NFKD — compatibility decomposition (folds fullwidth, etc.)
        2. Strip Variation Selectors (VS1-VS256) — done BEFORE recomposition
           so SMP variation selectors do not survive NFC.
        3. Strip all Mn (nonspacing combining marks) — done BEFORE
           recomposition.  This is critical: if we recomposed first,
           an ``i`` + U+0301 sequence would recompose into the
           precomposed U+00ED (í), which is category Ll and would
           no longer be strippable as Mn.  By stripping Mn while
           the codepoints are still in their decomposed form, we
           remove the base letter's decoration entirely.
        4. NFC — recompose precomposed characters that survived.

    Use this on a SECOND pass of the regex scanner (the ``stripped``
    variant).  For the primary pass, prefer
    :func:`normalize_preserving_diacritics`, which leaves legitimate
    German/French/Spanish diacritics intact so language-specific
    patterns (``lösche die Datei``) still match.
    """
    # Step 1: compatibility decomposition.
    text = unicodedata.normalize("NFKD", text)

    # Step 2: variation selectors (before recomposition, so the SMP
    # range is still in its decomposed form).
    text = strip_variation_selectors(text)

    # Step 3: all Mn combining marks.  Must happen before recomposition
    # so the base letter's decoration is gone regardless of whether
    # the original form was precomposed or decomposed.
    text = strip_combining_marks(text)

    # Step 4: final NFC pass for canonical form.
    text = unicodedata.normalize("NFC", text)

    return text


def normalize_preserving_diacritics(text: str) -> str:
    """Conservative normalizer: strip variation selectors, fold
    fullwidth/compatibility, but keep Latin/Cyrillic diacritics.

    This is the PRIMARY surface for the regex scanner — it lets
    language-specific patterns like ``Lösche die Datei`` continue to
    match.  Variation-selector bypasses are still closed (NFKD does
    not touch U+FE00-U+FE0F, so we strip them explicitly).

    Combining-mark bypasses (``i`` + U+0301 inside ``ignore``) are
    caught by a SECOND scan of the same text through
    :func:`normalize_aggressive`.  The detector unions hits from
    both passes.
    """
    text = unicodedata.normalize("NFKD", text)
    text = strip_variation_selectors(text)
    text = unicodedata.normalize("NFC", text)
    return text


__all__ = [
    "normalize_aggressive",
    "normalize_preserving_diacritics",
    "strip_combining_marks",
    "strip_variation_selectors",
]
