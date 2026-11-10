"""Homoglyph map regeneration — parity between generated map and TR39 source.

Orakel W2-1 follow-up (t_cb41d625): the ``_HOMOGLYPHS`` map used by
``content_tagger.is_untrusted_source`` must be generated from Unicode
TR39 confusables data (``data/confusables.txt``) via
``scripts/generate_homoglyph_map.py`` instead of hand-maintained.
"""

from __future__ import annotations

import importlib.util
import string
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parents[1]
_SOURCE_DATA = _PKG_DIR / "data" / "confusables.txt"
_GENERATOR = _PKG_DIR / "scripts" / "generate_homoglyph_map.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_homoglyph_map", _GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_map_matches_confusables_source() -> None:
    """The shipped map is exactly what regeneration from the vendored
    TR39 data (plus the generator's documented gap-fill extensions)
    produces."""
    gen = _load_generator()
    text = _SOURCE_DATA.read_text(encoding="utf-8")
    expected = gen.merge_with_extensions(gen.extract_map(text))
    from injection_shield.detectors.homoglyph_map import HOMOGLYPHS

    assert HOMOGLYPHS == expected


def test_map_is_deterministic_and_contract_clean() -> None:
    from injection_shield.detectors.homoglyph_map import HOMOGLYPHS

    allowed = set(string.ascii_lowercase + string.digits)
    assert all(isinstance(k, int) and k >= 0xA0 for k in HOMOGLYPHS)
    assert all(
        isinstance(v, str) and len(v) == 1 and v in allowed for v in HOMOGLYPHS.values()
    )
    assert list(HOMOGLYPHS) == sorted(HOMOGLYPHS)


def test_tr39_win_over_hand_map_conflicts() -> None:
    """Where the old hand map disagreed with TR39, TR39 wins:
    б (U+0431) confuses with '6', σ (U+03C3) with 'o' — not 'b'/'s'."""
    from injection_shield.detectors.homoglyph_map import HOMOGLYPHS

    assert HOMOGLYPHS[0x0431] == "6"
    assert HOMOGLYPHS[0x03C3] == "o"


def test_gap_fill_extensions_present() -> None:
    """Visually-identical glyphs TR39 omits (non-ASCII targets) stay
    folded — hand-map coverage is not silently lost."""
    from injection_shield.detectors.homoglyph_map import HOMOGLYPHS

    for cp, expected in (
        (0x043A, "k"),  # к
        (0x043C, "m"),  # м
        (0x043D, "h"),  # н
        (0x03B5, "e"),  # ε
        (0x03C9, "w"),  # ω
    ):
        assert HOMOGLYPHS[cp] == expected, f"gap-fill missing for U+{cp:04X}"


def test_predicate_uses_generated_map() -> None:
    """Mixed-script spoofed tool names still fold into the untrusted set."""
    from injection_shield.detectors.content_tagger import is_untrusted_source

    assert is_untrusted_source("w\u0435b_\u0435xtr\u0430ct")
    assert is_untrusted_source("m\u0441\u0440__x")
    assert is_untrusted_source("we\u0432_extract")  # в→b via gap-fill → "web_extract"
    assert not is_untrusted_source("fil\u0435_read")
