"""Generate ``detectors/homoglyph_map.py`` from Unicode confusables.txt.

Orakel W2-1 follow-up (t_cb41d625): the homoglyph folding map used by
``content_tagger.is_untrusted_source`` must be generated from the
Unicode TR39 confusables data instead of a hand-picked subset.

Extraction rule (deterministic):

* one source codepoint → one ASCII letter/digit (``[a-z0-9]`` after
  ``str.lower``); multi-codepoint sequences and non-Latin targets are
  skipped,
* ASCII/C-control sources (< 0xA0) are never mapped — ASCII must stay
  ASCII or legit tool names would mutate,
* first occurrence wins (``confusables.txt`` is sorted by codepoint),
  output is sorted by codepoint.

Usage::

    python scripts/generate_homoglyph_map.py                # vendored data
    python scripts/generate_homoglyph_map.py --source <confusables.txt>
"""

from __future__ import annotations

import argparse
import hashlib
import re
import string
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
PKG_DIR = SCRIPTS_DIR.parent
SOURCE_DATA = PKG_DIR / "data" / "confusables.txt"
OUTPUT_MODULE = PKG_DIR / "detectors" / "homoglyph_map.py"

CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"

_ALLOWED_VALUES = set(string.ascii_lowercase + string.digits)
_VERSION_RE = re.compile(r"^#\s*Version:\s*(\S+)", re.MULTILINE)

_GENERATED_BANNER = (
    '"""Generated homoglyph folding map — DO NOT EDIT BY HAND.\n'
    "\n"
    "Regenerate with ``python scripts/generate_homoglyph_map.py``.\n"
    "Source: Unicode UTS #39 confusables data ({source_name}), "
    "Unicode {unicode_version} ({tr39_entries} entries).\n"
    "Plus {extension_count} gap-fill extensions for visually-identical\n"
    "Cyrillic/Greek glyphs absent from TR39 (see the generator's\n"
    "``EXTENSIONS`` constant).\n"
    'Source sha256: {sha256}\n'
    '"""'
    "\n\n"
    "from __future__ import annotations\n\n"
    "HOMOGLYPHS: dict[int, str] = {{\n"
)


def extract_map(text: str) -> dict[int, str]:
    """Extract the ``[a-z0-9]``-targeting single-codepoint confusables."""
    result: dict[int, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.split("#")[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(";")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            continue
        src_tokens, target_tokens = parts[0].split(), parts[1].split()
        if len(src_tokens) != 1 or len(target_tokens) != 1:
            continue
        src = int(src_tokens[0], 16)
        target = int(target_tokens[0], 16)
        if src < 0xA0:
            continue
        folded = chr(target).lower()
        if len(folded) == 1 and folded in _ALLOWED_VALUES:
            result.setdefault(src, folded)
    extracted = dict(sorted(result.items()))
    return extracted


# Visually identical Cyrillic/Greek glyphs that TR39 confusables.txt does NOT
# map to an ASCII Latin target (verified against data/confusables.txt
# 18.0.0 — e.g. к→ĸ/ᴛ/ĸ dead-ends on non-ASCII targets, ё/ї/λ absent).
# TR39 entries always win overrides (e.g. б→6 and σ→o per TR39); these
# additions only fill gaps so hand-map coverage (Smith wave-2, t_5d7e23ce/002)
# is not silently lost when the source is regenerated.
EXTENSIONS: dict[int, str] = {
    0x0432: "b",  # в — looks like B
    0x043A: "k",  # к — looks like k (TR39 target ĸ is non-ASCII)
    0x043C: "m",  # м — looks like m
    0x043D: "h",  # н — looks like h
    0x0442: "t",  # т — looks like t (TR39 target ᴛ is non-ASCII)
    0x043F: "p",  # п — looks like p
    0x044E: "y",  # ю — looks like io/y? folded to y (hand-map WG-2)
    0x0451: "e",  # ё — NFKD → е + diaeresis
    0x0457: "i",  # ї — NFKD → і + diaeresis
    0x03B5: "e",  # ε — looks like e
    0x03BA: "k",  # κ — looks like k (TR39 target ĸ is non-ASCII)
    0x03BC: "m",  # μ — looks like m
    0x03C4: "t",  # τ — looks like t (hand-map)
    0x03C0: "p",  # π — looks like p (hand-map)
    0x03C7: "x",  # χ — looks like x (hand-map)
    0x03B8: "e",  # θ — looks like e (hand-map)
    0x03C9: "w",  # ω — looks like w (hand-map)
}


def merge_with_extensions(base: dict[int, str]) -> dict[int, str]:
    """Add gap-filling extensions; TR39 entries always win."""
    merged = dict(base)
    for cp, value in EXTENSIONS.items():
        merged.setdefault(cp, value)
    return dict(sorted(merged.items()))


def _unicode_version(text: str) -> str:
    match = _VERSION_RE.search(text)
    if not match:
        sys.exit(f"refusing to generate: no '# Version: ...' header in {SOURCE_DATA.name}")
    return match.group(1)


def render_module(map_data: dict[int, str], unicode_version: str, sha256: str) -> str:
    header = _GENERATED_BANNER.format(
        source_name=SOURCE_DATA.name,
        unicode_version=unicode_version,
        sha256=sha256,
        tr39_entries=len(map_data) - len(EXTENSIONS),
        extension_count=len(EXTENSIONS),
    )
    chunk: list[str] = [header]
    for i in range(0, len(map_data), 6):  # 6 keeps 5-digit cp lines ≤ ruff 100
        items = list(map_data.items())[i : i + 6]
        chunk.append(
            "    " + " ".join(f"0x{cp:04X}: {val!r}," for cp, val in items) + "\n"
        )
    chunk.append("}\n")
    return "".join(chunk)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--source",
        type=Path,
        default=SOURCE_DATA,
        help=f"confusables.txt to read (default: vendored {SOURCE_DATA.relative_to(PKG_DIR)})",
    )
    args = parser.parse_args(argv)

    source = args.source or SOURCE_DATA
    text = source.read_text(encoding="utf-8")
    unicode_version = _unicode_version(text)
    sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    base = extract_map(text)
    map_data = merge_with_extensions(base)
    OUTPUT_MODULE.write_text(render_module(map_data, unicode_version, sha256), encoding="utf-8")
    print(
        f"wrote {OUTPUT_MODULE.relative_to(PKG_DIR)}: "
        f"{len(base)} TR39 entries + {len(EXTENSIONS)} extensions = {len(map_data)} "
        f"(Unicode {unicode_version}, sha256 {sha256[:12]}…)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
