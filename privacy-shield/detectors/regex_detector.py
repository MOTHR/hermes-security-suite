"""Regex-based PII Detection — Phase 1, Tier 1 + Phase 2 Name Detection.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 5.4

Patterns:
- Email (RFC 5322 simplified)
- Phone (DE + international)
- IP Address (v4 + v6)
- IBAN (DE + EU)
- Tax ID (DE: 11 digits)
- Address (PLZ + city, heuristic)
- Passport Number (DE: 8-11 digits, context-disambiguated from tax_id)
- VAT ID (DE + EU)
- BIC (ISO 9362)
- Credit Card (Luhn-validated)
- Cookie-ID / Session-Token
- Name (two capitalized words, stop-word filtered)

Performance target: ≤3ms per scan (Spec Section 6).
"""

from __future__ import annotations

import html
import re
import unicodedata
import urllib.parse
from typing import Any

from .dataclasses import PIIMatch
from .name_detector import _NAME_RE, is_person_name
from .context_leak_detector import detect_context_leaks
from .extended_patterns import (
    BASE_EXTENDED_PATTERNS,
    CompiledPattern,
    _BTC_RE,
    _JWT_RE,
    is_seed_phrase,
    has_passport_context,
    _VAT_EU_COUNTRIES,
    _VAT_EU_RE,
)

# ``PIIMatch`` is defined in ``detectors.dataclasses`` (MORPH-PS-4 lift) and
# re-exported here for backward compatibility with the test suite and any
# external caller that imports ``from privacy_shield.detectors.regex_detector
# import PIIMatch``.


# ── Pattern / scan tuning constants ─────────────────────────────────────

# RFC 5322 local-part and domain length limits used by the linear email
# pre-filter to bound the candidate window (FIX-1E ReDoS hardening).
_EMAIL_LOCAL_PART_MAX_LEN: int = 64
_EMAIL_DOMAIN_PART_MAX_LEN: int = 255

# Context-window radius for passport-number disambiguation.
_PASSPORT_CONTEXT_WINDOW: int = 50

# Minimum length of a base64 token that may encode PII.
_BASE64_MIN_TOKEN_LEN: int = 20

# Credit-card digit-length range accepted by the Luhn validator.
_CREDIT_CARD_MIN_DIGITS: int = 13
_CREDIT_CARD_MAX_DIGITS: int = 19

# Modulus used by the Luhn checksum.
_LUHN_MODULUS: int = 10

# IBAN alphanumeric body length range (after country + check digits) for
# whitespace-tolerant candidate detection.
_IBAN_BODY_MIN_LEN: int = 11
_IBAN_BODY_MAX_LEN: int = 30

# Truncation limit for long match values in the audit trail.
_VALUE_TRUNCATION_LEN: int = 80

# Minimum number of non-empty lines for an indented block to be treated
# as a code region.
_CODE_INDENTED_MIN_LINES: int = 2


# ── Unicode normalization helpers ───────────────────────────────────────


_INVISIBLE_CHARS_RE = re.compile(
    r'[\u200b-\u200f\u2028-\u202f\u2060-\u206f\ufeff]'
)

# FIX-1E: expanded homoglyph table.
# NFKC folds the vast majority of look-alikes (fullwidth, mathematical alphanumerics,
# circled letters), but a curated set of Cyrillic / Greek / Latin Extended-A / Latin
# Extended-B glyphs renders identically to ASCII in most fonts and is NOT folded by
# NFKC.  The table below is generated programmatically at import time from a
# glyph → ASCII lookup (kept inline so the rules are easy to audit).
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic (lowercase) — visually identical to Latin counterparts
    '\u0430': 'a',  # а
    '\u0435': 'e',  # е
    '\u043e': 'o',  # о
    '\u0440': 'p',  # р
    '\u0441': 'c',  # с
    '\u0443': 'y',  # у (rendition ambiguous — Cyrillic У vs Latin Y; treat as Y)
    '\u0445': 'x',  # х
    '\u0456': 'i',  # і (Ukrainian)
    '\u0458': 'j',  # ј (Serbian)
    '\u04bb': 'h',  # һ (Bashkir/Tatar)
    '\u0501': 'd',  # ԁ (Cyrillic)
    # Cyrillic (uppercase) — limited to ones that share Latin glyph
    '\u0410': 'A',  # А
    '\u0412': 'B',  # В
    '\u0415': 'E',  # Е
    '\u041a': 'K',  # К
    '\u041c': 'M',  # М
    '\u041d': 'H',  # Н
    '\u041e': 'O',  # О
    '\u0420': 'P',  # Р
    '\u0421': 'C',  # С
    '\u0422': 'T',  # Т
    '\u0425': 'X',  # Х
    # Greek (lowercase)
    '\u03b1': 'a',  # α
    '\u03b5': 'e',  # ε
    '\u03bf': 'o',  # ο
    '\u03c1': 'p',  # ρ
    '\u03c2': 'c',  # ς (final sigma)
    '\u03c5': 'y',  # υ
    '\u03c7': 'x',  # χ
    '\u03b9': 'i',  # ι
    '\u03ba': 'k',  # κ
    '\u03bd': 'v',  # ν
    '\u03c0': 'n',  # π (visual approximation; risky in math context, applied selectively)
    # Latin look-alikes not folded by NFKC
    '\u0131': 'i',  # ı (dotless i)
    '\u0237': 'j',  # ȷ (dotless j)
    '\u1d00': 'a',  # ᴀ (small capital A)
    '\u0181': 'B',  # Ɓ (hooked B)
    '\u018a': 'D',  # Ɗ (hooked D)
    # Symbol confusables used as @ or . in obfuscation payloads
    '\uff20': '@',  # ＠ (fullwidth at sign)
    '\u0040': '@',  # @ (already ASCII but listed for clarity)
    '\uff0e': '.',  # ． (fullwidth full stop)
    # Mathematical monospace / bold Latin — NFKC SHOULD fold these; the explicit
    # entries act as a safety net for the rare case where a provider strips
    # the NFKC marker from the upstream prompt.
}


def _build_fullwidth_homoglyphs() -> dict[str, str]:
    """Return a dict mapping every fullwidth Latin letter to its ASCII equivalent.

    Fullwidth letters (U+FF21..U+FF3A uppercase, U+FF41..U+FF5A lowercase) are
    visually identical to ASCII at typical font sizes.  NFKC folds them, but
    we expose this map so ``normalize_text`` can re-apply the substitution
    after the NFKC step on its own (handy when upstream code strips
    compatibility-decomposition markers before reaching us).
    """
    table: dict[str, str] = {}
    for offset in range(0xFF21 - 0x41, 0xFF3A - 0x41 + 1):
        full = chr(0xFF21 + offset)
        ascii_upper = chr(0x41 + offset)
        table[full] = ascii_upper
    for offset in range(0xFF41 - 0x61, 0xFF5A - 0x61 + 1):
        full = chr(0xFF41 + offset)
        ascii_lower = chr(0x61 + offset)
        table[full] = ascii_lower
    return table


_FULLWIDTH_MAP: dict[str, str] = _build_fullwidth_homoglyphs()


def normalize_text(text: str) -> str:
    """Normalize text before PII detection.

    Steps:
      1. Strip invisible / zero-width characters.
      2. NFKC compatibility decomposition (catches many look-alikes).
      3. Replace fullwidth Latin letters (safety net for stripped NFKC).
      4. Replace a curated set of Cyrillic / Greek / Latin-Extended homoglyphs
         with ASCII.
      5. Decode HTML entities and URL percent-encoding (e.g. ``&#64;`` → ``@``).
      6. Replace common email-obfuscation spellings like ``[at]`` / ``[dot]``.
      7. Conservative leet normalization: ``0/o``, ``1/l/i``, ``3/e``, ``4/a``,
         ``5/s``, ``7/t``, ``8/b``, ``9/g``, ``$ → s`` — applied only to
         ``[at]``-style fragments (the ``@`` placeholder) so that we don't
         rewrite digits inside legitimate phone numbers, prices, or hex
         constants (FIX-1E FP tuning).
      8. Collapse whitespace around ``@`` and ``.``.
    """
    text = _INVISIBLE_CHARS_RE.sub('', text)
    text = unicodedata.normalize('NFKC', text)
    for homoglyph, ascii_char in _FULLWIDTH_MAP.items():
        text = text.replace(homoglyph, ascii_char)
    for homoglyph, ascii_char in _HOMOGLYPHS.items():
        text = text.replace(homoglyph, ascii_char)
    # Decode HTML entities and URL percent-encoding (must happen AFTER NFKC).
    text = html.unescape(text)
    text = urllib.parse.unquote(text)
    # Common obfuscations used to bypass simple email regexes.
    text = text.replace('[at]', '@').replace('(at)', '@')
    text = text.replace('[dot]', '.').replace('(dot)', '.')
    text = text.replace(' at ', '@').replace(' dot ', '.')
    # Collapse whitespace around the reconstructed @ and . so "max @ example . com"
    # becomes "max@example.com" and matches the email regex.
    text = re.sub(r'\s*@\s*', '@', text)
    text = re.sub(r'\s\.\s', '.', text)
    # FIX-1E: leet substitution INSIDE the reconstructed email fragments only.
    # We restrict the substitution to runs that sit immediately before an ``@``,
    # i.e. the local-part of an email or the user portion of a handle.  Runs
    # before ``.`` are left alone because that range covers IP addresses,
    # version numbers, prices, GPS coordinates, etc. — applying leet there
    # would destroy legitimate numeric structure.  Without this guard,
    # ``d1rk@ex4mpl3.com`` would still match the email regex (digits are
    # valid local-part chars), but tests like ``d!rk@exampl3.com``
    # (``! → i``) and ``$uper@host.co`` (``$ → s``) would leak through a
    # strictly-ASCII regex.
    text = re.sub(
        r'(?<![A-Za-z0-9])([A-Za-z0-9$!]+)(?=@)',
        lambda m: ''.join(_LEET_MAP.get(ch, ch) for ch in m.group(1)),
        text,
    )
    return text


# ── Span-tracking normalization (t_025240da offset-drift root cause) ──────
#
# normalize_text is NOT length-preserving: html.unescape, percent-decoding,
# whitespace collapse and the obfuscation rewrites all shrink the string.
# Matches found in normalized space therefore have offsets that are wrong
# for the RAW prompt the pseudonymizer mutates.  normalize_text_with_map
# reproduces normalize_text exactly (validated by _assert_map_matches below)
# while carrying, for every output character, the (orig_start, orig_end)
# span it was produced from — so match offsets can be re-anchored to the
# raw text before replacement.

# Mirrors CPython's html.unescape character-reference scan so the emulation
# consumes exactly the same source spans as the real implementation.
_CHARREF_RE: "re.Pattern[str]" = re.compile(
    r'&(#[0-9]{1,7};?|#[xX][0-9a-fA-F]+;?|[a-zA-Z][a-zA-Z0-9]{1,31};?)'
)

# Maximal run of percent-escapes (urllib.parse.unquote decodes the maximal
# %-run as UTF-8 together; trailing lone '%' is left in place by CPython).
_PERCENT_RUN_RE: "re.Pattern[str]" = re.compile(
    r'%(?:[0-9a-fA-F]{2})+(?:%[0-9a-fA-F]{2})*%?'
)

_OBFUSCATION_PAIRS: tuple[tuple[str, str], ...] = (
    (' at ', '@'),
    (' dot ', '.'),
)

_WS_AT_RE = re.compile(r'\s*@\s*')
_WS_DOT_RE = re.compile(r'\s\.\s')
_LEET_RUN_RE = re.compile(r'(?<![A-Za-z0-9])([A-Za-z0-9$!]+)(?=@)')


def _html_unescape_match(m: "re.Match[str]") -> str:
    repl = getattr(html, "_replace_charref", None)
    if repl is not None:
        return repl(m)  # type: ignore[no-any-return]
    return html.unescape(m.group(0))


def normalize_text_with_map(
    text: str,
) -> tuple[str, list[tuple[int, int]]]:
    """Length-tracking variant of :func:`normalize_text`.

    Returns ``(normalized_text, spans)`` where ``normalized_text`` is
    byte-identical to ``normalize_text(text)`` and ``spans[i]`` is the
    ``(orig_start, orig_end)`` span in *text* that normalized character
    ``i`` was produced from.

    Implementation: characters are carried as ``(char, span)`` units and
    every normalization step rewrites that list.  ``html.unescape`` and
    ``urllib.parse.unquote`` operate on whole-string CPython internals, so
    their steps are emulated per-match (substitution tables are identical)
    and the caller-visible equality against ``normalize_text`` is checked
    in :func:`spans_for_text` — a divergence falls back to legacy offsets
    there instead of producing mis-anchored replacements.
    """
    units: list[tuple[str, tuple[int, int]]] = [
        (ch, (i, i + 1)) for i, ch in enumerate(text)
    ]

    def _apply_regex(
        us: list[tuple[str, tuple[int, int]]],
        pattern: "re.Pattern[str]",
        repl_fn: Any,
    ) -> list[tuple[str, tuple[int, int]]]:
        joined = ''.join(c for c, _s in us)
        out: list[tuple[str, tuple[int, int]]] = []
        pos = 0
        for m in pattern.finditer(joined):
            for k in range(pos, m.start()):
                out.append(us[k])
            consumed = us[m.start():m.end()]
            span = (consumed[0][1][0], consumed[-1][1][1])
            for rch in repl_fn(m):
                out.append((rch, span))
            pos = m.end()
        out.extend(us[pos:])
        return out

    # 1. Strip invisible / zero-width characters (pure deletions).
    units = [(c, s) for c, s in units if not _INVISIBLE_CHARS_RE.match(c)]
    # 2. NFKC per character (expands 1..k chars, all map to one orig span).
    decomposed: list[tuple[str, tuple[int, int]]] = []
    for ch, span in units:
        for dch in unicodedata.normalize('NFKC', ch):
            decomposed.append((dch, span))
    units = [(_FULLWIDTH_MAP.get(c, c), s) for c, s in decomposed]
    units = [(_HOMOGLYPHS.get(c, c), s) for c, s in units]
    # 5. Decode HTML entities / percent-escapes (must happen AFTER NFKC).
    units = _apply_regex(
        units, _CHARREF_RE, lambda m: _html_unescape_match(m)
    )
    units = _apply_regex(
        units, _PERCENT_RUN_RE, lambda m: urllib.parse.unquote(m.group(0))
    )
    # 6. Email-obfuscation spellings (plain str.replace semantics).
    for _old, _new in _OBFUSCATION_PAIRS:
        units = _apply_regex(
            units, re.compile(re.escape(_old)), lambda m, _n=_new: _n
        )
    units = _apply_regex(
        units, re.compile(r'\[at\]'), lambda m: '@'
    )
    units = _apply_regex(
        units, re.compile(r'\(at\)'), lambda m: '@'
    )
    units = _apply_regex(
        units, re.compile(r'\[dot\]'), lambda m: '.'
    )
    units = _apply_regex(
        units, re.compile(r'\(dot\)'), lambda m: '.'
    )
    # 7. Collapse whitespace around the reconstructed @ and .
    units = _apply_regex(units, _WS_AT_RE, lambda m: '@')
    units = _apply_regex(units, _WS_DOT_RE, lambda m: '.')
    # 8. Leet normalization inside reconstructed email fragments (1:1).
    units = _apply_regex(
        units, _LEET_RUN_RE,
        lambda m: ''.join(_LEET_MAP.get(ch, ch) for ch in m.group(1)),
    )
    joined = ''.join(c for c, _s in units)
    return joined, [s for _c, s in units]


def reanchor_match_offsets(
    matches: list[PIIMatch],
    spans: "list[tuple[int, int]] | None",
    raw_len: int,
) -> list[PIIMatch]:
    """Map matches from normalized-space offsets onto raw-text spans.

    ``spans`` comes from :func:`normalize_text_with_map`; each match
    ``(start, end)`` is rewritten as ``(spans[start][0], spans[end-1][1])``.
    ``spans=None`` is the identity mapping (normalization left the text
    unchanged, so normalized offsets already point at raw offsets).
    A whole-text synthetic match (seed phrase) maps to ``(0, raw_len)``.
    Overlapping raw spans (shared collapsed whitespace) are clamped so
    sequential replacement never corrupts the raw text.
    """
    reanchored: list[PIIMatch] = []
    for m in matches:
        if spans is None:
            raw_start, raw_end = m.start, m.end
        elif m.start == 0 and m.end >= len(spans):
            raw_start, raw_end = 0, raw_len
        else:
            raw_start = spans[m.start][0]
            raw_end = spans[m.end - 1][1]
        if reanchored and raw_start < reanchored[-1].end:
            raw_start = reanchored[-1].end
        raw_end = max(raw_end, raw_start + 1)
        reanchored.append(PIIMatch(
            type=m.type,
            value=m.value,
            start=raw_start,
            end=raw_end,
            confidence=m.confidence,
            rule=m.rule,
        ))
    return reanchored


# FIX-1E: conservative leet map.  Single-character entries map a digit/symbol
# to the letter most likely to be substituted in evasion payloads.  Anything
# not in the map is returned unchanged so the substitution is strictly
# opt-in per character.
_LEET_MAP: dict[str, str] = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '9': 'g', '$': 's', '!': 'i',
}


def leet_normalize_fragment(fragment: str) -> str:
    """Public helper: leet-normalize a single fragment.

    Used by the Base64-encoded PII detector (FIX-1E) so it can decode a
    base64 string, then run leet normalization over the decoded bytes before
    handing the result to the regular detector pipeline.  Splitting this out
    keeps the ``normalize_text`` contract simple (it operates on a whole
    string) while letting nested detectors reuse the same map.
    """
    return ''.join(_LEET_MAP.get(ch, ch) for ch in fragment)


# ── Code-context detection (FIX-1E FP tuning) ────────────────────────────

# Markdown fenced code blocks (``` ``` or ~~~ ~~~).  We look for the opening
# fence, capture the language tag if present, and accept everything until the
# next fence at column 0 with the same character.
_CODE_FENCE_OPEN = re.compile(
    r'(?m)^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})[^\n]*\n',
)
_CODE_FENCE_CLOSE = re.compile(r'(?m)^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})[ \t]*$')

# Indented block heuristic: 4+ leading spaces OR a leading tab on a contiguous
# region.  Used as a fallback for plain-text code pastes that lack fences.
_INDENTED_BLOCK_LINE = re.compile(r'(?m)^(?:    |\t).+$')

# t_025240da P0-2: HTML-mail guard (T4 leak fix).
#
# Root cause (t_815fd79d LIVE-TEST): email HTML bodies are tab-indented
# template markup.  ``_detect_code_regions`` treats every tab-indented line
# as code, so the recipient address inside ``<a href="mailto:...">`` got the
# 0.6 ``code_context_penalty`` and fell below the masking threshold — the
# raw PII passed to the provider.
#
# Fix per fix-spec ("code_context_penalty in HTML-Kontext deaktivieren"):
# when the text is recognisably an HTML *document* (never the case for the
# code-snippet use case the penalty exists for), code-region detection is
# skipped entirely.  Match offsets still refer to the original prompt, so
# the pseudonymiser needs no re-mapping, and no new dependency (e.g.
# html2text) is introduced.
_HTML_DOC_MARKER = re.compile(r'(?is)<\s*(?:!doctype\s+html|html[\s>])')
_HTML_TAG_RE = re.compile(
    r'(?is)</?(?:td|tr|table|div|span|p|img|a|body|head|meta|font|style)\b'
)
_HTML_TAG_MIN_COUNT: int = 15


def _looks_like_html_document(text: str) -> bool:
    """Return True when *text* is recognisably an HTML document, not prose."""
    if _HTML_DOC_MARKER.search(text):
        return True
    return len(_HTML_TAG_RE.findall(text)) >= _HTML_TAG_MIN_COUNT


def _detect_code_regions(text: str) -> list[tuple[int, int]]:
    """Return a list of ``(start, end)`` character offsets that fall inside
    a code context (markdown fenced block or indented block).

    The detector uses a simple heuristic: prefer fenced blocks because they
    are explicit, then fall back to contiguous indented-line runs.  Plain
    text without markers is treated as prose.  Lines that look like
    ``key = value`` with a quoted PII literal are *not* included here; the
    penalty is applied per-match through ``_apply_code_penalty`` instead of
    by region.
    """
    regions: list[tuple[int, int]] = []
    cursor = 0
    while True:
        m = _CODE_FENCE_OPEN.search(text, cursor)
        if not m:
            break
        fence_char = m.group("fence")[0]
        fence_len = len(m.group("fence"))
        start = m.start()
        scan = m.end()
        close = None
        for candidate in _CODE_FENCE_CLOSE.finditer(text, scan):
            cand_fence = candidate.group("fence")
            if (
                cand_fence[0] == fence_char
                and len(cand_fence) >= fence_len
                and not cand_fence.rstrip(fence_char)[1:].strip()
            ):
                close = candidate
                break
        if close is None:
            # Unterminated fence: treat everything to end of text as code.
            regions.append((start, len(text)))
            break
        regions.append((start, close.end()))
        cursor = close.end()

    # Indented blocks: collect runs of indented lines ≥ 4 chars.
    in_block = False
    block_start = 0
    for line_match in re.finditer(r'(?m)^(.+\n?)', text):
        line = line_match.group(1).rstrip("\n")
        is_indented = bool(line and (line.startswith("    ") or line.startswith("\t")))
        if is_indented and not in_block:
            in_block = True
            block_start = line_match.start()
        elif not is_indented and in_block:
            in_block = False
            # Only count blocks of ≥ _CODE_INDENTED_MIN_LINES indented lines (filter accidental indents)
            block_text = text[block_start:line_match.start()]
            if sum(1 for ln in block_text.splitlines() if ln.strip()) >= _CODE_INDENTED_MIN_LINES:
                regions.append((block_start, line_match.start()))
    if in_block:
        block_text = text[block_start:]
        if sum(1 for ln in block_text.splitlines() if ln.strip()) >= _CODE_INDENTED_MIN_LINES:
            regions.append((block_start, len(text)))

    # Sort and merge overlapping regions.
    regions.sort()
    merged: list[tuple[int, int]] = []
    for start, end in regions:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _apply_code_penalty(
    matches: list[PIIMatch],
    code_regions: list[tuple[int, int]],
    penalty: float,
) -> list[PIIMatch]:
    """Return a new list of matches with confidence multiplied by ``penalty``
    if the match's span falls inside any code region.

    Typed credentials (api_key, jwt, stripe_live_key, etc.) are *not*
    down-scored here — they remain at full confidence so a real secret
    pasted inside a code block is still masked.  Only the FP-prone types
    (email, phone, iban, address, name, credit_card) absorb the penalty.
    """
    if not code_regions or penalty >= 1.0:
        return matches
    PENALIZED_TYPES = frozenset({
        # The core FP-prone types the hardening report flagged.
        "email", "phone", "iban", "address_de", "name", "credit_card",
        "vat_id_de", "vat_id_eu", "tax_id_de", "passport_number",
        "bip39_seed_phrase",
        # Typed credentials that are ALSO commonly FP-prone inside code
        # blocks (UUIDs look like heroku_api_key, IPs look like IP
        # addresses).  These are kept typed (the rule stays informative)
        # but the penalty drops them below the threshold so example
        # values stay un-masked.  Operators that want stricter behaviour
        # can set ``code_context_penalty = 1.0`` in their config.
        "ip_address",
    })
    adjusted: list[PIIMatch] = []
    for m in matches:
        in_code = any(rs <= m.start and m.end <= re_ for rs, re_ in code_regions)
        if in_code and m.type in PENALIZED_TYPES:
            new_conf = max(0.0, min(1.0, m.confidence * penalty))
            adjusted.append(PIIMatch(
                type=m.type,
                value=m.value,
                start=m.start,
                end=m.end,
                confidence=new_conf,
                rule=m.rule + "+code_context",
            ))
        else:
            adjusted.append(m)
    return adjusted


# ── Pattern Definitions ──────────────────────────────────────────────────

# Email: RFC 5322 simplified — local@domain.tld
# ReDoS-hardened: coarse linear pre-filter + exact non-backtracking final
# pattern. The old `_EMAIL_RE` has been removed so no code path can use it.

# Characters permitted in the local (before @) and domain (after @) parts
# used by the linear pre-filter to extract a bounded candidate window.
_EMAIL_LOCAL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-"
)
_EMAIL_DOMAIN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
)

# Final pattern: no nested `+`/`*` quantifiers on dot classes, anchored to
# the full candidate so catastrophic backtracking is impossible.
_EMAIL_FINAL = re.compile(
    r'''
    [a-zA-Z0-9._+%\-]+  # local part (plus-addressing, percent, dots, hyphens allowed)
    @
    [a-zA-Z0-9](?:[a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?  # domain
    \.[a-zA-Z]{2,24}  # TLD
    ''',
    re.VERBOSE | re.ASCII,
)


def _scan_emails(text: str) -> list[PIIMatch]:
    """Find emails in text without catastrophic backtracking.

    Uses a linear scan for '@' symbols, expands a bounded candidate window
    using a fixed set of allowed characters, then validates the candidate
    with a strict non-backtracking regex.
    """
    matches: list[PIIMatch] = []
    if "@" not in text:
        return matches

    n = len(text)
    local_ok = _EMAIL_LOCAL_CHARS
    domain_ok = _EMAIL_DOMAIN_CHARS
    final = _EMAIL_FINAL

    for at in range(1, n - 1):
        if text[at] != "@":
            continue
        # Expand left up to _EMAIL_LOCAL_PART_MAX_LEN chars over allowed local-part characters.
        left = at
        limit = max(0, at - _EMAIL_LOCAL_PART_MAX_LEN)
        while left > limit and text[left - 1] in local_ok:
            left -= 1
        # Expand right up to _EMAIL_DOMAIN_PART_MAX_LEN chars over allowed domain characters.
        right = at
        limit = min(n - 1, at + _EMAIL_DOMAIN_PART_MAX_LEN)
        while right < limit and text[right + 1] in domain_ok:
            right += 1
        # Trim a trailing dot/hyphen so "max@example.com." does not prevent a
        # match; word-boundary handling is implicit because we stop at the first
        # non-domain character.
        while right > at and text[right] in ".-":
            right -= 1
        candidate = text[left:right + 1]
        if not final.fullmatch(candidate):
            continue
        matches.append(PIIMatch(
            type="email",
            value=candidate,
            start=left,
            end=right + 1,
            confidence=1.0,
            rule="regex:email",
        ))
    return matches

# Phone: DE formats + international. FP-hardened 2026-09-20: the old single
# regex tokenized "20260920" inside vault file paths as a phone. One STRICT
# structured pattern with boundary anchors + structural validator lives in
# detectors/regex_phone.py and is imported here so the legacy
# RegexPIIDetector scans with the same logic.
from .regex_phone import (
    PhoneDetector,
    _PHONE_SEP_RE,
    _sep_valid,
    is_date_time_false_positive,
)

# IP v4: 0-255.0-255.0-255.0-255
_IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# IP v6: simplified (full + compressed forms)
# Note: \b doesn't work with colons (non-word chars), use lookahead/lookbehind
_IPV6_RE = re.compile(
    r'(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|'  # full
    r'(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?![0-9a-fA-F:])|'                # compressed end
    r'(?<![0-9a-fA-F:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|'  # compressed start
    r'(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])|'    # compressed middle
    r'(?<![0-9a-fA-F:])::[0-9a-fA-F]{1,4}(?![0-9a-fA-F:])'                               # loopback ::1
)

# IBAN: DE + EU (2-letter country + 2 check digits + up to 30 alphanumeric)
_IBAN_RE = re.compile(
    r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'
)

# German Tax ID (Steuer-ID): 11 digits, often formatted as 2-3-3-3 groups
# Format: 12 345 678 901 or 12345678901
# Must be exactly 11 digits (not part of a longer number)
_TAX_ID_DE_RE = re.compile(
    r'(?<!\d)\d{2}[\s]?\d{3}[\s]?\d{3}[\s]?\d{3}(?!\d)|'  # formatted
    r'(?<!\d)\d{11}(?!\d)'                                    # unformatted
)

# Address: German PLZ (5 digits) + city name (heuristic)
# Matches: "12345 Berlin", "12345 Berlin-Mitte", etc.
_ADDRESS_DE_RE = re.compile(
    r'\b\d{5}\s+[A-ZÄÖÜ][a-zäöüß]+(?:[\s\-/][A-ZÄÖÜ][a-zäöüß]+)*\b'
)

# Passport/Ausweisnummer (DE): 8-11 digits, optionally with leading uppercase letter
# Disambiguation via context keywords required (conflict with tax_id at 11 digits)
_PASSPORT_DE_RE = re.compile(r'\b[A-Z]?\d{8,11}\b')

# Passport context keywords (case-insensitive, within 50 chars)
_PASSPORT_KEYWORDS_RE = re.compile(r'Reisepass|Pass(?!\w)|Ausweis', re.IGNORECASE)

# VAT ID (DE): DE + 9 digits
_VAT_DE_RE = re.compile(r'\bDE\d{9}\b')

# VAT ID (EU extension): 2-letter country code + 9-12 alphanumeric chars
# Min 9 after country code to exclude DE12345678 (8 digits = too short)
# Country code whitelist: EU/EEA VAT prefixes
_VAT_EU_COUNTRIES = frozenset({
    'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'EL', 'ES',
    'FI', 'FR', 'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV', 'MT',
    'NL', 'PL', 'PT', 'RO', 'SE', 'SI', 'SK',
})
_VAT_EU_RE = re.compile(r'\b[A-Z]{2}[A-Z0-9]{9,12}\b')

# Cookie-ID / Session-Token pattern moved to detectors/extended_patterns.py
# (BASE_EXTENDED_PATTERNS entry) so the compiled pattern can carry
# confidence=0.5 metadata; the detector imports it via the CompiledPattern list.


# ── IBAN Validation (ISO 13616 mod-97) ──────────────────────────────────

def _mod97_check(iban: str) -> bool:
    """Validate IBAN checksum using ISO 13616 mod-97 algorithm.

    Algorithm:
    1. Move first 4 chars to end
    2. Convert letters to numbers (A=10, B=11, ..., Z=35)
    3. Compute integer mod 97 — valid IBANs yield remainder 1
    """
    # Normalize: strip whitespace, uppercase
    iban = iban.replace(' ', '').upper()

    # Move first 4 characters to the end
    rearranged = iban[4:] + iban[:4]

    # Convert letters to numbers
    digits = []
    for ch in rearranged:
        if 'A' <= ch <= 'Z':
            digits.append(str(ord(ch) - 55))
        else:
            digits.append(ch)

    # Compute mod 97 on the large integer
    num_str = ''.join(digits)
    remainder = 0
    for i in range(0, len(num_str), 9):
        # Process in chunks of 9 digits to avoid overflow
        chunk = num_str[i:i + 9]
        remainder = (remainder * (10 ** len(chunk)) + int(chunk)) % 97

    return remainder == 1

# BIC (Business Identifier Code): ISO 9362
# Format: 4-letter bank code + 2-letter country + 2 alphanumeric location
#         + optional 3-character branch code
_BIC_RE = re.compile(
    r'\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b'
)

# Credit Card: 13-19 digits, optionally grouped with spaces or dashes.
# ReDoS-hardened: rough non-backtracking pre-filter, exact non-backtracking
# final pattern, then Luhn validation.  The old `_CC_RE` / `_CC_CANDIDATE_RE`
# patterns have been removed entirely so no code path can use them anymore.
_CC_PRE = re.compile(r'\b\d[\d -]{11,34}\d\b')  # coarse candidate filter; ends on digit
# Final grouping: standard credit-card shapes (4-4-4-4, 4-6-5 Amex, %d-%d digits).
# We use `fullmatch` later, so no anchors are needed here.
_CC_FINAL = re.compile(
    r'(?:\d{4}[ -]?){3}\d{1,4}|\d{4}[ -]\d{6}[ -]\d{5}|\d{%d,%d}'
    % (_CREDIT_CARD_MIN_DIGITS, _CREDIT_CARD_MAX_DIGITS)
)


def _is_credit_card(text: str) -> bool:
    """Validate candidate string as a Luhn-valid credit card number.

    Steps:
      1. Strip non-digits.
      2. Require %d-%d digits.
      3. Run the Luhn (modulo-%d) check.
    """ % (
        _CREDIT_CARD_MIN_DIGITS,
        _CREDIT_CARD_MAX_DIGITS,
        _LUHN_MODULUS,
    )
    digits = re.sub(r'\D', '', text)
    if not _CREDIT_CARD_MIN_DIGITS <= len(digits) <= _CREDIT_CARD_MAX_DIGITS:
        return False
    return _luhn_check(digits)


def _luhn_check(digits: str) -> bool:
    """Validate a digit string using the Luhn (modulo-%d) algorithm.

    Returns True if the checksum is valid.
    """ % _LUHN_MODULUS
    total = 0
    reverse_digits = digits[::-1]
    for i, ch in enumerate(reverse_digits):
        d = int(ch)
        if i % 2 == 1:  # every second digit from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % _LUHN_MODULUS == 0


def _passport_context_check(text: str, start: int, end: int, window: int = _PASSPORT_CONTEXT_WINDOW) -> bool:
    """Check if passport keywords exist within `window` chars of the match."""
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    context = text[ctx_start:ctx_end]
    return bool(_PASSPORT_KEYWORDS_RE.search(context))


# Whitespace-tolerant BTC: many obfuscation guides suggest inserting spaces
# between address characters. We collapse whitespace inside a BTC-shaped
# candidate and validate it against the strict regex.
_BTC_SPACED_CANDIDATE_RE = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9\s]{8,87}|[13][a-km-zA-HJ-NP-Z1-9\s]{25,34})\b",
    re.IGNORECASE,
)


def _scan_spaced_btc(text: str) -> list[PIIMatch]:
    """Find BTC addresses that have internal whitespace obfuscation."""
    matches: list[PIIMatch] = []
    for m in _BTC_SPACED_CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        collapsed = re.sub(r"\s+", "", candidate)
        if _BTC_RE.fullmatch(collapsed):
            matches.append(PIIMatch(
                type="crypto_btc",
                value=candidate,
                start=m.start(),
                end=m.end(),
                confidence=1.0,
                rule="regex:crypto_btc_spaced",
            ))
    return matches


# Whitespace-tolerant IBAN: spaced IBANs (e.g. "DE89 3704 0044 0532 0130 00")
# must not be misclassified as phone numbers. We find candidates, collapse
# whitespace, and run the ISO 13616 mod-97 check.
_IBAN_SPACED_CANDIDATE_RE = re.compile(
    r"\b[A-Z]{2}\d{2}(?:\s*[A-Z0-9]){%d,%d}\b"
    % (_IBAN_BODY_MIN_LEN, _IBAN_BODY_MAX_LEN),
    re.IGNORECASE,
)


def _scan_spaced_iban(text: str) -> list[PIIMatch]:
    """Find IBANs that contain internal whitespace."""
    matches: list[PIIMatch] = []
    for m in _IBAN_SPACED_CANDIDATE_RE.finditer(text):
        candidate = m.group(0)
        collapsed = re.sub(r"\s+", "", candidate).upper()
        if _IBAN_RE.fullmatch(collapsed) and _mod97_check(collapsed):
            matches.append(PIIMatch(
                type="iban",
                value=candidate,
                start=m.start(),
                end=m.end(),
                confidence=1.0,
                rule="regex:iban",
            ))
    return matches


# FIX-1E: Base64-encoded PII detector.
# Adversaries obfuscate email/phone by base64-encoding the plaintext, e.g.
# ``bWF4Lm11c3Rlcm1hbm5lckBleGFtcGxlLmNvbQ==`` decodes to ``max.mustermann@example.com``.  The detector
# finds base64-shaped tokens (≥20 base64 chars with 0–2 padding ``=``), attempts
# a strict base64 decode, runs the recursive detector on the decoded bytes, and
# emits a single PIIMatch for the whole base64 token if at least one inner
# match was found.  Confidence is capped at 0.7 (heuristic), never auto-masked
# without explicit user opt-in, and the inner PIIMatch.rule string includes
# the inner type so the audit trail can correlate.
#
# Excluded from the candidate set:
#   * Tokens that contain a ``.`` (these are usually URLs, JWTs, file paths)
#   * Tokens whose length is not a multiple of 4 after stripping padding
#     (non-canonical base64; decoding would still work but with a much higher
#     false-positive rate on prose like "Lorem ipsum dolor sit amet").
#   * Tokens already detected as JWTs / API keys (handled in the overlap pass).
_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{%d,}={0,2})(?![A-Za-z0-9+/=])" % _BASE64_MIN_TOKEN_LEN)


def _try_base64_decode(token: str) -> str | None:
    """Return the UTF-8 decoded text of a base64 token, or ``None``.

    Strict mode: padding must be valid (0, 1, or 2 ``=``), the total token
    length must be a multiple of 4, the decoded byte length must be at least
    4, and the resulting bytes must be valid UTF-8 (so we don't false-positive
    on raw binary payloads).
    """
    import base64 as _b64

    stripped = token.rstrip("=")
    pad = len(token) - len(stripped)
    if pad > 2 or len(token) % 4 != 0:
        return None
    try:
        decoded = _b64.b64decode(token, validate=True)
    except (ValueError, _b64.binascii.Error):  # type: ignore[attr-defined]
        return None
    if len(decoded) < 4:
        return None
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _scan_base64_pii(
    text: str, detector: "RegexPIIDetector"
) -> list[PIIMatch]:
    """Find base64 tokens whose decoded payload contains PII.

    ``detector`` is the enclosing instance (passed in so we can reuse its
    ``scan`` method recursively — but only on the small decoded fragment, so
    the per-token cost stays bounded).
    """
    matches: list[PIIMatch] = []
    seen_spans: set[tuple[int, int]] = set()
    for m in _BASE64_TOKEN_RE.finditer(text):
        token = m.group(1)
        span = (m.start(1), m.end(1))
        if span in seen_spans:
            continue
        # Skip if the token contains a dot — usually URLs / JWT fragments.
        if "." in token:
            continue
        # Skip if the token's decoded bytes are unlikely to be PII.
        decoded = _try_base64_decode(token)
        if decoded is None:
            continue
        # Recurse on the decoded text via the no-base64 helper so adversarial
        # nesting (base64-of-base64-of-…) terminates after one level.
        inner_matches = detector._scan_no_base64(decoded, original_text=decoded)
        if not inner_matches:
            continue
        # Use the highest inner confidence, capped at 0.7 because the outer
        # match is heuristic (we don't know for sure the base64 token was
        # *intended* as PII — could be a hash, a UUID, etc.).
        inner_max = min(0.7, max(im.confidence for im in inner_matches))
        seen_spans.add(span)
        matches.append(PIIMatch(
            type="encoded_pii",
            value=token,
            start=span[0],
            end=span[1],
            confidence=inner_max,
            rule=f"heuristic:base64_decodes_to_pii[{inner_matches[0].type}]",
        ))
    return matches


class RegexPIIDetector:
    """Phase 4 PII detection using compiled regex patterns.

    Performance target: ≤3ms per scan (Spec Section 6).
    Includes the original 12 base patterns plus 35 extended patterns.
    """

    # Overlap-resolution preferences used by ``_merge_matches``.
    _PREFERRED_OVERLAP_TYPES = frozenset({"jwt", "iban"})
    _TYPED_CREDENTIAL_TYPES = frozenset({
        "jwt",
        "api_key",
        "stripe_live_key",
        "stripe_test_key",
        "stripe_public_key",
        "stripe_restricted_key",
        "stripe_webhook_secret",
        "github_pat",
        "github_fine_grained_pat",
        "google_api_key",
        "google_oauth",
        "github_oauth",
        "azure_sas",
        "database_url",
        "auth_bearer",
        "private_key",
        "telegram_bot_token",
        "discord_webhook",
        "slack_webhook",
        "slack_token",
        "aws_access_key",
        "npm_token",
        "pypi_token",
        "docker_hub_pat",
        "heroku_api_key",
    })

    def __init__(self, code_context_penalty: float = 1.0):
        # Build pattern list in priority order: most specific first.
        # Phase 1 base patterns — deterministic regexes, confidence 1.0.
        base: list[tuple[str, re.Pattern[str]]] = [
            ("ip_address", _IPV4_RE),
            ("ip_address", _IPV6_RE),
            ("iban", _IBAN_RE),
            ("passport_number", _PASSPORT_DE_RE),  # before tax_id for disambiguation
            ("tax_id", _TAX_ID_DE_RE),
            ("vat_id_de", _VAT_DE_RE),
            ("credit_card", _CC_PRE),   # before phone — Luhn-validated, more specific
            ("jwt", _JWT_RE),          # before api_key so header-like tokens are typed correctly
            ("phone", _PHONE_SEP_RE),
            ("address", _ADDRESS_DE_RE),
            ("bic", _BIC_RE),          # ISO 9362; also catches SWIFT codes
        ]
        # Phase 4 extended patterns — cookie_id / health_context / sensitive_context /
        # gps / *_context patterns carry an explicit low confidence in CompiledPattern;
        # the scan loop honours that confidence value when emitting PIIMatch.
        extended: list[tuple[str, re.Pattern[str]]] = [
            (cp.pii_type, cp.pattern) for cp in BASE_EXTENDED_PATTERNS
        ]
        # Pattern → confidence lookup so the scan loop can attach the right value.
        self._pattern_confidence: dict[str, float] = {
            cp.pii_type: cp.confidence for cp in BASE_EXTENDED_PATTERNS
        }
        # Broad fallbacks last. cookie_id was historically a fallback here, but is
        # now declared inside BASE_EXTENDED_PATTERNS with confidence=0.5 — leaving
        # the fallback out avoids a duplicate definition.
        fallbacks: list[tuple[str, re.Pattern[str]]] = [
            ("name", _NAME_RE),         # Phase 2: two capitalized words, stop-word filtered
        ]
        # Compose the active pattern list. ``_patterns_meta`` carries per-pattern
        # confidence so the scan loop can read it without re-doing the lookup.
        self._patterns: list[tuple[str, re.Pattern[str]]] = base + extended + fallbacks
        self._patterns_meta: dict[str, float] = {}
        # FIX-4C: parallel lookup of value_group (which capture group holds the
        # pseudonymized value).  0 = use the whole match (group 0); >0 = use
        # m.group(N) so the label prefix is left in place.
        self._patterns_value_group: dict[str, int] = {
            cp.pii_type: cp.value_group for cp in BASE_EXTENDED_PATTERNS
        }
        for pii_type, _ in self._patterns:
            # Most patterns are 1.0 unless overridden in BASE_EXTENDED_PATTERNS.
            self._patterns_meta[pii_type] = self._pattern_confidence.get(pii_type, 1.0)
        # FIX-1E: code-context penalty.  Multiplier applied to FP-prone
        # patterns (email, phone, iban, …) when the match falls inside a
        # markdown fenced block or an indented code region.  Default 1.0
        # disables the penalty so the legacy behaviour is preserved when no
        # value is supplied.  The plugin constructs the detector with the
        # value from ``PrivacyShieldConfig.code_context_penalty`` (0.6).
        self.code_context_penalty = float(code_context_penalty)

    def scan(self, text: str) -> list[PIIMatch]:
        """Scan text for PII patterns.

        Runs patterns against a Unicode-normalized copy of the text so
        homoglyph and zero-width obfuscations are caught, but reports
        match positions against the original text so replacement is
        applied to the caller's string.

        Returns list of PIIMatch objects, sorted by position.
        Overlapping matches are resolved by taking the longer match.

        FIX-1E: also sweeps for base64-encoded PII (heuristic, confidence
        capped at 0.7).  The recursive ``_scan_no_base64`` call inside the
        base64 decoder stops at depth 1, so adversarial nesting is bounded.
        """
        if not text:
            return []

        # t_025240da: runs detection in normalized space, then re-anchors
        # every match onto caller-visible offsets via the span map.  Without
        # re-anchoring, the pseudonymizer replaces spans in the RAW prompt
        # using normalized offsets and tokens land at wrong positions.
        #
        # Fast path (perf regression on the span-tracking commit): when
        # normalization leaves the text unchanged, normalized-space offsets
        # already ARE caller-visible offsets and the per-character span
        # machinery of normalize_text_with_map can be skipped.  spans=None
        # signals identity mapping to reanchor_match_offsets, which keeps
        # the overlap-clamping semantics of the slow path intact.
        normalized_text = normalize_text(text)
        if normalized_text == text:
            matches = self._scan_text(text)
            return reanchor_match_offsets(matches, None, len(text))

        normalized_text, spans = normalize_text_with_map(text)
        matches = self._scan_text(normalized_text)
        matches = reanchor_match_offsets(matches, spans, len(text))
        return matches

    def _scan_text(self, normalized_text: str) -> list[PIIMatch]:
        """Template-method step: run base64-aware scan, then merge context
        leaks and resolve overlaps for the final public result."""
        matches = self._scan_with_base64(normalized_text, normalized_text)

        # Sort by position, then length descending
        matches.sort(key=lambda x: (x.start, -(x.end - x.start)))

        # Add context-leak detections (low-confidence implicit identifiers)
        context_leaks = detect_context_leaks(normalized_text)
        matches.extend(context_leaks)
        matches.sort(key=lambda x: (x.start, -(x.end - x.start)))

        return self._merge_matches(matches)

    def _scan_with_base64(
        self, normalized_text: str, original_text: str,
    ) -> list[PIIMatch]:
        """Template-method step: standard sweep plus base64 heuristic."""
        matches = self._scan_no_base64(normalized_text, original_text)

        # FIX-1E: heuristic base64 sweep.  Runs AFTER the standard patterns
        # so overlap resolution can drop the base64 match if a more specific
        # JWT / API-key match landed at the same position.
        matches.extend(_scan_base64_pii(normalized_text, self))
        return matches

    def _merge_matches(self, matches: list[PIIMatch]) -> list[PIIMatch]:
        """Remove overlapping matches; longest match wins by default.

        ``jwt`` and ``iban`` prevail over broader catch-all patterns, and
        typed credentials prevail over a ``cookie_id`` fallback starting at
        the same position.
        """
        result: list[PIIMatch] = []
        for m in matches:
            if not result:
                result.append(m)
                continue
            prev = result[-1]
            if m.start >= prev.end:
                result.append(m)
            elif m.type in self._PREFERRED_OVERLAP_TYPES and prev.type not in self._PREFERRED_OVERLAP_TYPES:
                # Prefer specific type even if the broader match is longer.
                result[-1] = m
            elif (
                m.start == prev.start
                and prev.type == "cookie_id"
                and m.type in self._TYPED_CREDENTIAL_TYPES
            ):
                # Both matches start at the same position and the new one is
                # a typed credential: drop the cookie_id fallback in favour
                # of the typed match.
                result[-1] = m
            # Otherwise: longest-match-wins is the default and applies here.
        return result

    def _apply_confidence_partition(
        self,
        matches: list[PIIMatch],
        code_regions: list[tuple[int, int]],
    ) -> list[PIIMatch]:
        """Apply the configured code-context penalty to FP-prone matches."""
        if self.code_context_penalty >= 1.0 or not code_regions:
            return matches
        return _apply_code_penalty(matches, code_regions, self.code_context_penalty)

    def _scan_credit_cards(
        self, normalized_text: str, original_text: str,
    ) -> list[PIIMatch]:
        """Two-stage credit-card detection: coarse filter, exact format, Luhn."""
        matches: list[PIIMatch] = []
        for m in _CC_PRE.finditer(normalized_text):
            candidate = m.group(0)
            if not _CC_FINAL.fullmatch(candidate):
                continue
            if not _is_credit_card(candidate):
                continue
            orig_start = original_text.find(candidate)
            orig_end = orig_start + len(candidate) if orig_start != -1 else -1
            if orig_start == -1:
                try:
                    idx = normalized_text.index(candidate)
                    orig_start = idx
                    orig_end = idx + len(candidate)
                except ValueError:
                    orig_start = m.start()
                    orig_end = m.end()
            matches.append(PIIMatch(
                type="credit_card",
                value=candidate,
                start=orig_start,
                end=orig_end,
                confidence=1.0,
                rule="regex:credit_card",
            ))
        return matches

    def _scan_pattern_block(self, normalized_text: str) -> list[PIIMatch]:
        """Run the generic regex pattern loop (everything except credit_card)."""
        matches: list[PIIMatch] = []
        for pii_type, pattern in self._patterns:
            if pii_type == "credit_card":
                continue
            for m in pattern.finditer(normalized_text):
                # FIX-4C: when a pattern declares value_group=N>0 the value
                # is m.group(N) (label prefix stays in place).  Patterns
                # without an explicit value_group fall back to the whole
                # match (group 0) to preserve legacy behaviour for BIC,
                # credit card, JWT, etc.  Using lastindex would be wrong
                # because BIC, IBAN, etc. have a non-value capture group.
                value_group = self._patterns_value_group.get(pii_type, 0)
                if value_group > 0 and m.lastindex and value_group <= m.lastindex:
                    value = m.group(value_group)
                    value_start = m.start(value_group)
                    value_end = m.end(value_group)
                else:
                    value = m.group(0)
                    value_start = m.start()
                    value_end = m.end()
                # IBAN: apply ISO 13616 mod-97 check, skip invalid
                if pii_type == "iban":
                    if not _mod97_check(value):
                        continue
                # Phone (FP-hardened 2026-09-20): structural validation for
                # separated matches; unseparated patterns are anchored and
                # need no post-check.
                if pii_type == "phone" and pattern is _PHONE_SEP_RE:
                    if not _sep_valid(m):
                        continue
                    if is_date_time_false_positive(normalized_text, m):
                        continue
                # Passport: require context keyword disambiguation
                if pii_type == "passport_number":
                    if not _passport_context_check(normalized_text, m.start(), m.end()):
                        continue
                # VAT EU: validate country code prefix
                if pii_type == "vat_id_eu":
                    if value[:2] not in _VAT_EU_COUNTRIES:
                        continue
                # Führerschein: must not shadow EU VAT IDs like ATU12345678.
                if pii_type == "fuehrerschein_de":
                    prefix = value[:2].upper()
                    rest = value[2:].replace(" ", "").replace("-", "")
                    if prefix in _VAT_EU_COUNTRIES and rest.isdigit():
                        continue
                # Name: apply stop-word filter + first-name whitelist.
                # t_025240da: when a pair is rejected by the stop-word
                # filter, retry (a) the shifted in-match pair ("Kontakt
                # Petra" → "Petra") and (b) the pair that starts at the
                # SECOND word and reaches past the match ("Kontakt Petra
                # Meier" → "Petra Meier") — regex overlap would otherwise
                # swallow the real name.
                if pii_type == "name":
                    is_name, confidence = is_person_name(value)
                    if not is_name:
                        shifted = value.split(" ", 1)
                        if len(shifted) == 2:
                            is_name, confidence = is_person_name(shifted[1])
                            if is_name:
                                offset = len(shifted[0]) + 1
                                value = shifted[1]
                                value_start += offset
                                value_end = value_start + len(value)
                    if not is_name:
                        # (b): pair spanning the match boundary.
                        tail = normalized_text[m.end():]
                        tm = re.match(r"\s+([A-Z][a-zäöüß]+)", tail)
                        second = value.split(" ", 1)
                        if tm and len(second) == 2:
                            candidate = f"{second[1]} {tm.group(1)}"
                            is_name, confidence = is_person_name(candidate)
                            if is_name:
                                # start at the second word of the match
                                offset = len(second[0]) + 1
                                value = candidate
                                value_start = m.start() + offset
                                value_end = m.end() + tm.end(1)
                    if not is_name:
                        continue
                    matches.append(PIIMatch(
                        type=pii_type,
                        value=value,
                        start=value_start,
                        end=value_end,
                        confidence=confidence,
                        rule=f"name:{'firstname_whitelist' if confidence >= 0.9 else 'capitalized_pair'}",
                    ))
                    continue

                confidence = self._patterns_meta.get(pii_type, 1.0)
                rule = f"regex:{pii_type}"
                matches.append(PIIMatch(
                    type=pii_type,
                    value=value,
                    start=value_start,
                    end=value_end,
                    confidence=confidence,
                    rule=rule,
                ))
        return matches

    def _scan_no_base64(
        self, normalized_text: str, original_text: str | None = None,
    ) -> list[PIIMatch]:
        """Run the full pattern sweep except the base64 heuristic.

        Used as the recursion target for the base64-encoded-PII detector so
        adversarial nesting (base64-of-base64-of-…) terminates after one
        level.  ``original_text`` is the string the credit-card scan uses to
        map normalized positions back to caller-visible spans; default is
        ``normalized_text`` (correct when caller has not transformed the
        text further).
        """
        if original_text is None:
            original_text = normalized_text
        matches: list[PIIMatch] = []

        # FIX-1E: detect code regions for false-positive penalty.
        # The detector uses the ORIGINAL text (not normalized) so that
        # markdown-fence positions line up with caller-visible offsets.
        # The penalty is applied only to FP-prone types — typed credentials
        # (api_key, jwt, …) keep full confidence so a real secret pasted
        # inside a code block is still masked.
        #
        # t_025240da P0-2: HTML documents opt OUT of the penalty.  Mail
        # template markup is tab-indented by construction, so the indented
        # block heuristic would down-score the recipient address inside a
        # ``mailto:`` link to 0.6 and the raw PII would pass through.  The
        # penalty exists for code snippets (markdown fences / prose pastes)
        # which never look like an HTML document.
        if _looks_like_html_document(original_text):
            code_regions: list[tuple[int, int]] = []
        else:
            code_regions = _detect_code_regions(original_text)

        # BTC addresses with internal whitespace are handled before the regular
        # pattern loop so the strict regex can validate the collapsed string.
        matches.extend(_scan_spaced_btc(normalized_text))

        # Spaced IBANs must be detected before the broad phone regex claims
        # parts of the number sequence.
        matches.extend(_scan_spaced_iban(normalized_text))

        # Emails: coarse pre-filter + non-backtracking final pattern.
        matches.extend(_scan_emails(normalized_text))

        # Credit cards need two-stage matching; everything else uses the
        # generic pattern loop.
        matches.extend(self._scan_credit_cards(normalized_text, original_text))
        matches.extend(self._scan_pattern_block(normalized_text))

        # Seed phrase heuristic (12+ consecutive BIP39 words)
        if is_seed_phrase(normalized_text):
            # Add a synthetic match covering the whole text; actual recovery is hard
            # without expensive tokenization, but this flags the content.
            matches.append(PIIMatch(
                type="bip39_seed_phrase",
                value=(
                    original_text[:_VALUE_TRUNCATION_LEN] + "..."
                    if len(original_text) > _VALUE_TRUNCATION_LEN
                    else original_text
                ),
                start=0,
                end=len(original_text),
                confidence=0.8,
                rule="heuristic:bip39_seed_phrase",
            ))

        # Sort by position, then length descending
        matches.sort(key=lambda x: (x.start, -(x.end - x.start)))

        # Add context-leak detections (low-confidence implicit identifiers)
        context_leaks = detect_context_leaks(normalized_text)
        matches.extend(context_leaks)
        matches.sort(key=lambda x: (x.start, -(x.end - x.start)))

        # FIX-1E: apply code-context false-positive penalty.
        matches = self._apply_confidence_partition(matches, code_regions)

        return self._merge_matches(matches)

    def scan_types(self, text: str) -> set[str]:
        """Return set of PII types found in text (fast check)."""
        if not text:
            return set()

        normalized_text = normalize_text(text)
        types: set[str] = set()

        # Emails are no longer in the pattern list; check via the hardened scanner.
        if _scan_emails(normalized_text):
            types.add("email")

        for pii_type, pattern in self._patterns:
            if pattern.search(normalized_text):
                # Credit card: need at least one candidate that also matches
                # the final format. scan() already filters by Luhn; scan_types
                # only needs to know a candidate exists to avoid missing it.
                if pii_type == "credit_card":
                    if not _CC_PRE.search(normalized_text):
                        continue
                    if not any(_is_credit_card(m.group(0)) for m in _CC_PRE.finditer(normalized_text)):
                        continue
                # Passport: only report if context keywords present
                if pii_type == "passport_number":
                    m = pattern.search(normalized_text)
                    if m and not _passport_context_check(normalized_text, m.start(), m.end()):
                        continue
                types.add(pii_type)
        if is_seed_phrase(normalized_text):
            types.add("bip39_seed_phrase")
        return types

    @property
    def pattern_count(self) -> int:
        """Total number of configured patterns.

        Includes the 12 base patterns + 35 extended patterns.
        """
        return len(self._patterns) + (1 if is_seed_phrase(" ") else 0)
