"""PhoneDetector — extracted phone-number sub-detector (FIX-PS4).

FP-hardened 2026-09-20 (fleet Telegram incident): the old single-regex
approach tokenized ``20260920`` inside a vault file path as a phone number
(``TOKEN_PHONE_d4a6fa120b_012-...``). Detection is now a STRICT-structured
pattern (keeps the old block forms so the locale corpus stays green) plus
boundary anchoring and a structural validator:

- Boundary anchors: matches may not touch digits or filename-ish characters
  (``.`` followed by a letter) on the outside — a path like
  ``03-Market-Analysis/20260920-BTC-...md`` can never match.
- Structural validator: total digits 7-15; without an international prefix
  the area block must start with ``0`` (DE/Vorwahl convention); a 1-digit
  area with a country code is only valid when the subscriber part is
  unseparated (AT ``+43 1 1234567`` yes, JP ``+81 3 1234 5678`` no).
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseDetector

# STRICT block structure (same forms as the legacy single regex, which the
# locale corpus codifies), wrapped in boundary anchors:
#   [cc?] [area 1-4] [sep?] [block 3-4] [sep?] [block 2-4]
_PHONE_SEP_RE = re.compile(
    r'(?<![\d\w])'
    r'(?:(?P<cc>\+\d{1,3}|00\d{1,3})[\s\-./]?)?'
    r'(?P<a>\(0?\d{1,4}\)|0?\d{1,4})'
    r'(?P<sep>[\s\-./]?)'
    r'(?P<b1>\d{3,4})'
    r'(?P<sep2>[\s\-./]?)'
    r'(?P<b2>\d{2,4})'
    r'(?!\d)(?!\.[A-Za-z])'
)


# ── Date+time FP guard (2026-10-07, Fielmann incident) ──────────────────
# '26.08.2028 09:00' tokenized '08.2028 09' as a phone: area '08' passed the
# Vorwahl rule, '2028'/'09' filled b1/b2. Suppress a match ONLY when all
# three structural conditions hold — a real number like '26.0171 2345678'
# (day prefix + area '0171') fails the month check and stays detected.
_DATE_DAY_BEFORE_RE = re.compile(r'\d{1,2}\.$')
_DATE_TIME_AFTER_RE = re.compile(r':\d{2}')


def is_date_time_false_positive(text: str, match: re.Match[str]) -> bool:
    """True when the phone match sits inside a 'DD.MM.YYYY HH:MM' stamp."""
    before = text[: match.start()]
    if not _DATE_DAY_BEFORE_RE.search(before):
        return False
    a = match.group('a').lstrip('(')
    b1 = match.group('b1')
    if not (a.isdigit() and len(a) <= 2 and 1 <= int(a) <= 12):
        return False
    if not (b1.isdigit() and len(b1) == 4 and 1900 <= int(b1) <= 2099):
        return False
    return bool(_DATE_TIME_AFTER_RE.match(text, match.end()))


def _sep_valid(match: re.Match[str]) -> bool:
    """Structural check: total digits 7-15, area-0 rule without cc, and the
    1-digit-area-with-cc rule (AT vs JP disambiguation)."""
    cc = match.group('cc')
    a = match.group('a').lstrip('(')
    sep2 = match.group('sep2')
    digits = re.sub(r'\D', '', match.group(0))
    if not 7 <= len(digits) <= 15:
        return False
    if not cc and not a.startswith(('0', '(')):
        return False
    if len(a) < 2 and cc and sep2:
        return False
    return True


class PhoneDetector(BaseDetector):
    """Detect DE and international phone numbers (FP-hardened, 2026-09-20)."""

    @property
    def name(self) -> str:
        return "phone"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        matches: list[dict[str, Any]] = []
        for m in _PHONE_SEP_RE.finditer(text):
            if not _sep_valid(m):
                continue
            if is_date_time_false_positive(text, m):
                continue
            matches.append(
                {
                    "type": "phone",
                    "value": m.group(0),
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 1.0,
                    "rule": "regex:phone",
                }
            )
        return matches