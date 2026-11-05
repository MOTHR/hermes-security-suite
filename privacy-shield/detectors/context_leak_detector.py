"""Context-Leak Detection for Privacy-Shield.

Detects implicit identifiers — sentences that could re-identify a person
even without explicit PII (names, emails, etc.).

Spec reference: Google Privacy-Shield recommendation:
"Kontext-Leaks verhindern: LLMs können Personen oft auch ohne Klarnamen
identifizieren."

Patterns:
- "der/die einzige [BERUF] in [LOCATION]"
- "der/die [ALTER] aus [LOCATION]"
- "der/die [GEBURTSTAG/MONAT]"
- "Mitarbeiter [NUMMER]"

Detection mode: low-confidence (0.3-0.5), tagged as "implicit_identifier".
Action: pseudonymize entire sentence → [REDACTED:context]
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .dataclasses import PIIMatch

logger = logging.getLogger(__name__)

# MORPH-PS-4: ``PIIMatch`` lives in ``detectors.dataclasses`` (a leaf module
# with stdlib-only deps) so the previous lazy-import dance is no longer
# needed.  The import is direct and circular-import-free.


# ── ReDoS / tuning constants ─────────────────────────────────────────────

# Default per-pattern timeout for context-leak regex matching (ReDoS guard).
DEFAULT_TIMEOUT_SECONDS: float = 5.0

# Maximum number of words allowed in context-leak patterns after a keyword.
# The regex quantifiers are written as `{0,%d}` so the total span is at most
# this many words (Smith MED-003).
MAX_CONTEXT_WORDS: int = 5


# ── Context-Leak Patterns ────────────────────────────────────────────────

# Pattern 1: "der/die einzige [BERUF] in [LOCATION]"
# Matches: "der einzige Buchhalter in Filiale X", "die einzige Ärztin in Berlin"
# Quantifier limited to {1,%d} words to prevent ReDoS (Smith MED-003)
_LEAK_UNIQUE_ROLE_RE = re.compile(
    r'\b(der|die)\s+einzige[nrms]?\s+'
    r'[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,%d}\s+'
    r'in\s+'
    r'[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ]?\w*){0,%d}\b'
    % (MAX_CONTEXT_WORDS - 1, MAX_CONTEXT_WORDS - 1),
    re.IGNORECASE,
)

# Pattern 2: "der/die [ALTER] aus [LOCATION]"
# Matches: "der 45-jährige aus München", "die 30-Jährige aus Hamburg"
# Quantifier limited to {1,%d} words to prevent ReDoS (Smith MED-003)
_LEAK_AGE_LOCATION_RE = re.compile(
    r'\b(der|die)\s+\d{1,3}\s*[-–]\s*jährige[nrms]?\s+'
    r'aus\s+'
    r'[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,%d}\b'
    % (MAX_CONTEXT_WORDS - 1),
    re.IGNORECASE,
)

# Pattern 3: "der/die [GEBURTSTAG/MONAT]"
# Matches: "der am 15. Mai Geborene", "die im Juni Geborene"
_LEAK_BIRTH_RE = re.compile(
    r'\b(der|die)\s+'
    r'(?:am\s+\d{1,2}\.\s*[A-ZÄÖÜ][a-zäöüß]+\s+Geborene[nrms]?'
    r'|im\s+[A-ZÄÖÜ][a-zäöüß]+\s+Geborene[nrms]?)\b',
    re.IGNORECASE,
)

# Pattern 4: "Mitarbeiter [NUMMER]"
# Matches: "Mitarbeiter 12345", "Mitarbeiter #42", "Mitarbeiter Nr. 007"
_LEAK_EMPLOYEE_ID_RE = re.compile(
    r'\bMitarbeiter\s+(?:#|Nr\.?\s*)?\d+\b',
    re.IGNORECASE,
)

# ── Sentence Boundary ────────────────────────────────────────────────────

# Split on .!? followed by space + capital letter, or end of string
_SENTENCE_SPLIT_RE = re.compile(r'(?<=[.!?])\s+(?=[A-ZÄÖÜ0-9])')


def _find_containing_sentence(text: str, match_start: int, match_end: int) -> tuple[int, int]:
    """Find the sentence boundaries containing a match position.

    Returns (sentence_start, sentence_end) character offsets.
    """
    # Find sentence start: last sentence boundary before match_start
    boundaries = [0]
    for m in _SENTENCE_SPLIT_RE.finditer(text):
        boundaries.append(m.end())
    boundaries.append(len(text))

    sent_start = 0
    sent_end = len(text)
    for i in range(len(boundaries) - 1):
        if boundaries[i] <= match_start < boundaries[i + 1]:
            sent_start = boundaries[i]
            sent_end = boundaries[i + 1]
            break

    # Strip leading/trailing whitespace from sentence
    while sent_start < sent_end and text[sent_start] in ' \t\n\r':
        sent_start += 1
    while sent_end > sent_start and text[sent_end - 1] in ' \t\n\r':
        sent_end -= 1

    return sent_start, sent_end


# ── Detection Function ───────────────────────────────────────────────────

def _get_leak_rule_name(confidence: float) -> str:
    """Map confidence to a human-readable leak rule name."""
    if confidence >= 0.4:
        return "unique_role_or_age_location"
    elif confidence >= 0.35:
        return "birth_reference"
    else:
        return "employee_id"


def detect_context_leaks(
    text: str, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> list[Any]:
    """Detect implicit identifiers (context leaks) in text.

    Each match returns the ENTIRE containing sentence as the value,
    so the pseudonymizer can replace the whole sentence.

    Confidence: 0.3-0.5 (low — these are heuristics, not certain PII).

    Args:
        text: Input text to scan.
        timeout: Max seconds for regex matching (ReDoS guard, Smith MED-003).
    """
    if not text:
        return []

    patterns: list[tuple[re.Pattern[str], float]] = [
        (_LEAK_UNIQUE_ROLE_RE, 0.4),
        (_LEAK_AGE_LOCATION_RE, 0.4),
        (_LEAK_BIRTH_RE, 0.35),
        (_LEAK_EMPLOYEE_ID_RE, 0.3),
    ]

    # Collect all pattern matches with their sentence boundaries
    sentence_spans: set[tuple[int, int, float]] = set()

    import concurrent.futures

    def _match_pattern(
        pattern: re.Pattern[str], confidence: float
    ) -> list[tuple[int, int, float]]:
        results = []
        for m in pattern.finditer(text):
            sent_start, sent_end = _find_containing_sentence(
                text, m.start(), m.end()
            )
            results.append((sent_start, sent_end, confidence))
        return results

    # Run each pattern with a timeout guard (ReDoS protection)
    for pattern, confidence in patterns:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_match_pattern, pattern, confidence)
                results = future.result(timeout=timeout)
                sentence_spans.update(results)
        except (concurrent.futures.TimeoutError, RuntimeError):
            # Pattern timed out — skip it, don't block the pipeline
            logger.warning(
                "Context leak pattern %s timed out after %.1fs — skipping",
                pattern.pattern[:60], timeout,
            )

    # Build PIIMatch list, sorted by position, deduplicated
    matches = []
    seen_spans: set[tuple[int, int]] = set()

    for start, end, confidence in sorted(sentence_spans):
        if (start, end) in seen_spans:
            continue
        seen_spans.add((start, end))
        sentence_text = text[start:end]
        matches.append(PIIMatch(
            type="implicit_identifier",
            value=sentence_text,
            start=start,
            end=end,
            confidence=confidence,
            rule=f"context_leak:{_get_leak_rule_name(confidence)}",
        ))

    return matches
