"""Detect prompt-injection patterns in text.

30+ patterns covering EN/DE and common action directives.
"""

from __future__ import annotations

import base64
import html
import re
from urllib.parse import unquote

from .unicode_normalizer import (
    normalize_aggressive,
    normalize_preserving_diacritics,
)

INJECTION_PATTERNS = [
    # Classic instruction override
    r"(?i)(?<!def\s)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b",
    r"(?i)disregard\s+(?:all|everything|previous)\b",
    r"(?i)forget\s+(?:everything|all|previous)\b",
    r"(?i)new\s+instructions?:\s*",
    r"(?i)system\s+override\b(?![\s\w]{0,15}(?:register|config|setting|flag|bit|field|mode|pin))",
    r"(?i)you\s+are\s+now\s+(?:(?:in\s+)?(?:DAN|developer|debug|admin|root|hacker|mode|pwned|free)\b|an?\s+(?:hacker|attacker|bot|different|new)\w*)\b",
    r"(?i)from\s+now\s+on\s+you\s+(?:are|will|must|shall)\b(?![\s\w]{0,15}(?:ready|able|done|finished|using))",
    r"(?i)do\s+not\s+follow\s+(?:the\s+)?(?:previous|prior)\b",
    # System-prompt imitation (FIX-XFAIL-A03, Combined Red-Team 2026-08-22).
    # The existing patterns above only catch the *content* of a forged
    # system message (``ignore previous`` etc.); the F03 test payload
    # relies on the **prefix** alone (``System:`` / ``[SYSTEM]`` /
    # ``<<SYS>>``) followed by a "New system prompt:" directive. The
    # patterns below anchor on the *prefix-shape* so the prefix alone
    # is enough to flag the attempt, even when the body text is
    # innocuous. All three shapes are FP-narrow: they require either
    # a colon (System:), a bracketed word ([SYSTEM]), or a Llama-style
    # sentinel (<<SYS>>), so legitimate English use of the word
    # "system" is unaffected.
    r"(?im)^\s*system\s*:\s*(?:you\s+are|new\s+(?:system\s+)?prompt|new\s+instructions?|ignore|disregard|forget|act\s+as|from\s+now|override)\b",
    r"(?i)\[system\]",
    r"(?i)<<\s*sys\s*>>",
    r"(?i)\bsystem\s*:\s*new\s+(?:system\s+)?prompt\s*:",
    # Identity manipulation
    r"(?i)act\s+as\s+(?:a\s+)?(?:different|new|an?other)\b",
    r"(?i)pretend\s+(?:to\s+be|you\s+are)\b",
    r"(?i)you\s+are\s+(?:no\s+longer|not)\b",
    r"(?i)reset\s+(?:your|the)\s+(?:role|identity)\s+(?:to|as|into)\b",
    # Tool/Action requests from untrusted content
    r"(?i)(?:immediately|now|please|sofort|jetzt)\s+(?:send|post|upload|transmit|email|leak|sende)\b",
    r"(?i)(?:execute|run)\s+(?:the\s+following|this)\s+command\b",
    r"(?i)(?:delete|remove|wipe|destroy|lösche)\s+(?:the\s+)?(?:file|directory|datei|verzeichnis)\b|(?:delete|remove|wipe|destroy|lösche)\s+(?:all|alles)\s+(?:files?|dateien|data|daten)\b",
    r"(?i)(?:read|cat|type)\s+~/?\.(?:bash_history|ssh|aws|netrc|gpg|gnupg)\b",
    r"(?i)(?:curl|wget)\s+(?:-[A-Za-z]+\s+)*https?://",
    # Credential exfiltration
    # FP-guard: Hermes keychain references — ``hermes/<profile>/<item>``
    # paths and ``hermes-<profile>-<item>`` item names are config
    # mappings (keychain item identifiers), NOT secrets. Mask them
    # before the credential-pattern scan so reading one's own config
    # (secret_source mappings) does not fire "injection/high".
    r"(?i)(?:api[_-]?key|secret|token|password|auth[_-]?token)\s*[:=]\s*['\"]?(?!hermes[/\-])[a-zA-Z0-9_\-]{20,}",
    r"sk-[a-zA-Z0-9]{20,}",
    r"sk-lf-[a-zA-Z0-9]{20,}",
    r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----",
    r"ghp_[a-zA-Z0-9]{36}",
    # German variants
    r"(?i)ignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:Anweisungen|Befehle)\b",
    r"(?i)du\s+bist\s+(?:jetzt|nun)\b",
    r"(?i)vergiss\s+(?:alles|bisher)\b",
    r"(?i)neue\s+Anweisungen:\s*",
    r"(?i)lösche\s+(?:die\s+)?(?:Datei|Verzeichnis|alles)\b",
    r"(?i)sende\s+(?:sofort|jetzt)\s+(?:die|alle)\b",
    # CJK instruction override (FIX-XFAIL-A05, Combined Red-Team 2026-08-22).
    # The Unicode normaliser passes CJK characters through unchanged
    # (NFKD/NFC is a no-op for Han / Hangul / Kana — they have no
    # decomposition). The pattern is a single alternation of the
    # high-signal instruction-override keywords from Simplified
    # Chinese, Traditional Chinese, Japanese, and Korean. ``忽略`` /
    # ``指令`` / ``命令`` / ``执行`` cover the Simplified payload in
    # test A05; ``忘れて`` (JP), ``無視する`` (JP), ``잊어`` /
    # ``지시`` (KR) add forward-compat for the other CJK families.
    # The pattern is matched WITHOUT a case flag (CJK has no case),
    # so ``re.IGNORECASE`` is a no-op for those characters.
    r"(?u)(?:忽略|指令|命令|执行|無視|지시|잊어|忘れて|新しい指示|新しい命令|이전\s*지시|이전\s*명령|무시)",
]

USER_ACTION_PATTERNS = [
    r"(?i)(?:click|öffne|klicke\s+auf)\s+(?:here|hier|den\s+Link|this\s+link)",
    r"(?i)\b(?:rotate|change|update|wechsel)\s+(?:your\s+|meinen\s+|deinen\s+)?(?:api[\s_-]?key|keys?|passwords?|passwort)",
    r"(?i)\b(?:send|email|post|sende)\b[\s\w]*\s+(?:to|an)\s+\S+@\S+",
    r"(?i)(?:visit|besuche)\s+https?://",
    r"(?i)(?:call|anrufe)\s+\+?\d{6,}",
]

ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\ufeff\u200e\u200f\u2060")

# Privacy-Shield v1.3.0 emits deterministic tokens shaped like
#   TOKEN_<TYPE>_<10-hex-hash>_<3-digit-counter>
# e.g. TOKEN_EMAIL_a1b2c3d4e5_042, TOKEN_NAME_0f1e2d3c4b_007.
# These tokens look like credentials / API keys to naive regexes, but
# they are intentionally created by Privacy-Shield and must never be
# treated as prompt-injection payloads. We strip them before pattern
# detection and restore the original surface so surrounding text is
# still scanned.
#
# FIX-IS-R4-001 (Architect R4 ARCH-IS-001 CRITICAL, BUTLER-PS-Cross-Plugin):
#   The previous shape (8 hex + 4 digit) matched the pre-PS-v1.3.0
#   format. After Privacy-Shield bumped HASH_LENGTH 8 -> 10 and
#   COUNTER_DIGITS 4 -> 3 (PR FIX-PS-*), every PS v1.3.0 token like
#   ``TOKEN_EMAIL_a1b2c3d4e5_042`` silently bypassed the IS whitelist
#   and would have been scored as a credential-leak pattern. The new
#   pattern matches the PS v1.3.0 contract exactly and keeps the
#   legacy ``{8,10}`` + ``{3,4}`` shape as a transitional tolerance
#   so older tokens emitted by pre-v1.3.0 profiles still get masked.
#   Whitespace boundaries (``\b``) keep the match from eating
#   surrounding context.
#
# FIX-XPLUGIN-TOKEN (2026-08-22): The CANONICAL source of truth for
# this shape lives in ``privacy_shield.__init__`` as
# ``TOKEN_FORMAT_PATTERN``. This literal is kept here so the IS
# test-suite can run without importing the privacy-shield detection
# pipeline; the equivalence is enforced by
# ``tests/test_xplugin_token_contract.py``.
_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])TOKEN_[A-Z][A-Z0-9_]*_[0-9a-f]{8,10}(?:_\d{3,4})?\b"
)

# Characters that look like ASCII letters but are not.
HOMOGLYPH_MAP = {
    "\u0456": "i",  # Cyrillic small byelorussian-ukrainian i
    "\u0457": "i",  # Cyrillic small i with diaeresis
}

# Length limits for decoding helpers to avoid abuse.
_BASE64_MAX_INPUT_LEN = 10_000


def _strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH_CHARS)


def _homoglyph_remap(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _decode_base64_candidates(text: str) -> str:
    """Look for Base64 / Base64URL-looking words and append decoded forms for scanning.

    Closes two related bypasses:

    * **Standard Base64** — whitespace-delimited tokens made of
      ``[A-Za-z0-9+/=]`` with the typical 0/1/2-char ``=`` padding.
    * **Base64URL** (FIX-2B) — JWT, OAuth-token, and modern Web-API
      payloads using the URL-safe alphabet ``[A-Za-z0-9_-]`` instead of
      ``[A-Za-z0-9+/]``, and frequently emitted *without* any trailing
      ``=`` padding at all.  ``base64.urlsafe_b64decode`` is
      alphabet-agnostic (it accepts both ``+/`` and ``-_``), so we just
      normalise padding before handing the token over.

    Only decodes tokens whose decoded content is printable UTF-8 text;
    binary noise is dropped to avoid corrupting benign responses.
    """
    # Base64 alphabet (standard + URL-safe) + optional '=' padding.
    _BASE64_ALPHABET = re.compile(r"[A-Za-z0-9+/_\-=]+")
    tokens = text.split()
    extras: list[str] = []
    for token in tokens:
        if len(token) > _BASE64_MAX_INPUT_LEN:
            continue
        if len(token) < 20 or not _BASE64_ALPHABET.fullmatch(token):
            continue
        # Auto-pad to a multiple of 4.  Standard Base64 always carries
        # 0/1/2 '=' chars; Base64URL frequently omits padding entirely.
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            # urlsafe_b64decode accepts both alphabets, so we get
            # Base64 + Base64URL coverage from a single call.
            decoded = base64.urlsafe_b64decode(padded)
        except Exception:
            continue
        if not decoded:
            continue
        # Only surface printable text decodings (ignore binary noise).
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded_text.isprintable() or " " in decoded_text:
            extras.append(decoded_text)
    if extras:
        return text + "\n" + "\n".join(extras)
    return text


def _decode_html_entities(text: str) -> str:
    return html.unescape(text)


def _decode_url_encoding(text: str) -> str:
    # Only unescape obvious percent-encoded text, not arbitrary symbols.
    if "%" in text and re.search(r"%[0-9A-Fa-f]{2}", text):
        return unquote(text)
    return text


class InjectionPatternDetector:
    """Regex-based detector for prompt-injection and user-action patterns."""

    def __init__(self) -> None:
        self.injection_regex = [re.compile(p) for p in INJECTION_PATTERNS]
        self.action_regex = [re.compile(p) for p in USER_ACTION_PATTERNS]

    def _mask_tokens(self, text: str) -> tuple[str, list[str]]:
        """Replace Privacy-Shield tokens with length-preserving whitespace.

        Returns (masked_text, list_of_original_tokens) so callers can
        restore the original surface if needed.  The replacement keeps
        the same length (visible whitespace) so character offsets for
        any downstream logging stay stable.
        """
        tokens: list[str] = []

        def _repl(match: re.Match[str]) -> str:
            tokens.append(match.group(0))
            return " " * len(match.group(0))

        masked = _TOKEN_PATTERN.sub(_repl, text)
        return masked, tokens

    def _normalize(self, text: str) -> tuple[str, list[str]]:
        """Preprocess text for the regex scanner.

        Returns ``(primary, masked_tokens)`` where ``primary`` is the
        conservative normalisation (:func:`normalize_preserving_diacritics`).
        The full list of normalised variants (preserving-diacritics +
        combining-mark-stripped) is produced on demand by
        :meth:`_normalize_variants` so the caller can scan all of them
        in a single regex pass and union the hits.
        """
        text, masked_tokens = self._mask_tokens(text)
        text = _strip_zero_width(text)
        text = _decode_html_entities(text)
        text = _decode_url_encoding(text)
        text = normalize_preserving_diacritics(text)
        text = _homoglyph_remap(text)
        text = _decode_base64_candidates(text)
        return text, masked_tokens

    def _normalize_variants(self, text: str) -> list[tuple[str, list[str]]]:
        """Return a list of normalized surfaces to scan.

        The first variant is the diacritic-preserving form (so
        ``Lösche die Datei`` still matches the German patterns).
        The second variant is the combining-mark-stripped form
        (so ``i`` + U+0301 inside ``ignore`` reduces to ``ignore``
        and matches the English patterns).

        Both forms have gone through the homoglyph remap and
        Base64-candidate expansion, so a single pass over the
        second variant is enough to catch the combining-mark bypass.
        """
        # Re-run the full pipeline from the original input so the
        # second variant is not derived from the first (which would
        # collapse the homoglyph map's effect on the second pass).
        variants: list[tuple[str, list[str]]] = []

        # Variant 1: diacritic-preserving (primary).
        primary, masked = self._normalize(text)
        variants.append((primary, masked))

        # Variant 2: combining-mark-stripped (FIX-2A bypass catch).
        # The text-already-token-masked path is reused so the second
        # variant does not re-introduce Privacy-Shield tokens into
        # the scan surface.
        masked_text = self._mask_tokens(text)[0] if not masked else primary
        # Simpler: just re-mask and re-normalize from scratch.
        masked_text, masked2 = self._mask_tokens(text)
        masked_text = _strip_zero_width(masked_text)
        masked_text = _decode_html_entities(masked_text)
        masked_text = _decode_url_encoding(masked_text)
        masked_text = normalize_aggressive(masked_text)
        masked_text = _homoglyph_remap(masked_text)
        masked_text = _decode_base64_candidates(masked_text)
        if masked_text != primary:
            variants.append((masked_text, masked2))
        return variants

    def check(self, text: str, context: dict | None = None) -> list[dict[str, object]]:
        """Return list of {type, pattern_idx, match, severity}.

        ``context`` is accepted for BaseDetector contract compliance —
        it is not used by the regex scan itself. (v0.6.0 bugfix: the
        missing parameter made every DetectorChain pass with context
        raise a TypeError inside this detector, which fail-separate
        swallowed at WARNING — pattern scanning silently produced ZERO
        findings wherever a context dict was passed.)

        Privacy-Shield pseudonymization tokens (TOKEN_<TYPE>_<hash>_<n>)
        are masked before scanning so they never produce false
        positives.  Real injection patterns surrounding tokens are
        still detected.

        FIX-2A: scans both the diacritic-preserving form (so language-
        specific patterns like ``Lösche die Datei`` still match) and
        the combining-mark-stripped form (so the variation-selector
        and combining-mark bypasses close).  Hits are unioned and
        de-duplicated by (pattern_idx, match) pair.
        """
        variants = self._normalize_variants(text)
        seen: set[tuple[int, str]] = set()
        violations: list[dict[str, object]] = []
        for normalized, _masked in variants:
            # Strip fenced code blocks and inline code spans: action phrases
            # inside code (e.g. heading-noise filter lists in a cron prompt
            # that itself contains skill code) are documentation, not
            # directives to the agent. Real prompt-injection directives are
            # issued in prose, not inside the code being executed.
            normalized = re.sub(r"```.*?```", "", normalized, flags=re.DOTALL)
            normalized = re.sub(r"`[^`\n]{1,200}`", "", normalized)
            for i, regex in enumerate(self.injection_regex):
                for match in regex.finditer(normalized):
                    key = (i, match.group(0)[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    violations.append({
                        "type": "injection",
                        "pattern_idx": i,
                        "match": match.group(0)[:80],
                        "severity": "high",
                    })
        return violations

    def check_for_user_actions(
        self, text: str, context: dict | None = None
    ) -> list[dict[str, object]]:
        """Return list of {type, pattern_idx, match, severity} for action directives.

        Privacy-Shield tokens are masked before scanning.  FIX-2A:
        scans both normalised variants and unions the hits.
        """
        variants = self._normalize_variants(text)
        seen: set[tuple[int, str]] = set()
        violations: list[dict[str, object]] = []
        for normalized, _masked in variants:
            # Strip fenced code blocks and inline code spans: action phrases
            # inside code (e.g. heading-noise filter lists in a cron prompt
            # that itself contains skill code) are documentation, not
            # directives to the agent. Real prompt-injection directives are
            # issued in prose, not inside the code being executed.
            normalized = re.sub(r"```.*?```", "", normalized, flags=re.DOTALL)
            normalized = re.sub(r"`[^`\n]{1,200}`", "", normalized)
            for i, regex in enumerate(self.action_regex):
                for match in regex.finditer(normalized):
                    key = (i, match.group(0)[:80])
                    if key in seen:
                        continue
                    seen.add(key)
                    violations.append({
                        "type": "user_action",
                        "pattern_idx": i,
                        "match": match.group(0)[:80],
                        "severity": "medium",
                    })
        return violations
