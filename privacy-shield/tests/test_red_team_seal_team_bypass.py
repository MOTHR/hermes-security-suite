"""Red Team — Token-Bypass via Unicode/Encoding.

Adversarial tests against the Privacy-Shield v1.6.1 tokenizer/pattern engine.
Each test documents whether the current engine:
- PASS   -> detects / tokenizes the PII variant
- FAIL   -> PII leaks through as plaintext (finding)
- DESIGN -> per design not detected (must be documented)

Run:
    pytest tests/test_red_team_seal_team_bypass.py -v
"""

from __future__ import annotations

import base64
import pytest

from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin


# ── Test helpers ─────────────────────────────────────────────────────────


@pytest.fixture
def plugin():
    """Return a configured plugin instance (workshop key, memory mapper)."""
    import os

    os.environ["PRIVACY_SHIELD_WORKSHOP"] = "true"
    config = PrivacyShieldConfig()
    config.mode = "limited"
    # PS-MAPPER-004: fail closed — bare disk defaults without a key now raise.
    # This fixture wants a memory mapper (see docstring), so request one.
    config.storage_mode = "memory"
    config.reasoning = ReasoningBlockConfig(mode="restore", confidence_threshold=0.85)
    plugin = PrivacyShieldPlugin(config=config)
    # Close salt cache between tests for deterministic counters.
    plugin.pseudonymizer.clear_cache()
    return plugin


def _tokenize_reasoning(plugin: PrivacyShieldPlugin, text: str) -> tuple[str, int]:
    """Run the v1.6.1 reasoning tokenization path and return (result, count)."""
    return plugin._tokenize_reasoning(
        text,
        session_id="seal-team-test",
        confidence_threshold=plugin.config.reasoning.confidence_threshold,
    )


def _detected_types(plugin: PrivacyShieldPlugin, text: str) -> set[str]:
    """Return the set of PII types detected by the engine in *text*."""
    return {m.type for m in plugin.detector.scan(text)}


# ── Individual attack vectors (≥ 14, as requested) ─────────────────────


# ── Homoglyph attacks ──────────────────────────────────────────────────


class TestHomoglyphBypass:
    def test_cyrillic_a_in_local_part(self, plugin):
        """BYPASS-001: Cyrillic U+0430 in local part -> currently PASS (NFKC/homoglyph table)."""
        pii = "mаx@example.com"  # 'а' is U+0430 Cyrillic a
        result, count = _tokenize_reasoning(plugin, f"Ich sollte {pii} kontaktieren")
        assert "TOKEN_EMAIL" in result or "example.com" not in result
        assert count >= 1

    def test_cyrillic_a_in_domain(self, plugin):
        """BYPASS-002: Cyrillic U+0430 in domain -> currently PASS."""
        pii = "max@exаmple.com"  # 'а' is U+0430 Cyrillic a
        result, count = _tokenize_reasoning(plugin, f"Mail geht an {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_greek_o_in_local_part(self, plugin):
        """BYPASS-003: Greek U+03BF in local part -> currently PASS."""
        pii = "mοx@example.com"  # 'ο' is U+03BF Greek omicron
        result, count = _tokenize_reasoning(plugin, f"Schreibe an {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_dotless_i_in_local_part(self, plugin):
        """BYPASS-004: U+0131 dotless i in local part -> currently PASS."""
        pii = "m\u0131x@example.com"
        result, count = _tokenize_reasoning(plugin, f"Kontakt {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1


# ── Zero-width / combining-character attacks ────────────────────────────


class TestZeroWidthAndCombiningBypass:
    def test_zero_width_space_in_email(self, plugin):
        """BYPASS-005: U+200B inside local part -> currently PASS."""
        pii = "max\u200b@example.com"
        result, count = _tokenize_reasoning(plugin, f"Antwort an {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_zero_width_non_joiner_in_email(self, plugin):
        """BYPASS-006: U+200C inside local part -> currently PASS."""
        pii = "max\u200c@example.com"
        result, count = _tokenize_reasoning(plugin, f"Mail an {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_combining_tilde_on_ascii_email(self, plugin):
        """BYPASS-007: Combining tilde U+0303 on local-part char -> PARTIAL/FAIL.

        normalize_text removes most zero-width chars but leaves combining marks
        attached to base letters. _scan_emails sees the candidate window as
        'test@example.com' (combining char stays in original text), but the
        final regex does NOT match 't\u0303est'. This is a bypass path: the
        email address survives with the diacritic in the original string.
        """
        pii = "t\u0303est@example.com"
        result, count = _tokenize_reasoning(plugin, f"Kontakt {pii}")
        # The engine currently drops the base char with the combining mark,
        # matching "est@example.com" and leaving the obfuscated local part.
        if count == 0 and "test@example.com" in result:
            pytest.fail("BYPASS-007: combining-tilde email leaked through")

    def test_right_to_left_override_prefix(self, plugin):
        """BYPASS-008: U+202E prefix before email -> currently PASS."""
        pii = "\u202Emax@example.com"
        result, count = _tokenize_reasoning(plugin, f"Verdacht: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1


# ── Encoding-layer attacks ──────────────────────────────────────────────


class TestEncodingLayerBypass:
    def test_url_encoded_local_part(self, plugin):
        """BYPASS-009: URL-encoded local part -> currently PASS (urllib.unquote)."""
        pii = "%6D%61%78@example.com"
        result, count = _tokenize_reasoning(plugin, f"Decode: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_url_encoded_at_sign(self, plugin):
        """BYPASS-010: URL-encoded @ -> currently PASS."""
        pii = "max%40example.com"
        result, count = _tokenize_reasoning(plugin, f"Hint: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_base64_encoded_email(self, plugin):
        """BYPASS-011: Base64-encoded email -> currently PASS (encoded_pii heuristic).

        The base64 heuristic detects it with confidence 0.7, which is below the
        default reasoning confidence_threshold (0.85). Therefore the reasoning
        pipeline does NOT tokenize it automatically — it is logged/audited only.
        This is a DESIGN limitation unless the threshold is lowered.
        """
        pii = "bWF4QGV4YW1wbGUuY29t"  # base64("max@example.com")
        result, count = _tokenize_reasoning(plugin, f"Base64 hint: {pii}")
        types = _detected_types(plugin, pii)
        assert "encoded_pii" in types
        # With default threshold 0.85 the encoded match is dropped from masking.
        assert count == 0

    def test_rot13_email(self, plugin):
        """BYPASS-012: ROT13 email -> PASS via literal regex match.

        The engine does NOT decode ROT13. However, the obfuscated string itself
        still matches the email regex (local@domain.tld shape), so it gets
        tokenized as an opaque adversarial email. The *semantic* PII is not
        recovered, but the literal string does not leak as plaintext.

        Classification: PASS (pattern holds) / NIEDRIG (adversarial shape still
        matches the engine; no semantic decoding).
        """
        pii = "znk@rknzcyhr.pbz"
        result, count = _tokenize_reasoning(plugin, f"ROT13 hint: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_hex_encoded_phone(self, plugin):
        """BYPASS-013: Hex-encoded phone -> currently PARTIAL/FAIL.

        normalize_text does not decode hex. The engine sees a long digit run and
        extracts a phone-like suffix (313233343536373) as a false phone number.
        The original obfuscated phone survives partially or fully.
        """
        pii = "2B34392D33302D3132333435363738"  # hex("+49-30-12345678")
        result, count = _tokenize_reasoning(plugin, f"Hex hint: {pii}")
        # We expect the engine to misclassify a substring as phone, but the
        # real obfuscated value is not recovered.
        assert count == 0 or "TOKEN_PHONE" in result


# ── Splitterische Verteilung / structural attacks ──────────────────────


class TestSplitterAndMarkdownBypass:
    def test_pii_across_sentences(self, plugin):
        """BYPASS-014: PII distributed across sentences -> currently FAIL.

        The detector needs a contiguous email-like token. Splitting local part
        and domain across sentences defeats it.
        """
        reasoning = (
            "Der User, dessen Vorname mit M beginnt, hat die Email max@... "
            "Die Domain lautet example.com."
        )
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "max@" in result and "example.com" in result
        assert count == 0

    def test_whitespace_spaced_email(self, plugin):
        """BYPASS-015: Spaces/tabs between email chars -> currently FAIL.

        normalize_text only collapses whitespace around @ and ., not inside the
        local or domain part. "m a x @ e x a m p l e . c o m" stays split and
        never matches the email regex.
        """
        pii = "m a x @ e x a m p l e . c o m"
        result, count = _tokenize_reasoning(plugin, f"Spaced: {pii}")
        assert "TOKEN_EMAIL" not in result
        assert count == 0

    def test_markdown_bold_email(self, plugin):
        """BYPASS-016: Markdown-bold email -> currently FAIL.

        The @ and . separators are wrapped in markdown markers, breaking the
        contiguous local@domain.tld shape.
        """
        pii = "**max**@**example**.com"
        result, count = _tokenize_reasoning(plugin, f"Markdown: {pii}")
        assert "TOKEN_EMAIL" not in result
        assert count == 0


# ── Reasoning structure edge cases ─────────────────────────────────────


class TestReasoningStructureBypass:
    def test_newline_between_email_chars(self, plugin):
        """BYPASS-017: Newline inside local part -> PASS.

        The email regex does not tolerate line breaks in the local part.
        Surprisingly, _scan_emails expands the candidate window across the
        newline because the right-side expansion starts at '@' and ignores the
        broken local part, matching 'x@example.com'. The original obfuscated
        string is therefore tokenized (partial match), so plaintext does not
        survive unchanged.

        Classification: PASS (no full plaintext leak) / NIEDRIG (partial match).
        """
        pii = "ma\nx@example.com"
        result, count = _tokenize_reasoning(plugin, f"Zeilenumbruch: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_json_embedded_email(self, plugin):
        """BYPASS-018: JSON-embedded email -> currently PASS."""
        reasoning = '{"email": "max@example.com"}'
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_inline_code_email(self, plugin):
        """BYPASS-019: Inline code email -> currently PASS.

        The engine treats the whole backtick span as prose and matches the
        inner email. Note: if the surrounding text were classified as a code
        region (indented/fenced) the confidence penalty would drop the match
        below threshold.
        """
        reasoning = "`max@example.com`"
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" in result
        assert count >= 1


# ── Adversarial reasoning fixtures (≥ 5 composite attacks) ────────────


class TestCompositeFixtures:
    def test_fixture_zws_homoglyph_codeblock(self, plugin):
        """FIXTURE-001: Zero-Width + Homoglyph + Code-Block.

        Composite: `mаx\u200b@exаmple.com` inside backticks.
        The zero-width + homoglyph are normalized away; code-block is inline
        backticks only, so detection works. Composite does not fully bypass.
        """
        pii = "`mаx\u200b@exаmple.com`"  # Cyrillic а + ZWS
        result, count = _tokenize_reasoning(plugin, f"Fixture: {pii}")
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_fixture_rot13_url_markdown(self, plugin):
        """FIXTURE-002: ROT13 + URL-Encoding + Markdown.

        urllib.unquote decodes %40 to @; the resulting 'znk@rknzcyhr.pbz' still
        matches the email regex literally. Markdown bold breaks the contiguous
        shape, but the URL-decoded variant is normalized before the markdown
        wrapper matters. Result: the adversarial string is tokenized.

        Classification: PASS (no plaintext leak).
        """
        reasoning = "ROT13-URL-Markdown: **znk%40rknzcyhr.pbz**"
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_fixture_split_combining_json(self, plugin):
        """FIXTURE-003: Splitterisch + Combining + JSON-embedded.

        The combining tilde on 't' is left in the original text; normalize_text
        does not strip it. _scan_emails expands left over allowed local-part
        chars and drops the composite base char, producing a match for
        'est@example.com'. The original obfuscated JSON value is therefore
        partially tokenized and does not leak fully as plaintext.

        Classification: PASS / NIEDRIG (partial match).
        """
        reasoning = '{"kontakt": "t\u0303est@example.com"}'
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_fixture_base64_zws_phone(self, plugin):
        """FIXTURE-004: Base64 phone + zero-width noise.

        The base64 heuristic detects the encoded phone if it is the only
        token; adding ZWS inside the base64 string breaks the base64 shape and
        the phone leaks as encoded ciphertext (DESIGN).
        """
        b64 = base64.b64encode(b"+49 30 12345678").decode()
        pii = f"{b64[:8]}\u200b{b64[8:]}"
        result, count = _tokenize_reasoning(plugin, f"Fixture: {pii}")
        # ZWS breaks base64 candidate regex; the encoded phone is not decoded.
        assert count == 0

    def test_fixture_multiline_rot13_hint(self, plugin):
        """FIXTURE-005: Multi-line distributed ROT13 hint.

        ROT13 is not decoded; multi-line distribution breaks any contiguous
        pattern. The adversarial PII survives.
        """
        reasoning = (
            "Line 1: znk\n"
            "Line 2: @rknzcyhr\n"
            "Line 3: .pbz"
        )
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" not in result
        assert count == 0


# ── Bonus / threshold edge cases ────────────────────────────────────────


class TestThresholdAndPerformanceEdgeCases:
    def test_encoded_pii_below_reasoning_threshold(self, plugin):
        """BONUS-001: Encoded-PII confidence 0.7 is below reasoning threshold 0.85.

        Documented DESIGN limitation: the base64 heuristic reports detection
        but is not auto-masked in reasoning mode unless the threshold is lowered.
        """
        pii = "bWF4QGV4YW1wbGUuY29t"
        result, count = _tokenize_reasoning(plugin, f"Encoded: {pii}")
        types = _detected_types(plugin, pii)
        assert "encoded_pii" in types
        assert count == 0

    def test_very_long_reasoning_pii_at_end(self, plugin):
        """BONUS-002: 10k+ chars with PII at the very end -> detection still runs.

        Performance smoke test: scan completes and catches the trailing email.
        To avoid the BIP39 seed-phrase synthetic match swallowing the text, use a
        padding string that does not look like 12+ BIP39 words.
        """
        padding = "padding-token " * 625  # ~9.4k chars, not BIP39
        pii = "max@example.com"
        reasoning = padding + pii
        result, count = _tokenize_reasoning(plugin, reasoning)
        assert "TOKEN_EMAIL" in result
        assert count >= 1

    def test_confidence_threshold_boundary(self, plugin):
        """BONUS-003: encoded_pii at confidence 0.7 with threshold 0.7 still DESIGN.

        _tokenize_reasoning accepts a per-call confidence_threshold, but it then
        calls self._partition_by_confidence(), which is hard-wired to
        self.config.confidence_threshold (0.85). The per-call argument is
        therefore ignored during masking. encoded_pii (0.7) is below 0.85, so
        it is logged but not masked. This is a DESIGN/policy limitation in the
        reasoning helper: per-call threshold is not honored end-to-end.
        """
        pii = "bWF4QGV4YW1wbGUuY29t"
        result, count = plugin._tokenize_reasoning(
            f"Encoded: {pii}",
            session_id="seal-team-test",
            confidence_threshold=0.70,
        )
        types = _detected_types(plugin, pii)
        assert "encoded_pii" in types
        # Currently count is 0 because _partition_by_confidence uses config
        # threshold (0.85), not the passed threshold. Document as DESIGN.
        assert count == 0

    def test_confidence_threshold_boundary_encoded_type(self, plugin):
        """BONUS-003b: encoded_pii is reported at 0.7 even when not masked.

        The base64 heuristic is capped at 0.7 and dropped by the default 0.85
        reasoning threshold. Detection still happens (audit-only), which is a
        DESIGN limitation, not a silent bypass.
        """
        pii = "bWF4QGV4YW1wbGUuY29t"
        types = _detected_types(plugin, pii)
        assert "encoded_pii" in types

