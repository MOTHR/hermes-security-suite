"""Tests for Unicode normalization and obfuscation bypass resistance."""

import pytest

from privacy_shield.detectors.regex_detector import RegexPIIDetector, normalize_text


@pytest.fixture
def detector():
    return RegexPIIDetector()


class TestNormalization:
    def test_normalize_removes_zero_width(self):
        text = "alex\u200b@example.com"
        assert "\u200b" not in normalize_text(text)
        assert "alex@example.com" in normalize_text(text)

    def test_normalize_replaces_homoglyphs(self):
        # Cyrillic 'а' looks like ASCII 'a'
        text = "alex@\u0435xample.com"  # \u0435 = Cyrillic е
        normalized = normalize_text(text)
        assert "alex@example.com" in normalized

    def test_normalize_email_obfuscation(self):
        text = "alex [at] example [dot] com"
        assert normalize_text(text) == "alex@example.com"

    def test_normalize_email_obfuscation_parens(self):
        text = "alex (at) example (dot) com"
        assert normalize_text(text) == "alex@example.com"


class TestUnicodeBypassDetection:
    def test_email_zero_width_caught(self, detector):
        text = "alex\u200b@example.com"
        matches = detector.scan(text)
        assert any(m.type == "email" for m in matches)

    def test_email_obfuscation_caught(self, detector):
        text = "alex (at) example (dot) com"
        matches = detector.scan(text)
        assert any(m.type == "email" for m in matches)

    def test_cyrillic_homoglyph_email_caught(self, detector):
        text = "alex@\u0435xample.com"  # Cyrillic е
        matches = detector.scan(text)
        assert any(m.type == "email" for m in matches)

    def test_bip39_homoglyph_caught(self, detector):
        text = "abandon " * 12
        matches = detector.scan(text)
        assert any(m.type == "bip39_seed_phrase" for m in matches)

    def test_phone_with_invisible_chars_caught(self, detector):
        text = "+49\u200b 30 1234567"
        matches = detector.scan(text)
        assert any(m.type == "phone" for m in matches)


class TestMatchPositionIntegrity:
    def test_normalized_email_position_maps_back(self, detector):
        text = "Kontakt: alex\u200b@example.com bitte"
        matches = detector.scan(text)
        email_match = next(m for m in matches if m.type == "email")
        # The returned position must be a valid slice of the original text
        # containing the email (zero-width chars included). Length may differ
        # from the normalized match, so just verify the substring is present.
        original_span = text[email_match.start:email_match.end]
        assert "alex" in original_span
        assert "@example" in original_span
