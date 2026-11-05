"""Locale-coverage regression tests for Privacy-Shield v1.5.0.

These tests do NOT add new detection logic; they freeze the empirically
measured locale support of the existing regex/phase-2 detector so that the
`docs/locale-coverage.md` claims are test-backed.  If a detector is improved
for a locale, update the corresponding assertion and the matrix.

Status used in assertions:
- YES  → the expected type is detected today
- PART → detected as a generic / heuristic match (e.g. name without whitelist)
- NO   → not detected by the current pattern set
"""

from __future__ import annotations

import pytest

from privacy_shield.detectors.regex_detector import RegexPIIDetector


@pytest.fixture
def detector():
    return RegexPIIDetector()


# ── Helper: assert that a sample triggers at least one of the listed types ──

def assert_types(detector, text, expected_types, should_match=True):
    found = {m.type for m in detector.scan(text)}
    matched = bool(found & set(expected_types))
    if should_match:
        assert matched, f"Expected one of {expected_types} in {text!r}, got {found}"
    else:
        assert not matched, f"Did not expect {expected_types} in {text!r}, got {found}"


# ── Email: global / RFC 5322 simplified ────────────────────────────────────

@pytest.mark.parametrize("text", [
    "max@example.de",
    "john.doe@example.com",
    "jean.dupont@example.fr",
    "taro.yamada@example.jp",
    "joao.silva@example.br",
    "raj.kumar@example.in",
    "ivan.petrov@example.ru",
])
def test_email_detected_globally(detector, text):
    assert_types(detector, text, ["email"])


# ── IBAN: ISO 13616 + country whitelist ────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("DE89370400440532013000", True),
    ("GB29NWBK60161331926819", True),
    ("FR1420041010050500013M02606", True),
    ("ES9121000418450200051332", True),
    ("IT60X0542811101000000123456", True),
    ("BR1500000000000010932840814P2", True),
])
def test_iban_detected_for_supported_countries(detector, text, expected):
    assert_types(detector, text, ["iban"], should_match=expected)


# ── Phone: very permissive regex, but not universal ──────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("+49 30 1234567", True),          # DE
    ("+1-555-123-4567", True),          # US
    ("+44 20 1234 5678", True),          # UK
    ("+34 91 123 45 67", True),          # ES
    ("+39 06 1234 5678", True),          # IT
    ("+86 138 1234 5678", True),          # CN
    ("+91 98765 43210", True),          # IN
    ("+7 495 123 45 67", True),          # RU
    ("+52 55 1234 5678", True),          # MX
    ("+55 11 1234 5678", True),          # BR
    ("+33 1 23 45 67 89", False),         # FR (2-digit spacing fails)
    ("+81 3 1234 5678", False),           # JP (4-digit block fails)
    ("+82 2 123 4567", False),            # KR (3-digit block fails)
])
def test_phone_detection_per_locale(detector, text, expected):
    assert_types(detector, text, ["phone"], should_match=expected)


# ── Name: Phase-2 heuristic, Latin-only, no accents beyond German umlauts ────

@pytest.mark.parametrize("text,expected,confidence_min", [
    ("Max Mustermann", True, 0.9),     # DE + first-name whitelist
    ("John Smith", True, 0.7),         # US
    ("Jane Smith", True, 0.7),         # UK
    ("Jean Dupont", True, 0.7),        # FR
    ("Mario Rossi", True, 0.7),        # IT
    ("Taro Yamada", True, 0.7),        # JP
    ("Li Wei", True, 0.7),             # CN
    ("Kim Minseo", True, 0.7),         # KR
    ("Raj Kumar", True, 0.7),          # IN
    ("Ivan Petrov", True, 0.7),        # RU
    ("Juan García", False, 0.0),       # ES accent → not matched
    ("João Silva", False, 0.0),        # BR accent → not matched
    ("Carlos Hernández", False, 0.0),  # MX accent → not matched
])
def test_name_detection_per_locale(detector, text, expected, confidence_min):
    matches = [m for m in detector.scan(text) if m.type == "name"]
    if expected:
        assert matches, f"Expected name detection for {text!r}"
        assert matches[0].confidence >= confidence_min
    else:
        assert not matches, f"Did not expect name detection for {text!r}, got {matches}"


# ── Address: German PLZ + city heuristic, fragile internationally ──────────────

@pytest.mark.parametrize("text,expected", [
    ("10115 Berlin", True),            # DE
    ("75001 Paris", True),               # FR
    ("28001 Madrid", True),              # ES
    ("00100 Roma", True),                # IT
    ("01000 Mexico City", True),         # MX
    ("03001 Seoul", True),               # KR (heuristic catches it)
    ("10001 New York", True),            # US (5-digit ZIP heuristic)
    ("SW1A 1AA London", False),          # UK postcode with letters
    ("100-0001 Tokyo", False),           # JP hyphenated format
    ("100000 Beijing", False),           # CN 6-digit + ascii city
    ("110001 New Delhi", False),         # IN 6-digit
    ("101000 Moscow", False),            # RU 6-digit
    ("01001 São Paulo", False),          # BR accent
])
def test_address_detection_per_locale(detector, text, expected):
    assert_types(detector, text, ["address"], should_match=expected)


# ── Tax ID: only German Steuer-ID has dedicated pattern ──────────────────────

@pytest.mark.parametrize("text,expected_types", [
    ("12 345 678 901", {"tax_id"}),                    # DE
    # US SSN is mis-typed as old German tax number today
    ("078-05-1120", {"steuernummer_alt"}),
    # Remaining locales have no dedicated detector
    ("AA123456A", set()),                               # UK NINO
    ("1234567890123", set()),                           # FR TIN
    ("12345678A", set()),                               # ES NIF
    ("RSSMRA80A01H501U", set()),                        # IT CF
    ("ABCDE1234F", set()),                              # IN PAN
    ("ABCD010101A12", set()),                           # MX RFC
    ("123.456.789-09", set()),                          # BR CPF
    ("123456789012", set()),                            # RU INN
])
def test_tax_id_detection_per_locale(detector, text, expected_types):
    found = {m.type for m in detector.scan(text)}
    if expected_types:
        assert found & expected_types, (
            f"Expected one of {expected_types} in {text!r}, got {found}"
        )
    else:
        # Accept that nothing is found; in particular must NOT be tax_id.
        assert "tax_id" not in found, f"Unexpected tax_id match in {text!r}: {found}"


# ── Passport: DE context keywords only ───────────────────────────────────────

@pytest.mark.parametrize("text,expected", [
    ("Reisepass 1234567890", True),
    ("Personalausweis: 12345678", True),
    ("Passport 123456789", False),
    ("Passeport 123456789", False),
    ("Pasaporte 123456789", False),
    ("Passaporto 123456789", False),
])
def test_passport_detection_per_locale(detector, text, expected):
    assert_types(detector, text, ["passport_number"], should_match=expected)


# ── Global patterns: locale independent ──────────────────────────────────────

@pytest.mark.parametrize("text,expected_type", [
    ("4111111111111111", "credit_card"),
    ("10.255.255.1", "ip_address"),
    ("eyJhbG.eyJabc.xyz", "jwt"),
])
def test_global_patterns_work_everywhere(detector, text, expected_type):
    assert_types(detector, text, [expected_type])
