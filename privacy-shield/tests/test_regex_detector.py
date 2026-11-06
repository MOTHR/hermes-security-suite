"""Tests for RegexPIIDetector — Phase 1.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 4.3
Requirement: 20+ examples per pattern.
"""

import pytest
from privacy_shield.detectors.regex_detector import RegexPIIDetector, PIIMatch


@pytest.fixture
def detector():
    return RegexPIIDetector()


# ── Email Tests (25 examples) ───────────────────────────────────────────

class TestEmailDetection:
    """Email detection: RFC 5322 simplified."""

    POSITIVE = [
        "max@example.com",
        "john.doe@company.co.uk",
        "user+tag@domain.org",
        "first.last@sub.domain.com",
        "a@b.com",
        "test_user@my-domain.de",
        "support@123.com",
        "name@domain.travel",
        "contact@firma-gmbh.de",
        "max.mustermann@example.com",
        "hermes@agent.one",
        "privacy@shield.io",
        "admin@localhost.local",
        "user%test@example.com",
        "name@domain.museum",
        "hello@world.co",
        "a.b.c@x.y.z.com",
        "test@very-long-domain-name-here.com",
        "user@domain-with-dash.com",
        "first_last@domain.com",
        "name123@domain456.org",
        "u@d.io",
        "email@sub.sub.domain.com",
        "valid@email.co",
    ]

    NEGATIVE = [
        "not-an-email",
        "@missing-local.com",
        "missing-domain@",
        "no@tld",
        "double@@at.com",
        "",
        "just text",
        "user@.com",
        "@.com",
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            assert len(matches) >= 1, f"Failed to detect email: {text}"
            assert matches[0].type == "email"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            email_matches = [m for m in matches if m.type == "email"]
            assert len(email_matches) == 0, f"False positive email: {text}"

    def test_email_in_context(self, detector):
        text = "Contact max@example.com for details."
        matches = detector.scan(text)
        assert len(matches) == 1
        assert matches[0].value == "max@example.com"
        assert matches[0].start == 8

    def test_multiple_emails(self, detector):
        text = "Send to a@b.com and c@d.com"
        matches = detector.scan(text)
        emails = [m for m in matches if m.type == "email"]
        assert len(emails) == 2


# ── Phone Tests (25 examples) ───────────────────────────────────────────

class TestPhoneDetection:
    """Phone detection: DE + international formats."""

    POSITIVE = [
        "+49 30 1234567",
        "+49 30 123 456",
        "030 1234567",
        "030 123 456",
        "030/1234567",
        "+49-30-1234567",
        "+1-555-123-4567",
        "+44 20 1234 5678",
        "0123 456789",
        "0123/456789",
        "0123-456789",
        "+49 711 123456",
        "0711 123456",
        "+49 89 1234567",
        "089 1234567",
        "+49 40 123 456 78",
        "+41 44 123 45 67",
        "+43 1 1234567",
        "+49 1234 56789",
        "01234 56789",
        "+49 30 12345",
        "+49 30 123 45",
        "+49 30 12345678",
        "+49 30 123 456 78",
        "+49 30 123456-78",
    ]

    NEGATIVE = [
        "123",  # too short
        "12345",  # too short
        "abcdefghijk",
        "",
        "just text",
        # FP regression 2026-09-20: an agent's Telegram delivery tokenized
        # "20260920" inside a vault file path (TOKEN_PHONE_a19c5640da_015-...).
        # 8-digit date/id blocks with no separator are not phone numbers.
        "Analyse-File: 03-Market-Analysis/20260920-BTC-Regime-Grid-Analyse-v1.md",
        "20260920-BTC-Regime-Grid-Analyse-v1.md",
        "Report saved: 20260915_140154.md",
        "Run 20260920094438 finished",
        "Session 20260831_081225_e62fd2b4 ended",
        "Commit 48c2aea4aa merged",
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            phone_matches = [m for m in matches if m.type == "phone"]
            assert len(phone_matches) >= 1, f"Failed to detect phone: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            phone_matches = [m for m in matches if m.type == "phone"]
            assert len(phone_matches) == 0, f"False positive phone: {text}"

    def test_phone_in_context(self, detector):
        text = "Rufen Sie +49 30 1234567 an."
        matches = detector.scan(text)
        phone_matches = [m for m in matches if m.type == "phone"]
        assert len(phone_matches) == 1


# ── IP Address Tests (25 examples) ──────────────────────────────────────

class TestIPDetection:
    """IP address detection: v4 + v6."""

    IPV4_POSITIVE = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "1.1.1.1",
        "255.255.255.255",
        "0.0.0.0",
        "127.0.0.1",
        "192.168.178.1",
        "10.10.10.10",
        "172.31.255.255",
        "169.254.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "100.64.0.1",
    ]

    IPV6_POSITIVE = [
        "2001:db8::1",
        "::1",
        "fe80::1",
        "2001:db8:85a3:8d3:1319:8a2e:370:7348",
        "::ffff:192.0.2.1",
        "2001:db8::",
        "2001:db8:0:0:0:0:0:1",
    ]

    NEGATIVE = [
        "256.256.256.256",
        "192.168.1",
        "999.999.999.999",
        "not.an.ip.address",
        "",
    ]

    def test_ipv4_positive(self, detector):
        for text in self.IPV4_POSITIVE:
            matches = detector.scan(text)
            ip_matches = [m for m in matches if m.type == "ip_address"]
            assert len(ip_matches) >= 1, f"Failed to detect IPv4: {text}"

    def test_ipv6_positive(self, detector):
        for text in self.IPV6_POSITIVE:
            matches = detector.scan(text)
            ip_matches = [m for m in matches if m.type == "ip_address"]
            assert len(ip_matches) >= 1, f"Failed to detect IPv6: {text}"

    def test_ip_negative(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            ip_matches = [m for m in matches if m.type == "ip_address"]
            assert len(ip_matches) == 0, f"False positive IP: {text}"

    def test_ip_in_context(self, detector):
        text = "Server at 192.168.1.1 is down."
        matches = detector.scan(text)
        ip_matches = [m for m in matches if m.type == "ip_address"]
        assert len(ip_matches) == 1
        assert ip_matches[0].value == "192.168.1.1"


# ── IBAN Tests (25 examples) ────────────────────────────────────────────

class TestIBANDetection:
    """IBAN detection: DE + EU formats."""

    POSITIVE = [
        "DE89370400440532013000",
        "DE02120300000000202051",
        "DE02500105170137075030",
        "DE12500105170648489890",
        "GB29NWBK60161331926819",
        "FR1420041010050500013M02606",
        "ES9121000418450200051332",
        "IT60X0542811101000000123456",
        "NL91ABNA0417164300",
        "AT611904300234573201",
        "CH9300762011623852957",
        "BE68539007547034",
        "DK5000400440116243",
        "SE4550000000058398257466",
        "PT50000201231234567890154",
        "PL61109010140000071219812874",
        "CZ6508000000192000145399",
        "HU42117730161111101800000000",
        "RO49AAAA1B31007593840000",
        "GR1601101250000000012300695",
        "IE29AIBK93115212345678",
        "FI2112345600000785",
        "LU280019400644750000",
        "NO9386011117947",
        "SA0380000000608010167519",
    ]

    NEGATIVE = [
        "DE89370400440",  # too short (13 chars total, need >=15)
        "1234567890",  # no country prefix
        "not-an-iban",
        "",
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            iban_matches = [m for m in matches if m.type == "iban"]
            assert len(iban_matches) >= 1, f"Failed to detect IBAN: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            iban_matches = [m for m in matches if m.type == "iban"]
            assert len(iban_matches) == 0, f"False positive IBAN: {text}"

    def test_iban_in_context(self, detector):
        text = "Überweisen an DE89370400440532013000 bitte."
        matches = detector.scan(text)
        iban_matches = [m for m in matches if m.type == "iban"]
        assert len(iban_matches) == 1


# ── Tax ID Tests (25 examples) ──────────────────────────────────────────

class TestTaxIDDetection:
    """German Tax ID (Steuer-ID) detection: 11 digits."""

    POSITIVE = [
        "12345678901",
        "12 345 678 901",
        "98 765 432 109",
        "11 111 111 111",
        "99 999 999 999",
        "12345678901",
        "12 345 678 901",
        "55 123 456 789",
        "44 555 666 777",
        "33 444 555 666",
        "22 333 444 555",
        "11 222 333 444",
        "00 111 222 333",
        "99 888 777 666",
        "88 777 666 555",
        "77 666 555 444",
        "66 555 444 333",
        "55 444 333 222",
        "44 333 222 111",
        "33 222 111 000",
        "12 345 678 901",
        "98 765 432 109",
        "11 111 111 111",
        "99 999 999 999",
        "12 345 678 901",
    ]

    NEGATIVE = [
        "1234567890",  # 10 digits
        "123456789012",  # 12 digits
        "abcdefghijk",
        "123 456 789",  # 9 digits
        "",
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            tax_matches = [m for m in matches if m.type == "tax_id"]
            assert len(tax_matches) >= 1, f"Failed to detect tax_id: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            tax_matches = [m for m in matches if m.type == "tax_id"]
            assert len(tax_matches) == 0, f"False positive tax_id: {text}"

    def test_tax_id_in_context(self, detector):
        text = "Steuer-ID: 12 345 678 901 angeben."
        matches = detector.scan(text)
        tax_matches = [m for m in matches if m.type == "tax_id"]
        assert len(tax_matches) == 1


# ── Address Tests (25 examples) ─────────────────────────────────────────

class TestAddressDetection:
    """German address detection: PLZ + city (heuristic)."""

    POSITIVE = [
        "12345 Berlin",
        "10115 Berlin",
        "80331 München",
        "20095 Hamburg",
        "50667 Köln",
        "60311 Frankfurt",
        "70173 Stuttgart",
        "40210 Düsseldorf",
        "04103 Leipzig",
        "01067 Dresden",
        "90402 Nürnberg",
        "30159 Hannover",
        "28203 Bremen",
        "45127 Essen",
        "44135 Dortmund",
        "47051 Duisburg",
        "44787 Bochum",
        "42103 Wuppertal",
        "33602 Bielefeld",
        "53111 Bonn",
        "48143 Münster",
        "76131 Karlsruhe",
        "68159 Mannheim",
        "86150 Augsburg",
        "65183 Wiesbaden",
    ]

    NEGATIVE = [
        "1234 Berlin",  # 4-digit PLZ
        "123456 Berlin",  # 6-digit PLZ
        "ABCDE Berlin",  # non-numeric
        "12345",  # no city
        "",
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            addr_matches = [m for m in matches if m.type == "address"]
            assert len(addr_matches) >= 1, f"Failed to detect address: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            addr_matches = [m for m in matches if m.type == "address"]
            assert len(addr_matches) == 0, f"False positive address: {text}"

    def test_address_in_context(self, detector):
        text = "Lieferung nach 12345 Berlin, Hauptstraße 1."
        matches = detector.scan(text)
        addr_matches = [m for m in matches if m.type == "address"]
        assert len(addr_matches) == 1
        assert addr_matches[0].value == "12345 Berlin"


# ── BIC Tests (8 examples) ───────────────────────────────────────────────

class TestBICDetection:
    """BIC (Business Identifier Code) detection: ISO 9362."""

    POSITIVE = [
        "DEUTDEFF",
        "COBADEFFXXX",
        "BYLADEMM",
        "NWBKGB2L",
        "BARCGB22",
    ]

    NEGATIVE = [
        "DEUTDE",       # too short (6 chars)
        "DEUTDEFFX",    # 9 chars but not valid branch format
        "12345678",     # all digits
        "deutdeff",     # lowercase
        "DEUT DE FF",   # spaces
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            bic_matches = [m for m in matches if m.type == "bic"]
            assert len(bic_matches) >= 1, f"Failed to detect BIC: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            bic_matches = [m for m in matches if m.type == "bic"]
            assert len(bic_matches) == 0, f"False positive BIC: {text}"

    def test_bic_in_context(self, detector):
        text = "BIC: DEUTDEFF für Überweisung."
        matches = detector.scan(text)
        bic_matches = [m for m in matches if m.type == "bic"]
        assert len(bic_matches) == 1
        assert bic_matches[0].value == "DEUTDEFF"


# ── Credit Card Tests (8 examples) ───────────────────────────────────────

class TestCreditCardDetection:
    """Credit card detection: 13-19 digits with Luhn validation."""

    POSITIVE = [
        "4111111111111111",         # Visa (Luhn OK)
        "4111-1111-1111-1111",     # Visa formatted (Luhn OK)
        "5500000000000004",         # Mastercard (Luhn OK)
        "5500-0000-0000-0004",     # Mastercard formatted (Luhn OK)
        "378282246310005",          # Amex (Luhn OK)
        "3782-822463-10005",       # Amex formatted (Luhn OK), 4-6-5 grouping
    ]

    NEGATIVE = [
        "1234567890123456",         # 16 digits, Luhn FAIL
        "1234-5678-9012-3456",     # formatted, Luhn FAIL
        "DE89370400440532013000",   # IBAN (should not match as credit card)
        "1234567890",               # too short (10 digits)
        "12345678901234567890",     # too long (20 digits)
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            cc_matches = [m for m in matches if m.type == "credit_card"]
            assert len(cc_matches) >= 1, f"Failed to detect credit_card: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            cc_matches = [m for m in matches if m.type == "credit_card"]
            assert len(cc_matches) == 0, f"False positive credit_card: {text}"

    def test_credit_card_in_context(self, detector):
        text = "Zahlung mit Visa 4111-1111-1111-1111 erfolgt."
        matches = detector.scan(text)
        cc_matches = [m for m in matches if m.type == "credit_card"]
        assert len(cc_matches) == 1
        assert cc_matches[0].value == "4111-1111-1111-1111"


# ── Cookie-ID / Session-Token Tests (8 examples) ─────────────────────────

class TestCookieIDDetection:
    """Cookie-ID / Session-Token detection: 32-128 alphanumeric chars.

    Confidence: LOW — detection only, not auto-masked.
    """

    POSITIVE = [
        # FIX-5: cookie_id now requires a key=value prefix so that JWTs and
        # other long alphanumeric secrets are not misclassified as cookies.
        "session_id=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",        # 32 chars
        "sid=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",     # 36 chars
        "session=" + "x" * 24,                                  # session=…
        "Set-Cookie: session=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",  # HTTP style
    ]

    NEGATIVE = [
        "short",                                        # 5 chars
        "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5",             # 31 chars (just under 32)
        "not-a-cookie-because-too-short",               # 31 chars with dashes
        "only-twenty-eight-chars-here",                 # 28 chars
        "a",                                            # 1 char
        # FIX-5: bare 32+ char alphanumeric blobs (no key=value prefix) must
        # NOT be classified as cookie_id. They are typically JWT segments or
        # other typed credentials; the cookie pattern now requires a
        # session_id=/sid=/cookie= prefix to avoid swallowing them.
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # JWT signature
        "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF",  # bare 36-char alnum
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            cookie_matches = [m for m in matches if m.type == "cookie_id"]
            assert len(cookie_matches) >= 1, f"Failed to detect cookie_id: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            cookie_matches = [m for m in matches if m.type == "cookie_id"]
            assert len(cookie_matches) == 0, f"False positive cookie_id: {text}"

    def test_cookie_id_in_context(self, detector):
        text = "Set-Cookie: session=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; Path=/"
        matches = detector.scan(text)
        cookie_matches = [m for m in matches if m.type == "cookie_id"]
        assert len(cookie_matches) == 1
        assert cookie_matches[0].value == "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

    def test_cookie_id_emits_low_confidence(self, detector):
        """FIX-4B: cookie_id detection must carry confidence=0.5 so that the
        plugin's confidence-threshold filter can drop it from auto-masking."""
        text = "Set-Cookie: session=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6; Path=/"
        matches = detector.scan(text)
        cookie = [m for m in matches if m.type == "cookie_id"][0]
        assert cookie.confidence == 0.5, (
            f"cookie_id must emit confidence=0.5, got {cookie.confidence}"
        )


class TestContextPatternsEmitLowConfidence:
    """FIX-4B: low-confidence patterns declared in CompiledPattern must
    actually surface their confidence to the caller. Before this fix the
    confidence field on CompiledPattern was silently ignored and all matches
    came out at confidence=1.0.
    """

    def test_salary_context_low_confidence(self, detector):
        matches = detector.scan("Gehalt: 5000 Euro brutto")
        salary = [m for m in matches if m.type == "salary_context"]
        assert salary, "salary_context match expected"
        assert salary[0].confidence == 0.5, (
            f"salary_context must emit confidence=0.5, got {salary[0].confidence}"
        )

    def test_health_context_low_confidence(self, detector):
        matches = detector.scan("Diagnose: Diabetes mellitus")
        health = [m for m in matches if m.type == "health_context"]
        assert health, "health_context match expected"
        assert health[0].confidence == 0.5

    def test_birthday_context_low_confidence(self, detector):
        matches = detector.scan("geboren am 15.03.1985")
        birthday = [m for m in matches if m.type == "birthday_context"]
        assert birthday, "birthday_context match expected"
        assert birthday[0].confidence == 0.5

    def test_high_confidence_types_remain_one(self, detector):
        """email / iban / credit_card / etc. must keep confidence=1.0."""
        for text, expected in (
            ("max.mustermann@example.com", "email"),
            ("DE89370400440532013000", "iban"),
        ):
            matches = detector.scan(text)
            typed = [m for m in matches if m.type == expected]
            assert typed, f"{expected} match expected in {text!r}"
            assert typed[0].confidence == 1.0, (
                f"{expected} must remain confidence=1.0, got {typed[0].confidence}"
            )


# ── IBAN Luhn/Mod97 Validation Tests ─────────────────────────────────────

class TestIBANMod97Validation:
    """IBAN ISO 13616 mod-97 checksum validation.

    Pattern match alone is not enough — the checksum must be valid.
    """

    # Real IBANs with valid checksums (mod97 == 1)
    VALID = [
        "DE89370400440532013000",   # German (canonical test IBAN)
        "DE02120300000000202051",   # German
        "GB29NWBK60161331926819",   # UK
        "FR1420041010050500013M02606",  # French
        "BR1500000000000010932840814P2",  # Brazilian
        "NL91ABNA0417164300",       # Dutch
    ]

    # Strings matching IBAN pattern but with invalid checksums
    INVALID = [
        "DE89ABCDEFGHIJKLMNOPQR",   # Random string, pattern match, mod97 FAIL
        "DE00000000000000000000",   # All zeros, mod97 FAIL
        "GB00NWBK00000000000000",   # UK with zeroed check digits, mod97 FAIL
        "DE12345678901234567890",   # Sequential digits, mod97 FAIL
        "XX00000000000000000000",   # Invalid country code, mod97 FAIL
        "DE89370400440532013001",   # Off-by-one from valid DE IBAN, mod97 FAIL
        "FR00000000000000000000000", # French with zeroed check digits, mod97 FAIL
        "IT00X0542811101000000000000",  # Italian with zeroed check digits, mod97 FAIL
    ]

    def test_valid_ibans_pass_mod97(self, detector):
        for text in self.VALID:
            matches = detector.scan(text)
            iban_matches = [m for m in matches if m.type == "iban"]
            assert len(iban_matches) >= 1, (
                f"Valid IBAN should pass mod97: {text}"
            )

    def test_invalid_ibans_rejected_by_mod97(self, detector):
        for text in self.INVALID:
            matches = detector.scan(text)
            iban_matches = [m for m in matches if m.type == "iban"]
            assert len(iban_matches) == 0, (
                f"Invalid IBAN should be rejected by mod97: {text}"
            )

    def test_iban_in_context_with_mod97(self, detector):
        text = "Konto: DE89370400440532013000 (gültig) oder DE89ABCDEFGHIJKLMNOPQR (ungültig)"
        matches = detector.scan(text)
        iban_matches = [m for m in matches if m.type == "iban"]
        assert len(iban_matches) == 1
        assert iban_matches[0].value == "DE89370400440532013000"


# ── Integration Tests ────────────────────────────────────────────────────

class TestIntegration:
    """Multi-PII detection in realistic texts."""

    def test_mixed_pii_email_phone(self, detector):
        text = "Kontakt: max@example.com, Tel: +49 30 1234567"
        matches = detector.scan(text)
        types = {m.type for m in matches}
        assert "email" in types
        assert "phone" in types

    def test_mixed_pii_ip_iban(self, detector):
        text = "Server: 192.168.1.1, Konto: DE89370400440532013000"
        matches = detector.scan(text)
        types = {m.type for m in matches}
        assert "ip_address" in types
        assert "iban" in types

    def test_no_pii(self, detector):
        text = "Das Wetter ist schön heute."
        matches = detector.scan(text)
        assert len(matches) == 0

    def test_empty_string(self, detector):
        matches = detector.scan("")
        assert len(matches) == 0

    def test_overlap_resolution(self, detector):
        """Overlapping matches: longer match wins."""
        text = "12345 Berlin"
        matches = detector.scan(text)
        # Should detect as address, not as separate tax_id + city
        types = {m.type for m in matches}
        assert "address" in types

    def test_scan_types(self, detector):
        text = "Email max@example.com und IBAN DE89370400440532013000"
        types = detector.scan_types(text)
        assert "email" in types
        assert "iban" in types


# ── Passport Number Tests (10 examples) ──────────────────────────────────

class TestPassportDetection:
    """Passport/Ausweisnummer detection: 8-11 digits, context-disambiguated."""

    POSITIVE = [
        "Reisepass 1234567890",
        "Pass: 98765432101",
        "Ausweisnummer A12345678",
        "Personalausweis: 12345678",
        "Reisepass-Nr. 12345678901",
    ]

    NEGATIVE = [
        "12345678901",  # 11 digits without context → tax_id, not passport
        "Steuer-ID: 12345678901",  # tax_id context
        "1234567",  # too short (7 digits)
        "123456789012",  # too long (12 digits)
        "ABCDEFGHIJ",  # not a number
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            passport_matches = [m for m in matches if m.type == "passport_number"]
            assert len(passport_matches) >= 1, f"Failed to detect passport: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            passport_matches = [m for m in matches if m.type == "passport_number"]
            assert len(passport_matches) == 0, f"False positive passport: {text}"

    def test_tax_id_not_misclassified(self, detector):
        """11-digit number without passport context → tax_id, not passport."""
        text = "Steuer-ID: 12345678901"
        matches = detector.scan(text)
        types = {m.type for m in matches}
        assert "tax_id" in types
        assert "passport_number" not in types

    def test_passport_in_context(self, detector):
        text = "Bitte geben Sie Ihre Reisepass-Nummer 1234567890 an."
        matches = detector.scan(text)
        passport_matches = [m for m in matches if m.type == "passport_number"]
        assert len(passport_matches) == 1
        assert passport_matches[0].value == "1234567890"

    def test_passport_keyword_within_50_chars(self, detector):
        """Keyword within 50 chars triggers passport detection."""
        # Use spaces to avoid cookie_id overlap (alphanumeric string > 32 chars)
        text = "Ausweis" + " " * 43 + "12345678"
        matches = detector.scan(text)
        passport_matches = [m for m in matches if m.type == "passport_number"]
        assert len(passport_matches) == 1


# ── VAT ID Tests (8 examples) ────────────────────────────────────────────

class TestVATDetection:
    """VAT ID detection: DE + EU formats."""

    POSITIVE = [
        "DE123456789",
        "ATU12345678",
        "FR12345678901",
        "IT12345678901",
        "ESX12345678",
    ]

    NEGATIVE = [
        "DE12345678",  # too short (8 digits after DE)
        "XX123456789",  # invalid country code pattern (XX not a real VAT prefix)
        "123456789",  # no country prefix
    ]

    def test_positive_matches(self, detector):
        for text in self.POSITIVE:
            matches = detector.scan(text)
            vat_matches = [m for m in matches if m.type in ("vat_id_de", "vat_id_eu")]
            assert len(vat_matches) >= 1, f"Failed to detect VAT: {text}"

    def test_negative_non_matches(self, detector):
        for text in self.NEGATIVE:
            matches = detector.scan(text)
            vat_matches = [m for m in matches if m.type in ("vat_id_de", "vat_id_eu")]
            assert len(vat_matches) == 0, f"False positive VAT: {text}"

    def test_vat_de_in_context(self, detector):
        text = "USt-IdNr: DE123456789 für die Rechnung."
        matches = detector.scan(text)
        vat_matches = [m for m in matches if m.type == "vat_id_de"]
        assert len(vat_matches) == 1
        assert vat_matches[0].value == "DE123456789"

    def test_vat_eu_in_context(self, detector):
        text = "VAT: ATU12345678 aus Österreich."
        matches = detector.scan(text)
        vat_matches = [m for m in matches if m.type == "vat_id_eu"]
        assert len(vat_matches) == 1
        assert vat_matches[0].value == "ATU12345678"


# ── Explainability (rule field) Tests ────────────────────────────────────

class TestExplainabilityRule:
    """PIIMatch.rule field provides explainability for each detection."""

    def test_regex_email_has_rule(self, detector):
        matches = detector.scan("max@example.com")
        assert len(matches) == 1
        assert matches[0].rule == "regex:email"

    def test_regex_phone_has_rule(self, detector):
        matches = detector.scan("+49 30 1234567")
        phone_matches = [m for m in matches if m.type == "phone"]
        assert len(phone_matches) >= 1
        assert phone_matches[0].rule == "regex:phone"

    def test_regex_ip_has_rule(self, detector):
        matches = detector.scan("192.168.1.1")
        ip_matches = [m for m in matches if m.type == "ip_address"]
        assert len(ip_matches) >= 1
        assert ip_matches[0].rule == "regex:ip_address"

    def test_regex_iban_has_rule(self, detector):
        matches = detector.scan("DE89370400440532013000")
        iban_matches = [m for m in matches if m.type == "iban"]
        assert len(iban_matches) >= 1
        assert iban_matches[0].rule == "regex:iban"

    def test_name_whitelist_has_rule(self, detector):
        matches = detector.scan("Max Mustermann")
        name_matches = [m for m in matches if m.type == "name"]
        assert len(name_matches) >= 1
        assert "firstname_whitelist" in name_matches[0].rule

    def test_context_leak_has_rule(self, detector):
        text = "der einzige Buchhalter in Filiale X"
        matches = detector.scan(text)
        leak_matches = [m for m in matches if m.type == "implicit_identifier"]
        assert len(leak_matches) >= 1
        assert leak_matches[0].rule.startswith("context_leak:")

    def test_rule_field_default_empty(self):
        """PIIMatch default rule is empty string."""
        from privacy_shield.detectors.regex_detector import PIIMatch
        m = PIIMatch(type="test", value="x", start=0, end=1)
        assert m.rule == ""
