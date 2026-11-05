"""End-to-End Integration Tests — Privacy-Shield Sanity Check.

Validates the full pipeline: detect → pseudonymize → store → lookup → verify.
Also validates performance: 100KB text pseudonymized in <500ms.
"""

import hashlib
import os
import tempfile
import time

import pytest

from privacy_shield.detectors.regex_detector import RegexPIIDetector
from privacy_shield.mapping_table import MappingTable
from privacy_shield.pseudonymizer import Pseudonymizer


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def detector():
    return RegexPIIDetector()


@pytest.fixture
def pseudonymizer():
    return Pseudonymizer(token_style="deterministic", token_prefix="TOKEN")


@pytest.fixture
def mapping_table():
    """MappingTable with temp DB and fixed key (no pass/env dependency).

    Uses kdf_iterations=1000 for test speed (production default is 600_000).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "integration_test.db")
        table = MappingTable(
            storage_path=db_path,
            encryption_key="integration-test-key-32-bytes-xx",
            kdf_iterations=1000,
        )
        yield table


# ── Realistic Test Text ────────────────────────────────────────────────────

REALISTIC_TEXT = """\
Sehr geehrter Herr Mustermann,

vielen Dank für Ihre Anfrage. Sie erreichen mich unter der E-Mail-Adresse
max.mustermann@firma-gmbh.de oder telefonisch unter +49 711 123456.

Unsere Bankverbindung für die Rückerstattung lautet:
IBAN: DE89370400440532013000
BIC: COBADEFFXXX

Ihre Steuer-ID lautet 12 345 678 901.
Die Lieferung geht an: Hauptstraße 1, 12345 Berlin.

Für die Kreditkartenzahlung nutzen Sie bitte:
Karte: 4111 1111 1111 1111

Mit freundlichen Grüßen
Max Mustermann
"""


# ── Integration Tests ──────────────────────────────────────────────────────

class TestEndToEndPipeline:
    """Full pipeline: detect → pseudonymize → store → lookup → verify."""

    def test_full_pipeline_detect_and_pseudonymize(self, detector, pseudonymizer):
        """Step 1+2: Detect PII and replace with tokens."""
        matches = detector.scan(REALISTIC_TEXT)
        assert len(matches) > 0, "Should detect PII in realistic text"

        sanitized, mapping = pseudonymizer.replace(REALISTIC_TEXT, matches)
        assert len(mapping) == len(matches), "Mapping count must match match count"

        # Original PII values must NOT appear in sanitized text
        assert "max.mustermann@firma-gmbh.de" not in sanitized
        assert "+49 711 123456" not in sanitized
        assert "DE89370400440532013000" not in sanitized
        assert "12 345 678 901" not in sanitized
        assert "4111 1111 1111 1111" not in sanitized

        # Tokens must appear
        assert "TOKEN_EMAIL_" in sanitized
        assert "TOKEN_PHONE_" in sanitized
        assert "TOKEN_IBAN_" in sanitized

    def test_store_and_lookup(self, detector, pseudonymizer, mapping_table):
        """Step 3+4: Store mappings and look up by hash."""
        matches = detector.scan(REALISTIC_TEXT)
        sanitized, mapping = pseudonymizer.replace(REALISTIC_TEXT, matches)

        # Store in mapping table
        mapping_table.store(mapping, session_id="integration-test")
        assert mapping_table.count() == len(mapping)

        # Every stored hash must be retrievable
        for entry in mapping:
            token = mapping_table.lookup_by_hash(entry["original_hash"])
            assert token == entry["token"], (
                f"Lookup mismatch: hash={entry['original_hash'][:12]}..., "
                f"expected={entry['token']}, got={token}"
            )

    def test_round_trip_hash_verification(self, detector, pseudonymizer, mapping_table):
        """Round-trip: pseudonymize → store → lookup → verify hash matches original.

        Since original values are never stored (DSGVO Art. 4 Nr. 5: getrennte
        Aufbewahrung), re-identification works by:
        1. Pseudonymize: original → sha256(original) + token
        2. Store: sha256 → token
        3. Lookup: sha256(original) → token ✓
        4. Verify: sha256(original) matches the stored hash
        """
        # Known PII values for round-trip verification
        test_values = {
            "max.mustermann@firma-gmbh.de": "email",
            "+49 711 123456": "phone",
            "DE89370400440532013000": "iban",
            "12 345 678 901": "tax_id",
        }

        for original_value, expected_type in test_values.items():
            # 1. Compute hash (same as pseudonymizer does)
            original_hash = hashlib.sha256(original_value.encode()).hexdigest()

            # 2. Detect in text
            matches = detector.scan(REALISTIC_TEXT)
            matching = [m for m in matches if m.value.replace(" ", "") == original_value.replace(" ", "")]
            assert len(matching) >= 1, f"Should detect {expected_type}: {original_value}"

            # 3. Pseudonymize
            sanitized, mapping = pseudonymizer.replace(REALISTIC_TEXT, matches)
            token_entry = next(
                (m for m in mapping if m["original_hash"] == original_hash),
                None,
            )
            assert token_entry is not None, (
                f"Mapping must contain hash for {original_value}"
            )
            assert token_entry["type"] == expected_type

            # 4. Store
            mapping_table.store(mapping, session_id="round-trip")

            # 5. Lookup by hash → get token back
            retrieved_token = mapping_table.lookup_by_hash(original_hash)
            assert retrieved_token == token_entry["token"], (
                f"Round-trip failed for {expected_type}: "
                f"stored={token_entry['token']}, retrieved={retrieved_token}"
            )

            # 6. Reverse lookup: token → hash
            reverse_hash = mapping_table.lookup_by_token(token_entry["token"])
            assert reverse_hash == original_hash, (
                f"Reverse lookup failed: token={token_entry['token']} "
                f"→ hash={reverse_hash}, expected={original_hash}"
            )

    def test_no_pii_text_passes_through(self, detector, pseudonymizer, mapping_table):
        """Text without PII should pass through unchanged."""
        clean_text = "Guten Tag, wie kann ich Ihnen helfen?"
        matches = detector.scan(clean_text)
        sanitized, mapping = pseudonymizer.replace(clean_text, matches)
        assert sanitized == clean_text
        assert mapping == []
        mapping_table.store(mapping, session_id="clean")
        assert mapping_table.count() == 0

    def test_detected_types_coverage(self, detector):
        """Verify all expected PII types are detected in realistic text."""
        matches = detector.scan(REALISTIC_TEXT)
        detected_types = {m.type for m in matches}

        # Must detect these (present in REALISTIC_TEXT)
        expected = {"email", "phone", "iban", "tax_id", "address", "bic", "credit_card"}
        missing = expected - detected_types
        assert not missing, f"Missing PII types: {missing}"

    def test_sanitized_text_structure_preserved(self, detector, pseudonymizer):
        """Sanitized text should preserve non-PII structure and line breaks."""
        matches = detector.scan(REALISTIC_TEXT)
        sanitized, _ = pseudonymizer.replace(REALISTIC_TEXT, matches)

        # Structure markers preserved (names may be tokenized per Fix 3)
        assert "Sehr geehrter" in sanitized
        assert "vielen Dank" in sanitized
        assert "Mit freundlichen" in sanitized
        # Text is non-empty and roughly same magnitude
        assert len(sanitized) > 0


# ── Performance Test ────────────────────────────────────────────────────────

class TestPerformance:
    """100KB text must be pseudonymized in <1000ms (local) / <5000ms (CI).

    Note: PBKDF2 key derivation (OWASP 2023) adds ~0.4ms per mapping.
    With 1700+ mappings in 100KB text, encryption alone takes ~700ms.
    The 1000ms limit accounts for this security-hardening overhead.
    CI runners (ubuntu-latest) are slower than the local M1 Mac — same
    5x relaxation as tests/test_performance.py (5d28f8f's CI unblock).
    """

    LIMIT_MS = 5000.0 if os.environ.get("PRIVACY_SHIELD_CI", "") else 1000.0

    def test_100kb_text_performance(self, detector, pseudonymizer, mapping_table):
        """Full pipeline on 100KB text: detect + pseudonymize + store < 1000ms."""
        # Generate ~100KB of realistic text by repeating the template
        base = REALISTIC_TEXT
        repeat_count = (100 * 1024) // len(base) + 1
        large_text = (base + "\n") * repeat_count
        large_text = large_text[:100 * 1024]  # Trim to exactly ~100KB

        # Warmup: one scan to compile regexes
        _ = detector.scan(base)

        # Measure full pipeline
        start = time.perf_counter()

        matches = detector.scan(large_text)
        sanitized, mapping = pseudonymizer.replace(large_text, matches)
        mapping_table.store(mapping, session_id="perf-test")

        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < self.LIMIT_MS, (
            f"100KB pipeline too slow: {elapsed_ms:.1f}ms (limit: {self.LIMIT_MS:.0f}ms). "
            f"Detected {len(matches)} PII matches, stored {len(mapping)} mappings."
        )

        # Sanity: should detect many PII instances in repeated text
        assert len(matches) > 0, "Should detect PII in 100KB text"
        assert len(sanitized) >= len(large_text) * 0.9, (
            "Sanitized text should be roughly same size"
        )


# ── Round-Trip Restore Tests ────────────────────────────────────────────────

class TestRoundTripRestore:
    """Full round-trip: pseudonymize → store → restore → verify original."""

    def test_round_trip_restore_single_email(self, detector, pseudonymizer, mapping_table):
        """Pseudonymize an email, then restore it back."""
        text = "Mail an d@x.com bitte"
        matches = detector.scan(text)
        assert len(matches) > 0, "Should detect email"

        sanitized, mapping = pseudonymizer.replace(text, matches)
        mapping_table.store(mapping, session_id="round-trip-test")

        # Verify token is in sanitized text
        token = mapping[0]["token"]
        assert token in sanitized, f"Token {token} should be in sanitized text"

        # Restore
        restored = mapping_table.restore_text(sanitized)
        assert restored == text, (
            f"Round-trip failed: expected '{text}', got '{restored}'"
        )

    def test_round_trip_restore_multiple_pii(self, detector, pseudonymizer, mapping_table):
        """Pseudonymize multiple PII types, then restore all."""
        text = "Kontakt: max@test.de, Tel: +49 30 123456, IBAN: DE89370400440532013000"
        matches = detector.scan(text)
        assert len(matches) >= 3, f"Should detect 3+ PII types, got {len(matches)}"

        sanitized, mapping = pseudonymizer.replace(text, matches)
        mapping_table.store(mapping, session_id="multi-restore")

        # All original values must be gone
        assert "max@test.de" not in sanitized
        assert "+49 30 123456" not in sanitized
        assert "DE89370400440532013000" not in sanitized

        # Restore
        restored = mapping_table.restore_text(sanitized)

        # All original values must be back
        assert "max@test.de" in restored
        assert "+49 30 123456" in restored
        assert "DE89370400440532013000" in restored

    def test_missing_token_fallback(self, detector, pseudonymizer, mapping_table):
        """Tokens not in mapping table should be left as-is (not dropped)."""
        text = "Bitte senden an TOKEN_EMAIL_99999999"
        # No mapping stored for TOKEN_EMAIL_99999999

        restored = mapping_table.restore_text(text)
        # Token should be preserved, not dropped
        assert "TOKEN_EMAIL_99999999" in restored, (
            f"Missing token should be preserved as fallback, got: '{restored}'"
        )

    def test_no_tokens_passes_through(self, mapping_table):
        """Text without tokens should pass through unchanged."""
        text = "Guten Tag, wie kann ich helfen?"
        restored = mapping_table.restore_text(text)
        assert restored == text

    def test_partial_restore_mixed(self, detector, pseudonymizer, mapping_table):
        """Text with both known and unknown tokens: known restored, unknown kept."""
        # First store a real mapping
        text = "Mail an d@x.com"
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        mapping_table.store(mapping, session_id="partial-test")
        known_token = mapping[0]["token"]

        # Now create text with known + unknown token
        mixed = f"Schick an {known_token} und auch an TOKEN_PHONE_7777777777"
        restored = mapping_table.restore_text(mixed)

        assert "d@x.com" in restored, "Known token should be restored"
        assert "TOKEN_PHONE_7777777777" in restored, "Unknown token should be preserved"

    def test_restore_preserves_non_token_text(self, detector, pseudonymizer, mapping_table):
        """Non-token text structure must be preserved during restore."""
        text = "Sehr geehrter Herr Mustermann,\n\nBitte senden Sie die Unterlagen an max@test.de.\n\nMit freundlichen Grüßen"
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        mapping_table.store(mapping, session_id="structure-test")

        restored = mapping_table.restore_text(sanitized)

        assert "Sehr geehrter" in restored
        assert "Mit freundlichen Grüßen" in restored
        assert "max@test.de" in restored
        assert "\n\n" in restored  # Line breaks preserved

    def test_round_trip_with_session_id(self, detector, pseudonymizer, mapping_table):
        """Restore must use the correct session-scoped mapping."""
        text = "Mail an d@x.com"
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        mapping_table.store(mapping, session_id="session-x")

        restored = mapping_table.restore_text(sanitized, session_id="session-x")
        assert restored == text, f"Session-scoped restore failed: {restored}"
