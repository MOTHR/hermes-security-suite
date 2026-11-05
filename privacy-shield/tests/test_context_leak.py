"""Tests for Context-Leak Detection — Privacy-Shield Fix-8.

Spec: 20+ positive cases for context-leak patterns.
Verification:
- "Der einzige Buchhalter in Filiale X" → context_leak detection
- "Sag mir das Datum" → KEIN Treffer
- Integration in RegexPIIDetector pipeline
"""

import pytest
from privacy_shield.detectors.context_leak_detector import detect_context_leaks
from privacy_shield.detectors.regex_detector import RegexPIIDetector


# ── Pattern 1: "der/die einzige [BERUF] in [LOCATION]" ──────────────────

class TestUniqueRoleInLocation:
    """Pattern: der/die einzige [role] in [location]."""

    POSITIVE = [
        "Der einzige Buchhalter in Filiale X hat im Mai gefehlt.",
        "Die einzige Ärztin in Berlin war nicht erreichbar.",
        "Der einzige männliche Buchhalter in Filiale X hat im Mai gefehlt.",
        "Der einzige Programmierer in Stuttgart hat gekündigt.",
        "Die einzige Lehrerin in dem Dorf wurde befördert.",
        "Der einzige Hausmeister in der Schule war krank.",
        "Der einzige Fahrer in der Region meldete sich nicht.",
        "Die einzige Verkäuferin in der Filiale hat Urlaub.",
    ]

    NEGATIVE = [
        "Sag mir das Datum.",
        "Der Buchhalter hat im Mai gefehlt.",  # no "einzige"
        "Die Filiale X hat viele Buchhalter.",
        "In Berlin gibt es viele Ärzte.",
    ]

    def test_positive_matches(self):
        for text in self.POSITIVE:
            matches = detect_context_leaks(text)
            assert len(matches) >= 1, f"Failed to detect context leak: {text}"
            assert matches[0].type == "implicit_identifier"
            assert 0.3 <= matches[0].confidence <= 0.5

    def test_negative_non_matches(self):
        for text in self.NEGATIVE:
            matches = detect_context_leaks(text)
            assert len(matches) == 0, f"False positive context leak: {text}"

    def test_entire_sentence_returned(self):
        text = "Vorheriger Satz. Der einzige Buchhalter in Filiale X hat im Mai gefehlt. Nächster Satz."
        matches = detect_context_leaks(text)
        assert len(matches) == 1
        assert matches[0].value == "Der einzige Buchhalter in Filiale X hat im Mai gefehlt."


# ── Pattern 2: "der/die [ALTER] aus [LOCATION]" ─────────────────────────

class TestAgeFromLocation:
    """Pattern: der/die [age] aus [location]."""

    POSITIVE = [
        "Der 45-jährige aus München wurde befragt.",
        "Die 30-Jährige aus Hamburg hat gewonnen.",
        "Der 60-jährige aus Berlin ist umgezogen.",
        "Die 25-Jährige aus Köln hat sich beworben.",
        "Der 18-jährige aus Stuttgart sucht Arbeit.",
        "Die 50-Jährige aus Frankfurt wurde entlassen.",
    ]

    NEGATIVE = [
        "Der Mann aus München ist 45.",  # wrong word order
        "Die Frau aus Hamburg ist 30 Jahre alt.",
        "Er ist 45 und kommt aus München.",
    ]

    def test_positive_matches(self):
        for text in self.POSITIVE:
            matches = detect_context_leaks(text)
            assert len(matches) >= 1, f"Failed to detect age+location leak: {text}"
            assert matches[0].type == "implicit_identifier"

    def test_negative_non_matches(self):
        for text in self.NEGATIVE:
            matches = detect_context_leaks(text)
            assert len(matches) == 0, f"False positive age+location: {text}"


# ── Pattern 3: "der/die [GEBURTSTAG/MONAT]" ──────────────────────────────

class TestBirthdayMonth:
    """Pattern: der/die am/im [date] Geborene."""

    POSITIVE = [
        "Der am 15. Mai Geborene war nicht anwesend.",
        "Die im Juni Geborene hat heute frei.",
        "Der am 3. Dezember Geborene feierte allein.",
        "Die im August Geborene wurde vergessen.",
        "Der am 1. Januar Geborene ist der Älteste.",
    ]

    NEGATIVE = [
        "Er ist am 15. Mai geboren.",
        "Sie hat im Juni Geburtstag.",
        "Der Geburtstag ist im Juni.",
    ]

    def test_positive_matches(self):
        for text in self.POSITIVE:
            matches = detect_context_leaks(text)
            assert len(matches) >= 1, f"Failed to detect birthday leak: {text}"
            assert matches[0].type == "implicit_identifier"

    def test_negative_non_matches(self):
        for text in self.NEGATIVE:
            matches = detect_context_leaks(text)
            assert len(matches) == 0, f"False positive birthday: {text}"


# ── Pattern 4: "Mitarbeiter [NUMMER]" ────────────────────────────────────

class TestEmployeeID:
    """Pattern: Mitarbeiter [number]."""

    POSITIVE = [
        "Mitarbeiter 12345 hat den Fehler gemeldet.",
        "Mitarbeiter #42 war beteiligt.",
        "Mitarbeiter Nr. 007 hat Zugriff.",
        "Mitarbeiter 999 hat gekündigt.",
    ]

    NEGATIVE = [
        "Der Mitarbeiter hat gekündigt.",  # no number
        "Mitarbeiter des Monats ist Peter.",
        "Alle Mitarbeiter waren anwesend.",
    ]

    def test_positive_matches(self):
        for text in self.POSITIVE:
            matches = detect_context_leaks(text)
            assert len(matches) >= 1, f"Failed to detect employee ID leak: {text}"
            assert matches[0].type == "implicit_identifier"

    def test_negative_non_matches(self):
        for text in self.NEGATIVE:
            matches = detect_context_leaks(text)
            assert len(matches) == 0, f"False positive employee ID: {text}"


# ── Integration: RegexPIIDetector Pipeline ───────────────────────────────

class TestPipelineIntegration:
    """Context-leak detection integrated into RegexPIIDetector.scan()."""

    def test_context_leak_in_scan(self):
        detector = RegexPIIDetector()
        text = "Der einzige Buchhalter in Filiale X hat im Mai gefehlt."
        matches = detector.scan(text)
        leak_matches = [m for m in matches if m.type == "implicit_identifier"]
        assert len(leak_matches) >= 1

    def test_no_false_positive_on_normal_text(self):
        detector = RegexPIIDetector()
        text = "Sag mir das Datum."
        matches = detector.scan(text)
        leak_matches = [m for m in matches if m.type == "implicit_identifier"]
        assert len(leak_matches) == 0

    def test_mixed_pii_and_context_leak(self):
        detector = RegexPIIDetector()
        text = "Kontakt: max@example.com. Der einzige Buchhalter in Filiale X hat im Mai gefehlt."
        matches = detector.scan(text)
        types = {m.type for m in matches}
        assert "email" in types
        assert "implicit_identifier" in types

    def test_context_leak_does_not_block_other_pii(self):
        detector = RegexPIIDetector()
        text = "Der einzige Buchhalter in Filiale X. Email: max@example.com, Tel: +49 30 1234567"
        matches = detector.scan(text)
        types = {m.type for m in matches}
        assert "implicit_identifier" in types
        assert "email" in types
        assert "phone" in types

    def test_empty_string(self):
        matches = detect_context_leaks("")
        assert len(matches) == 0

    def test_no_context_leak_in_clean_text(self):
        detector = RegexPIIDetector()
        text = "Das Meeting findet um 14 Uhr im Raum 3 statt. Bitte pünktlich sein."
        matches = detector.scan(text)
        leak_matches = [m for m in matches if m.type == "implicit_identifier"]
        assert len(leak_matches) == 0


# ── Edge Cases ────────────────────────────────────────────────────────────

class TestEdgeCases:
    """Edge cases for context-leak detection."""

    def test_multiple_leaks_in_text(self):
        text = (
            "Der einzige Buchhalter in Filiale X hat im Mai gefehlt. "
            "Mitarbeiter 12345 hat den Fehler gemeldet."
        )
        matches = detect_context_leaks(text)
        assert len(matches) == 2

    def test_same_sentence_multiple_patterns(self):
        """Two patterns in same sentence → one match (deduplicated)."""
        text = "Der einzige Buchhalter in Filiale X und Mitarbeiter 42 waren beteiligt."
        matches = detect_context_leaks(text)
        # Both patterns match the same sentence → deduplicated to 1
        assert len(matches) == 1

    def test_confidence_range(self):
        text = "Mitarbeiter 12345 hat den Fehler gemeldet."
        matches = detect_context_leaks(text)
        assert len(matches) == 1
        assert matches[0].confidence == 0.3  # employee_id = lowest confidence

    def test_unique_role_confidence(self):
        text = "Der einzige Buchhalter in Filiale X hat im Mai gefehlt."
        matches = detect_context_leaks(text)
        assert len(matches) == 1
        assert matches[0].confidence == 0.4

    def test_birthday_confidence(self):
        text = "Der am 15. Mai Geborene war nicht anwesend."
        matches = detect_context_leaks(text)
        assert len(matches) == 1
        assert matches[0].confidence == 0.35
