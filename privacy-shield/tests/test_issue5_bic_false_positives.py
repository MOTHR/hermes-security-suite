"""Issue #5 regression tests — BIC detector false positives + ISO 9362 validation.

Issue: https://github.com/MOTHR/hermes-security-suite/issues/5
Privacy-Shield 1.9.3 matched ``_BIC_RE`` against any 8/11-char uppercase
token: 83% of the masks in the reported session were BIC false positives.

Fix contract (ISO 9362):

(a) strict 8 or 11 characters,
(b) positions 5-6 must be an ISO 3166-1 alpha-2 country code,
(c) optional, operator-configurable context cues (SWIFT/BIC/IBAN).

TEST-FIRST: the ISSUE-5 baseline cases in TestIssue5BICFalsePositives were
written against the released 1.9.3 behaviour and fail before the fix.
"""

import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.detectors.regex_detector import RegexPIIDetector


# The exact ten words from the Issue reproduction: every one is an 8-char
# uppercase word, none is a bank identifier code.
ISSUE5_BASELINE_WORDS = [
    "WORKFLOW",
    "SHUTDOWN",
    "DATABASE",
    "PASSWORD",
    "CONTINUE",
    "DOWNLOAD",
    "CATEGORY",
    "PLATFORM",
    "SETTINGS",
    "RESPONSE",
]

# Words masked in the delegated-transit evidence (Issue #5 comment):
# "STRONG REVIEWER", "ASYNC DELEGATION BATCH COMPLETE".
ISSUE5_TRANSIT_WORDS = ["REVIEWER", "COMPLETE"]


@pytest.fixture
def detector():
    return RegexPIIDetector()


@pytest.fixture
def bic_cue_detector():
    """Detector with context cues enabled (operator opt-in)."""
    return RegexPIIDetector(bic_context_cues=("BIC", "SWIFT", "IBAN"))


class TestIssue5BICFalsePositives:
    """Regression: ordinary uppercase words must never mask as BIC."""

    def test_issue5_baseline_ten_words(self, detector):
        for word in ISSUE5_BASELINE_WORDS:
            matches = [m for m in detector.scan(word) if m.type == "bic"]
            assert matches == [], f"False positive BIC for {word!r}"

    def test_issue5_transit_role_labels(self, detector):
        text = "ASYNC DELEGATION BATCH COMPLETE — STRONG REVIEWER"
        matches = [m for m in detector.scan(text) if m.type == "bic"]
        assert matches == [], "Role labels must not mask as BIC (Issue #5 comment)"

    def test_issue5_session_audit_line(self, detector):
        """Line quoted from the corrupted subagent result in Issue #5."""
        text = "line 117 of STRONG REVIEWER: fix applied"
        matches = [m for m in detector.scan(text) if m.type == "bic"]
        assert matches == []

    def test_issue5_realistic_text_now_clean(self, detector):
        """Multi-word uppercase prose without BIC context: zero bic masks."""
        text = "WORKFLOW SHUTDOWN PASSWORD REVIEWER"
        matches = [m for m in detector.scan(text) if m.type == "bic"]
        assert matches == []

    def test_issue5_baseline_count_in_mixed_text(self, detector):
        """83%-FP-baseline: 10 false-positive words in a config discussion."""
        text = " ".join(ISSUE5_BASELINE_WORDS)
        matches = [m for m in detector.scan(text) if m.type == "bic"]
        assert matches == [], "All 10 baseline words must be below FP threshold"


    def test_swift_code_extended_type_also_validated(self, detector):
        """The extended patterns emit the same loose regex as type
        'swift_code'; the ISO 9362 gate must cover that path too (found via
        the delegated-transit sanitizer flow)."""
        text = "BATCH COMPLETE STRONG REVIEWER"
        matches = [
            m for m in detector.scan(text)
            if m.type in ("bic", "swift_code")
        ]
        assert matches == []


class TestIssue5BICTruePositives:
    """Fix must not suppress genuine ISO 9362 BICs."""

    @pytest.mark.parametrize(
        "bic,expected",
        [
            ("DEUTDEFF", 8),          # DE — Germany
            ("COBADEFF", 8),          # DE — Commerzbank
            ("DEUTDEFF500", 11),      # DE — 11-char with branch code
            ("CHASUS33XXX", 11),      # US — Chase
            ("BNPAFRPP", 8),          # FR — BNP Paribas
            ("MIDLGB22XXX", 11),      # GB — HSBC
            ("BYLADEMM", 8),          # AT? BY — Belarusbank (BY)
            ("NWBKGB2L", 8),          # GB
        ],
    )
    def test_real_bics_still_match(self, detector, bic, expected):
        matches = [m for m in detector.scan(bic) if m.type == "bic"]
        assert matches, f"Real BIC {bic!r} masked away by the fix"
        assert matches[0].value == bic


class TestIssue5BICStrictShape:
    """ISO 9362 structural rules the loose regex never enforced."""

    def test_invalid_country_suffix_rejected(self, detector):
        # "WORKFLOW": positions 5-6 are "LO" — not a country code.
        matches = [m for m in detector.scan("WORKFLOW") if m.type == "bic"]
        assert matches == []

    def test_wrong_length_rejected(self, detector):
        for bogus in ("DEUTDEFF5", "DEUTDEFF50", "DEUTDEFF5000"):
            matches = [m for m in detector.scan(bogus) if m.type == "bic"]
            assert matches == [], f"Length-invalid {bogus!r} must not match"

    def test_country_slot_validation_is_real_country(self, detector):
        # Valid shape, but "QQ" is an unassigned ISO 3166 alpha-2 code.
        matches = [m for m in detector.scan("DEUTQQFF") if m.type == "bic"]
        assert matches == []


class TestIssue5BICContextCues:
    """Fix (c): operator-configurable context cues."""

    def test_cue_mode_requires_cue(self, bic_cue_detector):
        text = "Payment will route via DEUTDEFF tomorrow."
        matches = [m for m in bic_cue_detector.scan(text) if m.type == "bic"]
        assert matches == [], "Without a cue, BIC match must be dropped in cue mode"

    def test_cue_mode_accepts_bic_label(self, bic_cue_detector):
        text = "BIC: DEUTDEFF"
        matches = [m for m in bic_cue_detector.scan(text) if m.type == "bic"]
        assert matches and matches[0].value == "DEUTDEFF"

    def test_cue_mode_accepts_swift_label(self, bic_cue_detector):
        text = "Please send the SWIFT code DEUTDEFF500."
        matches = [m for m in bic_cue_detector.scan(text) if m.type == "bic"]
        assert matches and matches[0].value == "DEUTDEFF500"

    def test_cue_mode_accepts_iban_line(self, bic_cue_detector):
        """IBAN nearby in the same window keeps the BIC match."""
        text = "IBAN DE89370400440532013000 BIC DEUTDEFF"
        matches = [m for m in bic_cue_detector.scan(text) if m.type == "bic"]
        assert matches and matches[0].value == "DEUTDEFF"

    def test_cue_mode_case_insensitive(self, bic_cue_detector):
        text = "swift: DEUTDEFF"
        matches = [m for m in bic_cue_detector.scan(text) if m.type == "bic"]
        assert matches and matches[0].value == "DEUTDEFF"

    def test_default_detector_has_no_cue_gate(self, detector):
        """Cues default to disabled: country-code validation is the only gate."""
        config = PrivacyShieldConfig()
        assert config.bic_context_cues == ()

    def test_config_field_exists_for_yaml_override(self):
        config = PrivacyShieldConfig(bic_context_cues=("SWIFT",))
        assert "SWIFT" in config.bic_context_cues


class TestIssue5BICRegexShape:
    """The raw _BIC_RE must only emit 8/11-char candidates (fix (a))."""

    def test_regex_candidate_lengths(self):
        from privacy_shield.detectors import regex_detector as rd

        for candidate in rd._BIC_RE.finditer("WORKFLOWX REVIEWER2 DEUTDEFF DEUTDEFF500"):
            token = candidate.group(0)
            assert len(token) in (8, 11), token
