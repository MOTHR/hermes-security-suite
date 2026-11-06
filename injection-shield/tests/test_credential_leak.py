"""Tests for credential leak detector."""

from __future__ import annotations

import pytest
from injection_shield.detectors.credential_leak import CredentialLeakDetector

detector = CredentialLeakDetector()


@pytest.mark.parametrize("text,kind", [
    ("sk-abcDef123Ghi456Jkl7890", "openai_style_key"),
    ("sk-lf-abcdefghijklmnopqrstuvwxyz1234", "langfuse_key"),
    ("AKIAIOSFODNN7EXAMPLE", "aws_access_key"),
    ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc", "bearer_token"),
    ("ghp_1234567890abcdefg" "hijklmnopqrstuvwxyz12", "github_pat"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...", "private_key"),
    ("xoxb-12345" "67890-12345" "67890-abcdefghijklmnop", "slack_token"),
    ("AIzaSyDdI0hCZtE6vyS" "jMm-WEfCJhVjLZhc3gN0", "google_api_key"),
])
def test_detects_credentials(text: str, kind: str) -> None:
    hits = detector.check(text)
    assert hits, f"Expected credential hit for {kind}"
    assert hits[0]["credential_kind"] == kind
    assert hits[0]["severity"] == "critical"


def test_no_false_positives_on_short_strings() -> None:
    assert detector.check("my key is abc") == []
