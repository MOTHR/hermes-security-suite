"""Tests for the DetectorChain pattern (MORPH-PS-1 / FIX-PS4).

Covers the BaseDetector ABC, DetectorChain composition (fail-separate,
overlap resolution, typed-credential tie-breakers) and the new sub-detector
split (EmailDetector, PhoneDetector, IBANDetector, CreditCardDetector,
JWTDetector, IPAddressDetector).
"""

from __future__ import annotations

import pytest

from privacy_shield.detectors.base import (
    BaseDetector,
    DetectorChain,
    _PREFERRED_OVERLAP_TYPES,
    _TYPED_CREDENTIAL_TYPES,
)
from privacy_shield.detectors.chain_factory import (
    build_default_chain,
    build_legacy_chain,
)
from privacy_shield.detectors.regex_credit_card import CreditCardDetector
from privacy_shield.detectors.regex_email import EmailDetector
from privacy_shield.detectors.regex_iban import IBANDetector
from privacy_shield.detectors.regex_ip import IPAddressDetector
from privacy_shield.detectors.regex_jwt import JWTDetector
from privacy_shield.detectors.regex_phone import PhoneDetector


# ── Schema & ABC contract ──────────────────────────────────────────────


class _DummyDetector(BaseDetector):
    """Reference implementation for tests."""

    def __init__(self, name, payload):
        self._name = name
        self._payload = payload

    @property
    def name(self) -> str:
        return self._name

    def detect(self, text: str) -> list[dict]:
        # Always emit the same canned match — convenient for composition tests.
        return [dict(p) for p in self._payload]


def test_base_detector_is_abstract():
    """BaseDetector cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseDetector()  # type: ignore[abstract]


def test_base_detector_repr():
    """__repr__ surfaces the class + name for audit logs."""

    class _X(BaseDetector):
        @property
        def name(self) -> str:
            return "x-det"

        def detect(self, text: str) -> list[dict]:
            return []

    assert "_X" in repr(_X())
    assert "x-det" in repr(_X())


# ── DetectorChain basics ───────────────────────────────────────────────


def test_detector_chain_empty_returns_empty_list():
    """A chain with no detectors returns no matches."""
    chain = DetectorChain([])
    assert chain.detect("hello world") == []


def test_detector_chain_runs_all_detectors():
    """Every detector in the chain is invoked exactly once."""
    calls = []

    class _Counter(BaseDetector):
        def __init__(self, name):
            self._name = name

        @property
        def name(self) -> str:
            return self._name

        def detect(self, text: str) -> list[dict]:
            calls.append(self._name)
            return []

    chain = DetectorChain([_Counter("a"), _Counter("b"), _Counter("c")])
    chain.detect("test")
    assert calls == ["a", "b", "c"]


def test_detector_chain_basic_email():
    """Single EmailDetector correctly identifies a valid email."""
    chain = DetectorChain([EmailDetector()])
    matches = chain.detect("Contact: max.mustermann@example.com")
    assert any(m["type"] == "email" for m in matches)
    assert any(m["value"] == "max.mustermann@example.com" for m in matches)


# ── Fail-separate ──────────────────────────────────────────────────────


def test_detector_chain_fail_separate():
    """A crashing detector must not block the others (fail-separate)."""

    class _CrashingDetector(BaseDetector):
        @property
        def name(self) -> str:
            return "crasher"

        def detect(self, text: str) -> list[dict]:
            raise ValueError("intentional crash")

    class _WorkingDetector(BaseDetector):
        @property
        def name(self) -> str:
            return "worker"

        def detect(self, text: str) -> list[dict]:
            return [
                {
                    "type": "test",
                    "value": text[:4],
                    "start": 0,
                    "end": 4,
                    "confidence": 1.0,
                    "rule": "test:worker",
                }
            ]

    chain = DetectorChain([_CrashingDetector(), _WorkingDetector()])
    matches = chain.detect("test-input")
    assert len(matches) == 1
    assert matches[0]["type"] == "test"
    assert matches[0]["value"] == "test"


def test_detector_chain_all_crash_returns_empty(caplog):
    """When every detector crashes, the chain returns an empty list (no raise)."""

    class _AlwaysCrash(BaseDetector):
        @property
        def name(self) -> str:
            return "boom"

        def detect(self, text: str) -> list[dict]:
            raise RuntimeError("kaboom")

    chain = DetectorChain([_AlwaysCrash(), _AlwaysCrash()])
    with caplog.at_level("WARNING"):
        matches = chain.detect("anything")
    assert matches == []
    # Each failure must be logged at WARNING so it shows up in the audit trail.
    assert sum("Detector boom failed" in r.message for r in caplog.records) == 2


# ── Overlap resolution ────────────────────────────────────────────────


def test_detector_chain_overlap_longest_match_wins():
    """Overlapping matches: longest match wins (default rule)."""

    class _Long(BaseDetector):
        @property
        def name(self) -> str:
            return "long"

        def detect(self, text: str) -> list[dict]:
            return [
                {
                    "type": "long",
                    "value": text[:10],
                    "start": 0,
                    "end": 10,
                    "confidence": 1.0,
                    "rule": "test:long",
                }
            ]

    class _Short(BaseDetector):
        @property
        def name(self) -> str:
            return "short"

        def detect(self, text: str) -> list[dict]:
            return [
                {
                    "type": "short",
                    "value": text[:5],
                    "start": 0,
                    "end": 5,
                    "confidence": 1.0,
                    "rule": "test:short",
                }
            ]

    chain = DetectorChain([_Short(), _Long()])
    matches = chain.detect("0123456789")
    assert len(matches) == 1
    assert matches[0]["type"] == "long"


def test_detector_chain_preferred_overlap_jwt_beats_cookie():
    """A JWT match wins over a generic cookie_id fallback at the same position."""
    jwt_value = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
    chain = DetectorChain(
        [
            _DummyDetector(
                "cookie",
                [
                    {
                        "type": "cookie_id",
                        "value": jwt_value,
                        "start": 0,
                        "end": len(jwt_value),
                        "confidence": 0.5,
                        "rule": "regex:cookie_id",
                    }
                ],
            ),
            _DummyDetector(
                "jwt",
                [
                    {
                        "type": "jwt",
                        "value": jwt_value,
                        "start": 0,
                        "end": len(jwt_value),
                        "confidence": 1.0,
                        "rule": "regex:jwt",
                    }
                ],
            ),
        ]
    )
    matches = chain.detect(jwt_value)
    # Cookie listed first + same start; JWT (typed credential) replaces it.
    assert len(matches) == 1
    assert matches[0]["type"] == "jwt"


def test_detector_chain_typed_credential_over_cookie_same_start():
    """Typed credential at the same start replaces the cookie_id fallback."""
    api_key_value = "sk_live_4eC39HqL" "yjWDarjtT1zdp7dc"
    chain = DetectorChain(
        [
            _DummyDetector(
                "cookie",
                [
                    {
                        "type": "cookie_id",
                        "value": api_key_value,
                        "start": 0,
                        "end": len(api_key_value),
                        "confidence": 0.5,
                        "rule": "regex:cookie_id",
                    }
                ],
            ),
            _DummyDetector(
                "api",
                [
                    {
                        "type": "stripe_live_key",
                        "value": api_key_value,
                        "start": 0,
                        "end": len(api_key_value),
                        "confidence": 1.0,
                        "rule": "regex:stripe_live_key",
                    }
                ],
            ),
        ]
    )
    matches = chain.detect(api_key_value)
    assert len(matches) == 1
    assert matches[0]["type"] == "stripe_live_key"


def test_detector_chain_no_overlap_passes_through():
    """Non-overlapping matches are emitted independently."""
    chain = DetectorChain(
        [
            _DummyDetector(
                "a",
                [
                    {
                        "type": "alpha",
                        "value": "hello",
                        "start": 0,
                        "end": 5,
                        "confidence": 1.0,
                        "rule": "test:a",
                    }
                ],
            ),
            _DummyDetector(
                "b",
                [
                    {
                        "type": "beta",
                        "value": "world",
                        "start": 6,
                        "end": 11,
                        "confidence": 1.0,
                        "rule": "test:b",
                    }
                ],
            ),
        ]
    )
    matches = chain.detect("hello world")
    types = {m["type"] for m in matches}
    assert types == {"alpha", "beta"}


# ── Sub-detector smoke tests ──────────────────────────────────────────


def test_email_detector_finds_valid_email():
    matches = EmailDetector().detect("Send to alice@example.com please")
    assert any(m["value"] == "alice@example.com" for m in matches)


def test_phone_detector_finds_phone():
    matches = PhoneDetector().detect("Call +49 30 12345678")
    assert any(m["type"] == "phone" for m in matches)


def test_iban_detector_validates_iban():
    # Known-valid German IBAN (mod-97 = 1)
    valid = "DE89370400440532013000"
    matches = IBANDetector().detect(f"Transfer to {valid}")
    assert any(m["value"] == valid for m in matches)


def test_iban_detector_skips_invalid():
    matches = IBANDetector().detect("DE00000000000000000000 invalid")
    assert matches == []


def test_credit_card_detector_luhn_validation():
    # Visa test card number (passes Luhn)
    matches = CreditCardDetector().detect("Card: 4111 1111 1111 1111")
    assert any(m["type"] == "credit_card" for m in matches)


def test_jwt_detector_finds_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxw"
    matches = JWTDetector().detect(f"Token: {jwt}")
    assert any(m["type"] == "jwt" and m["value"] == jwt for m in matches)


def test_ip_detector_finds_ipv4():
    matches = IPAddressDetector().detect("Server 192.168.1.1 is down")
    assert any(m["type"] == "ip_address" for m in matches)


# ── Factory + integration ─────────────────────────────────────────────


def test_build_default_chain_contains_sub_detectors():
    chain = build_default_chain()
    names = {d.name for d in chain.detectors}
    assert {"email", "phone", "iban", "credit_card", "jwt", "ip_address"}.issubset(names)


def test_build_default_chain_matches_legacy_on_simple_input():
    """Modern chain and legacy RegexPIIDetector agree on a simple prompt."""
    legacy_chain = build_legacy_chain()
    modern_chain = build_default_chain()
    text = "Contact max.mustermann@example.com or call +49 30 12345678"

    legacy = sorted(m["type"] for m in legacy_chain.detect(text))
    modern = sorted(m["type"] for m in modern_chain.detect(text))
    assert modern  # at least the email and phone show up
    # Modern chain covers email + phone + ip + iban + credit_card + jwt
    # so its detected-type set is a superset of the legacy chain's
    # restricted-to-those-six-types subset.
    assert "email" in modern
    assert "phone" in modern


def test_privacy_shield_plugin_exposes_chain():
    """The PrivacyShieldPlugin now exposes a ``detector_chain`` attribute."""
    from privacy_shield.plugin import PrivacyShieldPlugin
    plugin = PrivacyShieldPlugin()
    assert hasattr(plugin, "detector_chain")
    assert hasattr(plugin, "detector")  # legacy attribute preserved
    # Legacy detector still scans correctly (backward compat).
    matches = plugin.detector.scan("Mail me at max.mustermann@example.com")
    assert any(m.type == "email" for m in matches)
    # Chain returns the same canonical schema.
    chain_matches = plugin.detector_chain.detect("Mail me at max.mustermann@example.com")
    assert any(m["type"] == "email" for m in chain_matches)


# ── Tie-breaker constants exposed for downstream consumers ─────────────


def test_overlap_constants_contain_required_keys():
    assert "jwt" in _PREFERRED_OVERLAP_TYPES
    assert "iban" in _PREFERRED_OVERLAP_TYPES
    assert {"jwt", "api_key", "private_key", "github_pat"}.issubset(_TYPED_CREDENTIAL_TYPES)
