"""Factory for the default :class:`DetectorChain` used by the PrivacyShieldPlugin.

MORPH-PS-1 (FIX-PS4): PrivacyShieldPlugin previously constructed a single
monolithic ``RegexPIIDetector``.  This module exposes the modernised pipeline
— a :class:`DetectorChain` composed of independent :class:`BaseDetector`
sub-detectors that delegate to the legacy regex helpers.  Adding new
detectors (ML/NER, custom heuristics) now requires only registering another
``BaseDetector`` instance in ``build_default_chain`` below.

The legacy ``RegexPIIDetector`` is preserved as a thin compatibility shim
(see ``build_legacy_chain``) so external code can opt back into the
pre-MORPH-PS-1 behaviour without import changes.
"""

from __future__ import annotations

from .base import BaseDetector, DetectorChain
from .regex_credit_card import CreditCardDetector
from .regex_email import EmailDetector
from .regex_iban import IBANDetector
from .regex_ip import IPAddressDetector
from .regex_jwt import JWTDetector
from .regex_phone import PhoneDetector


def build_default_chain() -> DetectorChain:
    """Construct the default Privacy-Shield detector pipeline.

    Order matches the legacy ``RegexPIIDetector`` priority: most specific
    (typed credentials) first, broader fallbacks last.  The chain resolves
    overlaps via the same longest-match-wins rules used by the legacy
    detector — see :data:`DetectorChain._PREFERRED_OVERLAP_TYPES` and
    :data:`DetectorChain._TYPED_CREDENTIAL_TYPES`.
    """
    detectors: list[BaseDetector] = [
        IPAddressDetector(),
        IBANDetector(),
        CreditCardDetector(),
        JWTDetector(),
        EmailDetector(),
        PhoneDetector(),
    ]
    return DetectorChain(detectors)


def build_legacy_chain(code_context_penalty: float = 1.0) -> DetectorChain:
    """Wrap the legacy monolithic :class:`RegexPIIDetector` as a single
    ``BaseDetector`` inside a chain.

    Preserved for backward compatibility with code that depends on the
    full Phase-4 pattern list (47 patterns, code-context penalty, base64
    heuristic, BIP39 sweep, context-leak detector, etc.).  New code should
    prefer :func:`build_default_chain`.
    """
    from .regex_detector import RegexPIIDetector
    from .regex_adapter import LegacyRegexDetectorAdapter

    legacy = RegexPIIDetector(code_context_penalty=code_context_penalty)
    return DetectorChain([LegacyRegexDetectorAdapter(legacy)])


__all__ = [
    "build_default_chain",
    "build_legacy_chain",
]
