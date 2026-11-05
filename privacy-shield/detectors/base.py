"""DetectorChain — Base class + chain-of-responsibility for privacy detectors.

Morpheus R5 MORPH-PS-1 (FIX-PS4): Privacy-Shield lacked a formal DetectorChain
pattern.  This module introduces:

* :class:`BaseDetector` — abstract base class every privacy detector inherits
  from.  Mirrors the Injection-Shield FIX-2D design so both shields expose
  the same extension point.
* :class:`DetectorChain` — runs detectors in priority order, isolates failures
  (fail-separate), and resolves overlapping matches using longest-match-wins
  with a small set of typed-credential tie-breakers.

Backward compatibility: the original monolithic
``RegexPIIDetector.scan()`` is preserved unchanged.  Plugin code can opt into
the chain pattern via ``PrivacyShieldPlugin.detector_chain``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Iterable


_logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Abstract base class for all Privacy-Shield PII detectors.

    A detector consumes a string of text and returns a list of match dicts
    using the canonical schema::

        {
            "type":       str,    # e.g. "email", "phone", "jwt"
            "value":      str,    # the matched text
            "start":      int,    # character offset in original text
            "end":        int,    # character offset (exclusive)
            "confidence": float,  # 0.0..1.0 (regex ≈ 1.0, heuristic < 1.0)
            "rule":       str,    # explainability tag, e.g. "regex:email"
        }
    """

    @abstractmethod
    def detect(self, text: str) -> list[dict[str, Any]]:
        """Return all PII matches in *text* (empty list when none found)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short detector identifier used in audit logs and telemetry."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.__class__.__name__} name={self.name}>"


# ── Overlap resolution tie-breakers ────────────────────────────────────

# A small set of high-specificity types that MUST win over broader patterns
# (e.g. an explicit JWT match must not be downgraded to a generic API-key
# fallback just because the latter is longer).
_PREFERRED_OVERLAP_TYPES: frozenset[str] = frozenset({"jwt", "iban"})

# Typed credentials (api_key, jwt, …) win over a generic ``cookie_id``
# fallback when both start at the same position.
_TYPED_CREDENTIAL_TYPES: frozenset[str] = frozenset({
    "jwt",
    "api_key",
    "stripe_live_key",
    "stripe_test_key",
    "stripe_public_key",
    "stripe_restricted_key",
    "stripe_webhook_secret",
    "github_pat",
    "github_fine_grained_pat",
    "google_api_key",
    "google_oauth",
    "github_oauth",
    "azure_sas",
    "database_url",
    "auth_bearer",
    "private_key",
    "telegram_bot_token",
    "discord_webhook",
    "slack_webhook",
    "slack_token",
    "aws_access_key",
    "npm_token",
    "pypi_token",
    "docker_hub_pat",
    "heroku_api_key",
})


class DetectorChain:
    """Run a list of :class:`BaseDetector` instances with safe composition.

    * **Fail-separate**: a crashing detector is logged but does not prevent
      the remaining detectors from running.  This is critical for production
      deployments where one buggy heuristic (e.g. an ML/NER pipeline) must
      not silently disable all PII detection.
    * **Longest-match-wins**: overlapping matches are resolved by length;
      a small set of *typed credential* types additionally breaks ties in
      favour of the more specific match — mirroring the legacy
      ``RegexPIIDetector.scan()`` rules so behavioural compatibility is
      preserved.
    """

    def __init__(self, detectors: Iterable[BaseDetector]):
        self.detectors: list[BaseDetector] = list(detectors)

    def detect(self, text: str) -> list[dict[str, Any]]:
        """Run every detector, fail-separate, then resolve overlaps."""
        all_matches: list[dict[str, Any]] = []
        for detector in self.detectors:
            try:
                matches = detector.detect(text)
            except Exception as exc:  # noqa: BLE001 - intentional fail-separate
                _logger.warning(
                    "Detector %s failed: %s", getattr(detector, "name", repr(detector)), exc,
                )
                continue
            if matches:
                all_matches.extend(matches)
        return self._resolve_overlaps(all_matches)

    # ── overlap resolution ─────────────────────────────────────────────

    @staticmethod
    def _resolve_overlaps(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Resolve overlapping matches using longest-match-wins.

        Tie-breakers (matching the legacy ``RegexPIIDetector.scan()``):
          * ``_PREFERRED_OVERLAP_TYPES`` (jwt, iban) win over a broader
            fallback even when the broader match is longer.
          * When two matches start at the same position and the previous
            one is ``cookie_id`` while the new one is a typed credential,
            the typed credential wins.
        """
        if not matches:
            return []

        # Sort by (start asc, length desc) — same key as the legacy detector.
        matches = sorted(
            matches,
            key=lambda m: (m["start"], -(m["end"] - m["start"])),
        )

        resolved: list[dict[str, Any]] = []
        for match in matches:
            if not resolved:
                resolved.append(match)
                continue
            prev = resolved[-1]
            if match["start"] >= prev["end"]:
                # No overlap.
                resolved.append(match)
            elif (
                match["type"] in _PREFERRED_OVERLAP_TYPES
                and prev["type"] not in _PREFERRED_OVERLAP_TYPES
            ):
                # More specific type wins even when shorter.
                resolved[-1] = match
            elif (
                match["start"] == prev["start"]
                and prev["type"] == "cookie_id"
                and match["type"] in _TYPED_CREDENTIAL_TYPES
            ):
                # Same start, typed credential replaces cookie_id fallback.
                resolved[-1] = match
            # Otherwise: longest-match-wins is the default and applies.

        return resolved


__all__ = [
    "BaseDetector",
    "DetectorChain",
    "_PREFERRED_OVERLAP_TYPES",
    "_TYPED_CREDENTIAL_TYPES",
]
