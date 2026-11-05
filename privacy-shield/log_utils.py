"""Detection / confidence / audit-logging helpers for PrivacyShieldPlugin.

Morpheus R5 / FIX-PS-R5-STRUCT: ``PrivacyShieldPlugin`` previously held
~90 LOC of audit-log / confidence-partition / bucketed-counting
plumbing.  These helpers are stateless (or close to it) and belong in
their own module so the plugin class stays focused on the hook
contract.

All functions are designed to be called from instance methods without
state — pass the relevant config / detector / mapping-table as
arguments rather than capturing them via ``self``.  This keeps the
helpers trivially testable (see ``tests/test_struct_extraction.py``)
without spinning up a full :class:`PrivacyShieldPlugin` instance.
"""

from __future__ import annotations

import logging
from typing import Any

# Use the same logger as PrivacyShieldPlugin so existing
# ``caplog.at_level(..., logger="privacy_shield.plugin")`` test
# fixtures still capture these messages.  See R5 test coverage
# parity (test_egress_security.py + test_post_llm_call_output_scanning).
_logger = logging.getLogger("privacy_shield.plugin")


# Magnitude buckets for ``count`` — kept small so the audit log
# never leaks exact PII density.  See R5 review SEC-4 rationale.
def bucket_count(count: int) -> str:
    """Return a magnitude bucket for *count* to avoid exact leaks."""
    if count == 0:
        return "0"
    if count <= 1:
        return "1-1"
    if count <= 10:
        return "1-10"
    if count <= 100:
        return "1-100"
    if count <= 1000:
        return "1-1000"
    return "10000+"


def partition_by_confidence(
    pii_hits: list[Any], threshold: float, overrides: dict[str, float]
) -> tuple[list[Any], list[Any]]:
    """Split PII matches into ``(mask, drop)`` by confidence threshold.

    Per-type overrides in ``overrides`` (cookie_id, *_context, …) win
    over the global ``threshold``.  Default config ships overrides of
    1.0 for cookie_id and the ``*_context`` types so those detections
    surface in the audit log without ever being auto-masked.

    See FIX-4B / Architect NEU-002 for the original motivation.
    """
    masked: list[Any] = []
    dropped: list[Any] = []
    for hit in pii_hits:
        per_type_threshold = overrides.get(hit.type, threshold)
        if hit.confidence >= per_type_threshold:
            masked.append(hit)
        else:
            dropped.append(hit)
    return masked, dropped


def log_detections(mapping: list[dict[str, Any]], session_id: str) -> None:
    """Bucketed audit-log: one entry per call, no raw counts or plaintext.

    Logs a magnitude bucket for the detection count and a small sample
    of PII types (no original values, only type labels).  Prevents an
    attacker from inferring exact PII density through log volume or
    event-timing side channels.
    """
    if not mapping:
        return
    bucket = bucket_count(len(mapping))
    pii_types = list(dict.fromkeys(entry.get("type", "unknown") for entry in mapping))[
        :3
    ]
    _logger.info(
        "Privacy-Shield detections: count_bucket=%s types=%s session=%s",
        bucket,
        pii_types,
        session_id,
    )


def log_dropped_detections(dropped_hits: list[Any], session_id: str) -> None:
    """Log low-confidence detections that were NOT auto-masked.

    Same side-channel-aware bucketing as :func:`log_detections` —
    magnitude bucket + small sample of type labels, no original
    values.  Gives operators visibility into false-positive-prone
    patterns (cookie IDs, health/sensitive context) without leaking
    the matched content.
    """
    if not dropped_hits:
        return
    bucket = bucket_count(len(dropped_hits))
    pii_types = list(dict.fromkeys(hit.type for hit in dropped_hits))[:3]
    _logger.info(
        "Privacy-Shield low-confidence (NOT masked): count_bucket=%s types=%s session=%s",
        bucket,
        pii_types,
        session_id,
    )


__all__ = [
    "bucket_count",
    "log_detections",
    "log_dropped_detections",
    "partition_by_confidence",
]
