"""IPAddressDetector — extracted IPv4 / IPv6 sub-detector (FIX-PS4).

Wraps ``regex_detector._IPV4_RE`` and ``_IPV6_RE`` so the standalone
``BaseDetector`` API emits the same canonical dict schema the legacy
:class:`RegexPIIDetector` produces.
"""

from __future__ import annotations

from typing import Any

from .base import BaseDetector
from .regex_detector import _IPV4_RE, _IPV6_RE


class IPAddressDetector(BaseDetector):
    """Detect IPv4 and IPv6 addresses."""

    @property
    def name(self) -> str:
        return "ip_address"

    def detect(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        matches: list[dict[str, Any]] = []
        for pattern in (_IPV4_RE, _IPV6_RE):
            for m in pattern.finditer(text):
                matches.append(
                    {
                        "type": "ip_address",
                        "value": m.group(0),
                        "start": m.start(),
                        "end": m.end(),
                        "confidence": 1.0,
                        "rule": "regex:ip_address",
                    }
                )
        return matches
