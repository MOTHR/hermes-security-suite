"""Detectors package — defense-layer components for injection-shield.

ARCH-1 (FIX-2D) — every defense layer is now a standalone
:class:`BaseDetector` that can be composed via :class:`DetectorChain`.
The legacy class names (``InjectionPatternDetector``,
``ZeroWidthDetector``, ``CredentialLeakDetector``) are still exported
for backwards compatibility with the existing test suite.
"""

from __future__ import annotations

from .base import BaseDetector, DetectorChain
from .content_tagger import ContentTagger, is_untrusted_source
from .credential_leak import CredentialLeakDetector
from .css_concealment import CssConcealmentDetector  # re-export: chain layer

__all__ = [
    "ContentTagger",
    "CredentialLeakDetector",
    "CssConcealmentDetector",
    "DetectorChain",
    "InjectionPatternDetector",
    "InstructionFirewall",
    "OutputValidator",
    "ToolCallPatternDetector",
    "ZeroWidthDetector",
    "is_untrusted_source",
]
from .injection_patterns import InjectionPatternDetector
from .instruction_firewall import InstructionFirewall
from .output_validator import OutputValidator
from .tool_call_patterns import ToolCallPatternDetector
from .zero_width import ZeroWidthDetector

__all__ = [
    "BaseDetector",
    "ContentTagger",
    "CredentialLeakDetector",
    "DetectorChain",
    "InjectionPatternDetector",
    "InstructionFirewall",
    "OutputValidator",
    "ToolCallPatternDetector",
    "ZeroWidthDetector",
    "is_untrusted_source",
]
