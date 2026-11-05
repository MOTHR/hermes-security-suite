"""Detectors package for privacy-shield plugin."""

from .context_leak_detector import detect_context_leaks
from .dataclasses import PIIMatch
from .regex_detector import RegexPIIDetector

# ``PIIMatch`` canonical location is now ``detectors.dataclasses``
# (MORPH-PS-4 lift) but we re-export from here so existing
# ``from privacy_shield.detectors import PIIMatch`` callers keep working.

__all__ = ["RegexPIIDetector", "PIIMatch", "detect_context_leaks"]
