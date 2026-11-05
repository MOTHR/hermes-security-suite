"""Privacy-Shield exception hierarchy.

Morpheus R5 (API-5): the plugin used bare ``PermissionError`` / ``ValueError`` /
``RuntimeError`` for every failure mode, which made it hard for callers to
distinguish between "user-asked for strict mode and we blocked the call" and
"internal misconfiguration".  The new hierarchy gives consumers a single
``PrivacyShieldError`` base class plus a small set of named subclasses for
the three real outcomes: policy enforcement, missing configuration, and
content-shape problems.

The old exceptions (``PermissionError`` etc.) are still raised by call sites
that pre-date this module — the new classes are additive.  ``BaseException``
subclasses are exported through ``__all__`` so plugin consumers can
``except PrivacyShieldError`` in a single branch.

Backward compatibility
----------------------
The new exceptions are *additive*.  All call sites that raised
``PermissionError`` continue to do so for now; new code may either continue
to raise the standard exception or migrate to a named subclass without
breaking downstream handlers.
"""

from __future__ import annotations


class PrivacyShieldError(Exception):
    """Base class for every Privacy-Shield-specific failure.

    Catch this to handle every error the plugin can raise without having to
    list every subclass.
    """


class PolicyViolationError(PrivacyShieldError):
    """The configured policy (strict / paranoid) rejected the request.

    Raised when a non-off mode detects PII and the configured enforcement
    level mandates blocking rather than masking.  Subclasses disambiguate
    between the two enforcement levels.
    """


class StrictModeBlock(PolicyViolationError, PermissionError):
    """Strict-mode policy rejected the call (PII to a non-local provider).

    Inherits from :class:`PermissionError` for backward compatibility
    with callers that catch the standard exception; downstream code
    may also ``except StrictModeBlock`` for fine-grained handling.
    """


class ParanoidModeBlock(PolicyViolationError, PermissionError):
    """Paranoid-mode policy rejected the call (PII to any provider).

    Inherits from :class:`PermissionError` for backward compatibility
    with callers that catch the standard exception.
    """


class MissingKeyError(PrivacyShieldError, RuntimeError):
    """A required secret (e.g. ``PRIVACY_SHIELD_KEY``) was not provided.

    Distinguished from generic ``RuntimeError`` so callers can present a
    user-friendly "run `privacy-shield setup` first" hint.  Inherits
    from :class:`RuntimeError` for backward compatibility with code
    that catches the standard exception.
    """


class PreprocessorError(PrivacyShieldError):
    """A preprocessor (PDF / image OCR) could not handle the input.

    Wraps the underlying ``FileNotFoundError`` / ``ValueError`` so callers
    can write a single ``except PreprocessorError`` to drop the failing
    attachment and fall through to the standard text path.
    """


__all__ = [
    "PrivacyShieldError",
    "PolicyViolationError",
    "StrictModeBlock",
    "ParanoidModeBlock",
    "MissingKeyError",
    "PreprocessorError",
]
