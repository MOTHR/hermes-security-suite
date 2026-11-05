"""BasePreprocessor — unified interface for attachment pre-processors.

Morpheus R5 MORPH-PS-2: PDF and Image pre-processors previously had
incompatible public surfaces (different return types, no shared base
class), forcing :class:`PrivacyShieldPlugin` to keep two ~80%-duplicate
loops with bespoke error handling.  This module introduces a minimal
abstract base so the AttachmentProcessor can iterate over both
formats without branching per MIME type.

Contract
--------
Every concrete preprocessor MUST expose:

* ``supported_mime_types()`` — frozen set of MIME prefixes the
  pre-processor handles.  ``AttachmentProcessor`` uses this to filter
  attachments before dispatch.
* ``is_supported(path)`` — runtime check (covers extension mismatches,
  e.g. a ``.png`` masquerading as text).  Must be safe to call on
  untrusted paths.
* ``extract(path) -> ExtractionResult`` — return a uniform
  :class:`ExtractionResult` regardless of source format.  Implementers
  adapt their native output (``str`` for PDF, ``OCRResult`` for
  images) into this shape internally.
* ``render_sanitized(original_path, sanitized_text, output_path)`` —
  write a sanitized artifact back to disk for the user.  PDF
  re-renders the text as a new PDF; image writes an underlay of the
  tokenised text on top of the original.

The interface is intentionally narrow: anything that varies between
PDFs and images stays in the concrete class.  ``AttachmentProcessor``
relies on the three public methods above and on the
``ExtractionResult.text`` field only.

Backward compatibility
----------------------
``PDFPreprocessor.extract`` and ``ImagePreprocessor.extract`` keep
their original signatures; the new interface is a thin shim that
calls them.  ``render_sanitized`` is the only new method we add — it
is a near-alias for ``PDFPreprocessor.restore_pdf`` (and the existing
``ImagePreprocessor.render_sanitized``) so existing tests and call
sites continue to work.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BasePreprocessor(ABC):
    """Abstract base class for attachment pre-processors.

    Mirrors the DetectorChain pattern in spirit (uniform contract,
    pluggable concrete implementations) but stays narrower because
    pre-processors only have to produce text and render an artifact.

    The contract intentionally returns the native types (``str`` for
    PDF, ``OCRResult`` for images) so existing call sites are
    unaffected.  The :class:`AttachmentProcessor` uses a thin
    ``extract_text()`` shim (default = ``extract``) to read a uniform
    string without losing the native result object.
    """

    @abstractmethod
    def supported_mime_types(self) -> frozenset[str]:
        """Return the set of MIME-type prefixes this pre-processor handles.

        Examples: ``{"application/pdf"}`` for PDF, ``{"image/jpeg",
        "image/png", "image/heic", ...}`` for the image OCR.
        """

    @abstractmethod
    def is_supported(self, source_path: Path) -> bool:
        """Return True when *source_path* is handled by this pre-processor.

        Used as a runtime guard: a file may carry the right MIME
        header but actually contain a corrupted payload, or an image
        may use a container variant the runtime library cannot decode
        (e.g. HEIC without ``pillow-heif``).  Implementations must be
        cheap — the AttachmentProcessor calls this for every
        attachment.
        """

    @abstractmethod
    def extract(self, source_path: Path, **kwargs: Any) -> Any:
        """Return the native extraction result for *source_path*.

        Implementations catch their own exceptions and surface them as
        :class:`ValueError` (malformed input) or
        :class:`FileNotFoundError` (missing file) so the
        AttachmentProcessor can convert them to the canonical
        :class:`PreprocessorError` without inspecting concrete
        exception types.

        The return type is intentionally ``Any`` because PDF returns
        ``str`` and Image returns :class:`OCRResult`; the
        AttachmentProcessor adapts to a uniform string via
        :meth:`extract_text`.
        """

    def extract_text(self, source_path: Path, **kwargs: Any) -> str:
        """Return just the textual content of *source_path*.

        Default implementation assumes :meth:`extract` returns either a
        ``str`` or an object with a ``.text`` attribute.  Subclasses
        override only when their native shape diverges.
        """
        result = self.extract(source_path, **kwargs)
        if isinstance(result, str):
            return result
        return getattr(result, "text", "") or ""

    @abstractmethod
    def render_sanitized(
        self,
        original_path: Path,
        sanitized_text: str,
        output_path: Path,
    ) -> Path:
        """Write a sanitized artifact for the user and return its path.

        The original file MUST NOT be modified in place — the
        sanitized artifact goes to *output_path* so the round-trip
        remains visible.  Raises ``OSError`` on write failure (caught
        by the AttachmentProcessor and added to the error summary).
        """


__all__ = ["BasePreprocessor"]
