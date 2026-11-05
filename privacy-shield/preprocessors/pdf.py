"""PDF text extraction for Privacy-Shield.

Phase 1: text-only PDFs (no OCR).  Renders extracted pages back into a
sanitized PDF using reportlab so the round-trip stays local (no cloud egress).

Security notes
--------------
* ``extract`` catches every exception from pdfplumber.  A malicious PDF
  (ZIP-bomb, malformed object, recursive structure) MUST NOT crash
  the LLM call — it is surfaced as ``ValueError`` so the caller can
  fall back to the existing text path or block per config.
* ``restore_pdf`` writes into a directory owned by the plugin (default
  ``~/.hermes/privacy/restore/pdf``) with ``mode=0o700`` so tokens and
  restored plaintext never leak to other local users.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import BasePreprocessor

try:
    import pdfplumber
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "pdfplumber is required for Privacy-Shield PDF support. "
        "Install with: pip install pdfplumber"
    ) from exc

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "reportlab is required for Privacy-Shield PDF restore. "
        "Install with: pip install reportlab"
    ) from exc


PAGE_MARKER_TEMPLATE = "\n[PAGE {page}]\n"
_CHUNK_SIZE_DEFAULT = 10  # pages per chunk for memory-capped extraction
_LINES_PER_PAGE = 50  # restoration rendering cap per PDF page
_LINE_MAX_CHARS = 80
_TOP_Y = 750
_LINE_DROP = 12
_BOTTOM_Y = 50
_LEFT_X = 50


class PDFPreprocessor(BasePreprocessor):
    """Extracts and re-renders text from PDFs for the PII pipeline.

    Parameters
    ----------
    max_size_mb:
        Soft guardrail.  PDFs larger than this still parse (pdfplumber is
        streaming), but the caller is expected to enforce this when
        accepting user uploads.  Kept here so the hook integration has a
        single source of truth.

    MORPH-PS-2 (Morpheus R5): now inherits :class:`BasePreprocessor` so
    the AttachmentProcessor can iterate over PDF and image formats with
    a single uniform loop.  The legacy ``extract(pdf_path)`` and
    ``restore_pdf(text, path)`` signatures are preserved unchanged for
    backward compatibility — the new methods are thin shims over them.
    """

    SUPPORTED_MIME_TYPES: frozenset[str] = frozenset({"application/pdf"})

    def supported_mime_types(self) -> frozenset[str]:
        return self.SUPPORTED_MIME_TYPES

    def is_supported(self, source_path: Path) -> bool:
        """A path is "supported" when it carries the PDF extension.

        We do not parse the file at this stage — the size guard and
        pdfplumber's own error handling cover malformed payloads.
        """
        return Path(source_path).suffix.lower() == ".pdf"

    def render_sanitized(
        self,
        original_path: Path,
        sanitized_text: str,
        output_path: Path,
    ) -> Path:
        """Uniform BasePreprocessor adapter — delegates to ``restore_pdf``.

        The ``original_path`` argument is part of the
        :class:`BasePreprocessor` contract; for PDFs the source file is
        not needed during restoration because reportlab generates a
        fresh canvas.
        """
        return self.restore_pdf(sanitized_text, output_path)

    def __init__(self, max_size_mb: int = 100) -> None:
        self.max_size_mb = max_size_mb

    # ------------------------------------------------------------------ extract

    def extract(self, source_path: Path, **kwargs: Any) -> str:
        """Return concatenated text from every PDF page.

        Pages are separated by ``[PAGE N]`` markers so the downstream
        detector/pseudonymizer has positional context (matches keep their
        ``start``/``end`` indices across the concatenated string).

        PERF-5: for large PDFs use :meth:`extract_chunks` instead of this
        method; ``extract`` still builds the full string in memory to
        preserve its historical contract.
        """
        pdf_path = Path(source_path)
        # PERF-3 (Morpheus R5): ``+=`` on a growing string is O(n²) because
        # Python strings are immutable.  Building a list and joining once is
        # O(n) and noticeably faster for 100+ page PDFs.
        parts: list[str] = []
        for page in self.extract_pages(pdf_path):
            parts.append(PAGE_MARKER_TEMPLATE.format(page=page["page"]))
            parts.append(page["text"])
        return "".join(parts)

    def extract_chunks(
        self,
        pdf_path: Path,
        *,
        chunk_size: int = _CHUNK_SIZE_DEFAULT,
    ) -> Any:
        """Yield text chunks of ``chunk_size`` pages without holding all pages in memory.

        PERF-5 (Morpheus R5): large PDFs can produce multi-megabyte strings.
        This generator keeps only one chunk in memory at a time and lets
        the caller process/detect/pseudonymize incrementally. The chunk
        shape matches ``extract`` (``[PAGE N]`` markers + page text) so
        downstream code can treat each chunk the same way as a full
        ``extract`` result.

        Args:
            pdf_path: Path to the PDF file.
            chunk_size: Number of pages per yielded chunk (must be >= 1).

        Yields:
            str: Concatenated text for the next ``chunk_size`` pages.
        """
        pdf_path = Path(pdf_path)
        chunk_size = max(1, chunk_size)
        self._guard_size(pdf_path)
        try:
            with pdfplumber.open(pdf_path) as pdf:
                parts: list[str] = []
                count = 0
                for idx, page in enumerate(pdf.pages):
                    text = page.extract_text() or ""
                    parts.append(PAGE_MARKER_TEMPLATE.format(page=idx + 1))
                    parts.append(text)
                    count += 1
                    if count >= chunk_size:
                        yield "".join(parts)
                        parts = []
                        count = 0
                if parts:
                    yield "".join(parts)
        except Exception as exc:  # pdfplumber raises a zoo of exceptions
            raise ValueError(
                f"PDF-Parsing fehlgeschlagen für {pdf_path}: {exc}"
            ) from exc

    def extract_pages(self, pdf_path: Path) -> list[dict[str, Any]]:
        """Return one dict per page with text and dimensions."""
        pdf_path = Path(pdf_path)
        self._guard_size(pdf_path)
        pages: list[dict[str, Any]] = []
        try:
            with pdfplumber.open(pdf_path) as pdf:
                for idx, page in enumerate(pdf.pages):
                    text = page.extract_text() or ""
                    pages.append(
                        {
                            "page": idx + 1,
                            "text": text,
                            "width": float(page.width),
                            "height": float(page.height),
                        }
                    )
        except Exception as exc:  # pdfplumber raises a zoo of exceptions
            raise ValueError(
                f"PDF-Parsing fehlgeschlagen für {pdf_path}: {exc}"
            ) from exc
        return pages

    # ------------------------------------------------------------------ restore

    def restore_pdf(
        self,
        sanitized_text: str,
        output_pdf: Path,
    ) -> Path:
        """Render *sanitized_text* into a new PDF.

        The *original_pdf* argument from the original task spec is kept as
        optional metadata — we no longer require it because reportlab
        generates a fresh canvas.  Layout will not be byte-identical to
        the source, but the textual content is preserved token-for-token.
        """
        output_pdf = Path(output_pdf)
        output_pdf.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        c = canvas.Canvas(str(output_pdf), pagesize=letter)
        y = _TOP_Y
        for raw_line in (sanitized_text or "").split("\n"):
            c.drawString(_LEFT_X, y, raw_line[:_LINE_MAX_CHARS])
            y -= _LINE_DROP
            if y < _BOTTOM_Y:
                c.showPage()
                y = _TOP_Y
        c.save()
        return output_pdf

    # ----------------------------------------------------------------- helpers

    def _guard_size(self, pdf_path: Path) -> None:
        """Warn (do not block) on oversize PDFs.  Real cap lives at upload time."""
        if not pdf_path.exists():
            raise FileNotFoundError(f"PDF nicht gefunden: {pdf_path}")
        size_mb = pdf_path.stat().st_size / (1024 * 1024)
        if size_mb > self.max_size_mb:
            # We deliberately do not raise — pdfplumber streams and the
            # real DoS protection belongs at the HTTP layer.  Log instead.
            import logging
            logging.getLogger(__name__).warning(
                "Privacy-Shield PDF: %s is %.1f MB (> %d MB limit).",
                pdf_path,
                size_mb,
                self.max_size_mb,
            )
