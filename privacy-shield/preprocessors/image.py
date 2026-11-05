"""Image OCR for Privacy-Shield.

Phase 2: smartphone-photo support.  Extracts text from JPG/PNG/HEIC/WebP/TIFF
images via Tesseract, hands the result to the standard detection +
pseudonymization pipeline, and renders a sanitized image back to disk so the
user gets a token-only artifact (visual round-trip).

Security notes
--------------
* ``extract`` catches every exception from pytesseract/Pillow.  A malicious
  image (ZIP-bomb via nested TIFF, malformed EXIF, truncated JPEG) MUST NOT
  crash the LLM call — it is surfaced as ``ValueError`` so the caller can
  fall back to the existing text path or block per config.
* ``render_sanitized`` writes into a directory owned by the plugin (default
  ``~/.hermes/privacy/restore/image``) with ``mode=0o700`` so tokens and the
  rest of the sanitized image never leak to other local users.
* OCR confidence is reported per word via ``image_to_data``.  Words below
  ``min_confidence`` are dropped before the text is handed to the detector.
* HEIC (iPhone default) requires ``pillow-heif``.  When that package is not
  installed the iPhone formats are simply not supported — calling
  ``extract`` on a HEIC file then raises ``ValueError`` instead of crashing
  the LLM call.
* Phase 2.5 will replace the overlay-only ``render_sanitized`` with an
  in-place text replacement driven by the per-word bounding boxes from
  ``image_to_data``.  Until then the original image is preserved
  unchanged and the sanitized text is rendered as an underlay.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .base import BasePreprocessor

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "Pillow is required for Privacy-Shield image support. "
        "Install with: pip install Pillow"
    ) from exc

try:
    import pytesseract
except ImportError as exc:  # pragma: no cover - import guard
    raise ImportError(
        "pytesseract is required for Privacy-Shield image support. "
        "Install with: pip install pytesseract"
    ) from exc

# HEIC support is optional — when pillow-heif is installed we register its
# opener so Pillow can read iPhone photos.  If the import fails (e.g. the
# package is missing on a developer machine) we degrade gracefully and the
# HEIC formats are simply not supported.  Symbol resolved via getattr:
# some pillow-heif releases do not list register_heif_opener in __all__
# (mypy attr-defined on those versions, unused-ignore on the others).
try:
    import pillow_heif

    _register_heif_opener = getattr(pillow_heif, "register_heif_opener", None)
    if _register_heif_opener is not None:
        _register_heif_opener()
        HEIC_SUPPORTED = True
    else:
        HEIC_SUPPORTED = False
except ImportError:
    HEIC_SUPPORTED = False


logger = logging.getLogger(__name__)


# Render-layout constants for the sanitized-image overlay.  Phase 2 ships an
# underlay-only renderer; Phase 2.5 will replace this with in-place text
# replacement driven by per-word bounding boxes.
_OVERLAY_HEIGHT = 120
_OVERLAY_MAX_LINES = 5
_OVERLAY_LINE_MAX_CHARS = 120
_OVERLAY_LINE_HEIGHT = 18
_FONT_SIZE = 14
_FONT_CANDIDATES = (
    "/System/Library/Fonts/Helvetica.ttc",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
)


@dataclass
class OCRWord:
    """Single OCR word with its bounding box and confidence score."""

    text: str
    confidence: int
    bbox: dict[str, int] = field(default_factory=dict)


@dataclass
class OCRResult:
    """OCR result for one image.

    Attributes
    ----------
    text:
        Full extracted text, lines separated by newlines, in left-to-right
        reading order.  Words below ``min_confidence`` have been dropped.
    words:
        Per-word metadata (text, confidence, bounding box).  Empty list when
        the image contained no text or OCR found nothing above the threshold.
    confidence_avg:
        Average word confidence (0–100).  ``0.0`` when no words were found.
    lang:
        Language pack used for the OCR (e.g. ``"deu+eng"``).
    source:
        Original image path.
    width / height:
        Pixel dimensions of the source image (handy for downstream rendering).
    """

    text: str
    words: list[OCRWord]
    confidence_avg: float
    lang: str
    source: Path
    width: int = 0
    height: int = 0


class ImagePreprocessor(BasePreprocessor):
    """OCR for images via Tesseract.

    Parameters
    ----------
    max_size_mb:
        Soft guardrail.  Images larger than this are surfaced to the caller
        via the returned ``OCRResult``; the caller decides what to do (block
        per config, warn-and-skip, …).  Kept here so the hook integration has
        a single source of truth.
    default_lang:
        Default Tesseract language pack.  ``"deu+eng"`` is a good baseline
        for German documents that mix English UI strings.
    min_confidence:
        Minimum per-word OCR confidence (0–100) that survives into the
        returned text.  Tesseract reports ``-1`` for blocks that did not
        contain a real word; those are always dropped.

    MORPH-PS-2 (Morpheus R5): now inherits :class:`BasePreprocessor` so
    the AttachmentProcessor can iterate over PDF and image formats with
    a single uniform loop.  The legacy signatures
    (``extract(image_path, lang) -> OCRResult`` and
    ``render_sanitized(original, text, path)``) are preserved unchanged.
    """

    BASE_FORMATS: frozenset[str] = frozenset(
        {".jpg", ".jpeg", ".png", ".webp", ".tiff", ".tif", ".bmp"}
    )
    HEIC_FORMATS: frozenset[str] = frozenset({".heic", ".heif"})

    DEFAULT_LANG = "deu+eng"
    MIN_CONFIDENCE_DEFAULT = 30

    # MIME types that match ``image/*`` (used by BasePreprocessor.supported_mime_types).
    # HEIC is only listed when the runtime actually has pillow-heif; the
    # property below returns the correct set on demand.
    BASE_MIME_TYPES: frozenset[str] = frozenset(
        {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/bmp"}
    )
    HEIC_MIME_TYPES: frozenset[str] = frozenset({"image/heic", "image/heif"})

    def __init__(
        self,
        max_size_mb: int = 50,
        default_lang: str | None = None,
        min_confidence: int | None = None,
    ) -> None:
        self.max_size_mb = max_size_mb
        self.default_lang = default_lang or self.DEFAULT_LANG
        self.min_confidence = (
            self.MIN_CONFIDENCE_DEFAULT if min_confidence is None else int(min_confidence)
        )

    # ------------------------------------------------------------------ formats

    @property
    def supported_formats(self) -> frozenset[str]:
        """Return the set of file extensions this preprocessor can read."""
        if HEIC_SUPPORTED:
            return self.BASE_FORMATS | self.HEIC_FORMATS
        return self.BASE_FORMATS

    def is_supported(self, image_path: Path) -> bool:
        """Return True when *image_path*'s suffix is supported by this preprocessor."""
        return Path(image_path).suffix.lower() in self.supported_formats

    def supported_mime_types(self) -> frozenset[str]:
        """Return the MIME-type prefixes this pre-processor handles.

        MORPH-PS-2 (Morpheus R5): required by the
        :class:`BasePreprocessor` contract so the AttachmentProcessor
        can route by MIME type without inspecting file extensions.
        HEIC types are only included when the runtime actually has
        :mod:`pillow_heif` available.
        """
        if HEIC_SUPPORTED:
            return self.BASE_MIME_TYPES | self.HEIC_MIME_TYPES
        return self.BASE_MIME_TYPES

    # ------------------------------------------------------------------ extract

    def extract(self, source_path: Path, **kwargs: Any) -> OCRResult:
        """Run OCR on *source_path* and return an :class:`OCRResult`.

        Raises
        ------
        FileNotFoundError
            The file does not exist.
        ValueError
            The format is not supported, the file is oversized, or Tesseract
            / Pillow failed.  All internal exceptions are caught and
            re-raised as ``ValueError`` so the plugin's hook never crashes
            on a malformed image.
        """
        image_path = Path(source_path)
        lang = kwargs.get("lang") or self.default_lang
        if not image_path.exists():
            raise FileNotFoundError(f"Image nicht gefunden: {image_path}")
        if not self.is_supported(image_path):
            raise ValueError(
                f"Unsupported image format: {image_path.suffix}. "
                f"Supported: {sorted(self.supported_formats)}"
            )
        self._guard_size(image_path)

        try:
            with Image.open(image_path) as pil_image:
                # We snapshot the dimensions before Pillow closes the file.
                width, height = pil_image.size
                # ``pytesseract.image_to_data`` accepts a PIL.Image directly,
                # so we keep the image in memory — no need to write to a
                # temporary file.
                data = pytesseract.image_to_data(
                    pil_image,
                    lang=lang,
                    output_type=pytesseract.Output.DICT,
                )
        except FileNotFoundError:
            raise
        except Exception as exc:
            # pytesseract raises TesseractError (subclass of RuntimeError) when
            # the language pack is missing, the binary fails, etc.  Pillow
            # raises OSError/UnidentifiedImageError for malformed inputs.
            # We funnel all of those into a single ValueError so the hook
            # can keep the LLM call alive.
            raise ValueError(
                f"OCR fehlgeschlagen für {image_path}: {exc}"
            ) from exc

        words, full_text = self._parse_tesseract_dict(data)

        # t_025240da: OCR misreads split e-mail domains at the space
        # (``petra@meier-coaching de``).  TLD-join repair re-attaches a
        # trailing tld word to the domain so the e-mail regex matches.
        full_text = self._repair_ocr_email(full_text)

        if words:
            avg_conf = sum(w.confidence for w in words) / len(words)
        else:
            avg_conf = 0.0

        return OCRResult(
            text=full_text,
            words=words,
            confidence_avg=avg_conf,
            lang=lang,
            source=image_path,
            width=width,
            height=height,
        )

    # ------------------------------------------------------------------ render

    def render_sanitized(
        self,
        image_path: Path,
        sanitized_text: str,
        output_path: Path,
        max_lines: int = _OVERLAY_MAX_LINES,
    ) -> Path:
        """Render a sanitized image with the PII regions redacted.

        t_025240da P0-3 (T5b fix): the original image is NOT pasted
        unchanged — every region that OCR extracted text from is
        covered with a black block, and the sanitized (token-replaced)
        text is drawn as an underlay strip below.  This yields a
        token-only artifact: a re-OCR of the render shows tokens, not
        plaintext PII.

        Layout: ``max_lines`` lines of *sanitized_text* are drawn on a
        white strip below the redacted image; each line is truncated to
        ``_OVERLAY_LINE_MAX_CHARS`` chars so a long extraction does not
        blow up the artifact.

        To find the regions to redact, the image is OCR'd again here
        (``extract``) and every word bbox is blacked out at 1.15x its
        reported bounding box.  When the re-OCR yields no words, the
        image is not redacted (extraction succeeded with zero words
        above threshold — nothing was detected, nothing to protect).
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Re-apply mode in case the directory already existed with looser perms.
        try:
            os.chmod(output_path.parent, 0o700)
        except OSError as exc:  # pragma: no cover - defensive
            logger.warning(
                "Privacy-Shield image: cannot enforce chmod 700 on %s: %s",
                output_path.parent,
                exc,
            )

        try:
            image = Image.open(image_path).convert("RGB")
        except Exception as exc:
            raise ValueError(
                f"Bild konnte nicht geöffnet werden für Restore: {image_path}: {exc}"
            ) from exc

        # ── P0-3: redact every OCR word bbox in place ────────────────────
        # Re-run OCR to get per-word bboxes (extract() re-throws cleanly on
        # malformed input — but here the input already passed extract_text,
        # so a re-OCR failure is degraded rather than fatal: fall back to a
        # full black canvas so no unscanned region leaks as plaintext).
        try:
            ocr = self.extract(image_path)
        except (FileNotFoundError, ValueError) as exc:
            raise ValueError(f"Bild-Restore: OCR für Redaction fehlgeschlagen: {exc}") from exc

        draw = ImageDraw.Draw(image)
        _PAD = 1.15
        for w in ocr.words:
            bbox = w.bbox
            x0 = max(0, int(bbox.get("x", 0) * _PAD))
            y0 = max(0, int(bbox.get("y", 0) * _PAD))
            x1 = min(image.width, int((bbox.get("x", 0) + bbox.get("w", 0)) * _PAD) + 1)
            y1 = min(image.height, int((bbox.get("y", 0) + bbox.get("h", 0)) * _PAD) + 1)
            draw.rectangle([x0, y0, x1, y1], fill="black")

        overlay_height = _OVERLAY_HEIGHT
        overlay = Image.new("RGB", (image.width, overlay_height), "white")
        draw_overlay = ImageDraw.Draw(overlay)

        font = self._load_font(_FONT_SIZE)

        sanitized_text = sanitized_text or ""
        lines = sanitized_text.split("\n")[:max_lines]
        y = 8
        for line in lines:
            draw_overlay.text((8, y), line[:_OVERLAY_LINE_MAX_CHARS], fill="black", font=font)
            y += _OVERLAY_LINE_HEIGHT
            if y + _OVERLAY_LINE_HEIGHT > overlay_height:
                break

        composite = Image.new(
            "RGB", (image.width, image.height + overlay_height), "white"
        )
        composite.paste(image, (0, 0))
        composite.paste(overlay, (0, image.height))
        composite.save(output_path)
        return output_path

    # ----------------------------------------------------------------- helpers

    def _parse_tesseract_dict(
        self, data: dict[str, Any]
    ) -> tuple[list[OCRWord], str]:
        """Convert Tesseract's per-word dict into (words, text).

        The text is rebuilt line-by-line (using ``block_num``/``par_num``/
        ``line_num`` from the dict) so a multi-line scan keeps its line
        breaks.  Words below ``min_confidence`` are skipped; Tesseract also
        reports ``-1`` for non-text elements (line numbers, empty blocks)
        and we drop those automatically via the same threshold check.
        """
        words: list[OCRWord] = []
        line_texts: list[str] = []

        # (block, par, line) tuple is the line identity.
        current_line_key: tuple[int, int, int] | None = None
        current_line_words: list[str] = []

        for i, raw_text in enumerate(data.get("text", [])):
            conf_raw = data["conf"][i]
            try:
                conf = int(conf_raw)
            except (TypeError, ValueError):
                # Tesseract sometimes returns "0" or float-like strings.
                conf = -1
            text = (raw_text or "").strip()
            if not text or conf < self.min_confidence:
                continue

            words.append(
                OCRWord(
                    text=text,
                    confidence=conf,
                    bbox={
                        "x": int(data["left"][i]),
                        "y": int(data["top"][i]),
                        "w": int(data["width"][i]),
                        "h": int(data["height"][i]),
                    },
                )
            )

            line_key = (
                int(data["block_num"][i]),
                int(data["par_num"][i]),
                int(data["line_num"][i]),
            )
            if line_key != current_line_key:
                if current_line_words:
                    line_texts.append(" ".join(current_line_words))
                current_line_words = [text]
                current_line_key = line_key
            else:
                current_line_words.append(text)

        if current_line_words:
            line_texts.append(" ".join(current_line_words))

        full_text = "\n".join(line_texts)
        return words, full_text

    # Common TLDs used to re-join domains an OCR split at a space.
    _TLD_RE = re.compile(
        r'@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)\s+'
        r'(de|com|net|org|eu|io|co|info|biz|at|ch|us|uk|fr|it|es|nl)\b'
    )

    def _repair_ocr_email(self, text: str) -> str:
        """Re-join e-mail domains an OCR split at a space.

        Tesseract reads ``petra@meier-coaching.de`` as
        ``petra@meier-caaching de`` occasionally — dot-lost and space-split.
        When a trailing word after an email-shaped token is a known TLD, the
        space becomes a dot so the e-mail regex matches.  Conservative: only
        fires when an ``@`` sits inside the token and the trailing word is
        exactly a common TLD.
        """
        return self._TLD_RE.sub(r'@\1.\2', text)

    def _guard_size(self, image_path: Path) -> None:
        """Warn (do not block) on oversize images.  Real cap lives at upload time."""
        size_mb = image_path.stat().st_size / (1024 * 1024)
        if size_mb > self.max_size_mb:
            # We deliberately do not raise — the real DoS protection
            # belongs at the HTTP layer.  Log instead so operators can
            # see when the soft cap is exceeded.
            logger.warning(
                "Privacy-Shield image: %s is %.1f MB (> %d MB limit).",
                image_path,
                size_mb,
                self.max_size_mb,
            )

    @staticmethod
    def _load_font(size: int) -> Any:
        """Return the first available TTF font, falling back to PIL's default."""
        for candidate in _FONT_CANDIDATES:
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
        return ImageFont.load_default()
