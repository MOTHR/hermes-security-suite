"""Privacy-Shield preprocessors.

Each preprocessor handles a specific input format (PDF, image, Office, audio, ...)
and produces a plain-text representation that the standard detection +
pseudonymization pipeline can consume.

* ``pdf``   — text-based PDFs (Phase 1)
* ``image`` — JPG / PNG / HEIC / WebP / TIFF via Tesseract OCR (Phase 2)
"""

from __future__ import annotations

__all__ = ["pdf", "image"]
