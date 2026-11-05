#!/usr/bin/env python3
"""Generate a fixture image containing PII for Privacy-Shield tests.

Simulates a smartphone photo of an invoice / business document. The text is
rendered with a real TrueType font at a high DPI so Tesseract can read it
reliably across all supported language packs.

Run once to materialize ``tests/fixtures/sample_invoice.png``::

    ~/.hermes/hermes-agent/venv/bin/python scripts/generate_test_image.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def _load_font(size: int) -> ImageFont.ImageFont:
    """Try several system font paths so the script works on macOS and Linux."""
    candidates = (
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    )
    for candidate in candidates:
        try:
            return ImageFont.truetype(candidate, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def make_invoice_image(output_path: Path) -> None:
    """Render a PII-laden invoice image (smartphone-photo style)."""
    # 1200x900 at 144 dpi mimics a phone screenshot at 2x.
    width, height = 1200, 900
    image = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(image)

    title_font = _load_font(34)
    body_font = _load_font(24)

    # Subtle paper-texture border to mimic a real photograph.
    border_color = (235, 235, 235)
    draw.rectangle([(20, 20), (width - 20, height - 20)], outline=border_color, width=2)

    y = 60
    draw.text((50, y), "RECHNUNG / INVOICE", fill="black", font=title_font)
    y += 70
    lines = [
        "Kunde: Max Mustermann",
        "Email: max.mustermann@example.com",
        "IBAN: DE89370400440532013000",
        "Steuer-ID: 123456789",
        "Telefon: +49 30 12345678",
        "Datum: 21.08.2026",
        "Betrag: 1.234,56 EUR",
    ]
    for line in lines:
        draw.text((50, y), line, fill="black", font=body_font)
        y += 44

    image.save(output_path)


if __name__ == "__main__":
    target = (
        Path(__file__).resolve().parent.parent
        / "tests"
        / "fixtures"
        / "sample_invoice.png"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    make_invoice_image(target)
    print(f"Sample-Image erstellt: {target}")
