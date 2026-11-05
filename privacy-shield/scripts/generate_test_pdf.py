#!/usr/bin/env python3
"""Generate a fixture PDF containing PII for Privacy-Shield tests.

Run once to materialize ``tests/fixtures/sample_invoice.pdf``.
"""

from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def make_invoice(output_path: Path) -> None:
    c = canvas.Canvas(str(output_path), pagesize=letter)
    c.drawString(50, 750, "RECHNUNG / INVOICE")
    c.drawString(50, 720, "Kunde: Max Mustermann")
    c.drawString(50, 700, "Email: max.mustermann@example.com")
    c.drawString(50, 680, "IBAN: DE89370400440532013000")
    c.drawString(50, 660, "Steuer-ID: 123456789")
    c.drawString(50, 640, "Date: 2026-08-21")
    c.drawString(50, 620, "Betrag: 1.234,56 EUR")
    c.save()


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sample_invoice.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)
    make_invoice(target)
    print(f"Sample-PDF erstellt: {target}")
