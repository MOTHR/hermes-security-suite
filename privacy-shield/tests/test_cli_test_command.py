"""Tests for the `privacy-shield test` CLI command."""

from __future__ import annotations

from click.testing import CliRunner

from privacy_shield.cli import main


def _invoke(*args: str) -> tuple[int, str, str]:
    runner = CliRunner()
    result = runner.invoke(main, args)
    return result.exit_code, result.output, str(result.exception) if result.exception else ""


def test_test_command_detects_email_iban_btc_jwt() -> None:
    text = (
        "Kontakt: max.mustermann@example.com, IBAN: DE89370400440532013000, "
        "BTC: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh, "
        "JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    )
    exit_code, output, _ = _invoke("test", "--text", text)

    assert exit_code == 0
    assert "Found 4 PII match(es):" in output
    assert "email" in output
    assert "iban" in output
    assert "crypto_btc" in output
    assert "jwt" in output


def test_test_command_round_trip_ok() -> None:
    text = "Sende an max@example.com und ueberweise auf DE89370400440532013000"
    exit_code, output, _ = _invoke("test", "--text", text)

    assert exit_code == 0
    assert "Round-trip OK: original == restored" in output


def test_test_command_no_input_fails() -> None:
    runner = CliRunner()
    # Simulate an interactive terminal with no input
    result = runner.invoke(main, ["test"], input="")

    assert result.exit_code == 1
    assert "No input text provided" in result.output


def test_test_command_empty_text_fails() -> None:
    exit_code, output, _ = _invoke("test", "--text", "")

    assert exit_code == 1
    assert "No input text provided" in output


def test_test_command_no_pii_shows_zero_matches() -> None:
    text = "Dies ist ein harmloser Satz ohne jede PII."
    exit_code, output, _ = _invoke("test", "--text", text)

    assert exit_code == 0
    assert "Found 0 PII match(es):" in output
    assert "--- Sanitized output ---" in output
    # No mapping means no explicit round-trip message, but sanitized == original
    assert text in output
