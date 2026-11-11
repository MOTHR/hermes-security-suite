"""Tests for privacy-shield doctor command and helper functions."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from privacy_shield.cli import main, _check_key, _check_smoke, _check_echt, _check_pytest


@pytest.fixture
def runner():
    return CliRunner()


# ── _check_key ──────────────────────────────────────────────────────────

class TestCheckKey:
    """Pre-Stage 0: Encryption-Key assertion."""

    def test_key_present(self):
        """_check_key returns True when the config resolves a key."""
        fake_config = MagicMock()
        fake_config.encryption_key = "s3cret"
        with patch("privacy_shield.cli.load_config", return_value=fake_config):
            assert _check_key() is True

    def test_key_missing(self):
        """_check_key returns False when no encryption key resolves (1.9.x: plugin disabled)."""
        fake_config = MagicMock()
        fake_config.encryption_key = ""
        with patch("privacy_shield.cli.load_config", return_value=fake_config):
            assert _check_key() is False

    def test_key_load_raises(self):
        """_check_key returns False when load_config raises."""
        with patch("privacy_shield.cli.load_config", side_effect=OSError("config unreadable")):
            assert _check_key() is False


# ── _check_smoke ────────────────────────────────────────────────────────

class TestCheckSmoke:
    """Stage 1: Plugin-Scan mit Test-PII."""

    def test_smoke_detects_email(self):
        """_check_smoke returns True when scan finds test@example.com."""
        fake_result = MagicMock()
        fake_result.stdout = "Found 1 PII match(es):\n  email: 'test@example.com'"
        with patch("subprocess.run", return_value=fake_result):
            assert _check_smoke() is True

    def test_smoke_detects_email_lowercase(self):
        """_check_smoke returns True when output contains 'email' (case-insensitive)."""
        fake_result = MagicMock()
        fake_result.stdout = "Found 1 PII match(es):\n  EMAIL: 'test@example.com'"
        with patch("subprocess.run", return_value=fake_result):
            assert _check_smoke() is True

    def test_smoke_no_pii_found(self):
        """_check_smoke returns False when no PII detected."""
        fake_result = MagicMock()
        fake_result.stdout = "No PII detected."
        with patch("subprocess.run", return_value=fake_result):
            assert _check_smoke() is False

    def test_smoke_subprocess_error(self):
        """_check_smoke returns False on subprocess failure."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)):
            assert _check_smoke() is False

    def test_smoke_generic_exception(self):
        """_check_smoke returns False on any exception."""
        with patch("subprocess.run", side_effect=OSError("no such file")):
            assert _check_smoke() is False


# ── _check_echt ─────────────────────────────────────────────────────────

class TestCheckEcht:
    """Stage 2: Pseudonymize + map --list."""

    def test_echt_detects_token_email(self):
        """_check_echt returns True when output contains TOKEN_EMAIL."""
        fake_result = MagicMock()
        fake_result.stdout = "Replaced 1 PII instance(s):\n  email: TOKEN_EMAIL_001\n\n--- Sanitized output ---\nTOKEN_EMAIL_001"
        with patch("subprocess.run", return_value=fake_result):
            assert _check_echt() is True

    def test_echt_detects_token_generic(self):
        """_check_echt returns True when output contains TOKEN (generic)."""
        fake_result = MagicMock()
        fake_result.stdout = "Replaced 1 PII instance(s):\n  email: TOKEN_42\n\n--- Sanitized output ---\nTOKEN_42"
        with patch("subprocess.run", return_value=fake_result):
            assert _check_echt() is True

    def test_echt_no_token(self):
        """_check_echt returns False when no TOKEN in output."""
        fake_result = MagicMock()
        fake_result.stdout = "No PII detected — output unchanged.\ntest@example.com"
        with patch("subprocess.run", return_value=fake_result):
            assert _check_echt() is False

    def test_echt_subprocess_error(self):
        """_check_echt returns False on subprocess failure."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)):
            assert _check_echt() is False


# ── _check_pytest ───────────────────────────────────────────────────────

class TestCheckPytest:
    """Stage 3: Run pytest."""

    def test_pytest_passes(self):
        """_check_pytest returns True when pytest exits 0."""
        fake_result = MagicMock()
        fake_result.returncode = 0
        with patch("subprocess.run", return_value=fake_result):
            assert _check_pytest() is True

    def test_pytest_fails(self):
        """_check_pytest returns False when pytest exits non-zero."""
        fake_result = MagicMock()
        fake_result.returncode = 1
        with patch("subprocess.run", return_value=fake_result):
            assert _check_pytest() is False

    def test_pytest_subprocess_error(self):
        """_check_pytest returns False on subprocess failure."""
        with patch("subprocess.run", side_effect=OSError("pytest not found")):
            assert _check_pytest() is False


# ── doctor CLI command ──────────────────────────────────────────────────

class TestDoctorCommand:
    """End-to-end tests for the doctor CLI command."""

    def test_doctor_quick_all_pass(self, runner):
        """doctor --quick with both stages passing."""
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True):
            result = runner.invoke(main, ["doctor", "--quick"])
            assert result.exit_code == 0
            assert "Stage 1" in result.output
            assert "Stage 2" in result.output
            assert "Verdict: 2/2 OK" in result.output

    def test_doctor_quick_one_fail(self, runner):
        """doctor --quick with one stage failing exits 1 (false-pass fix)."""
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=False):
            result = runner.invoke(main, ["doctor", "--quick"])
            assert result.exit_code == 1
            assert "Verdict: 1/2 OK" in result.output

    def test_doctor_full_all_pass(self, runner):
        """doctor (full) with stages 1-3 passing."""
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True), \
             patch("privacy_shield.cli._check_pytest", return_value=True):
            result = runner.invoke(main, ["doctor"])
            assert result.exit_code == 0
            assert "Stage 1" in result.output
            assert "Stage 2" in result.output
            assert "Stage 3" in result.output
            assert "Stage 4" in result.output
            assert "Stage 5" in result.output
            assert "Verdict: 3/5 OK" in result.output

    def test_doctor_full_pytest_fails(self, runner):
        """doctor (full) with pytest failing exits 1."""
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True), \
             patch("privacy_shield.cli._check_pytest", return_value=False):
            result = runner.invoke(main, ["doctor"])
            assert result.exit_code == 1
            assert "Verdict: 2/5 OK" in result.output

    def test_doctor_header(self, runner):
        """doctor shows version header (FIX-PS5: dynamic __version__)."""
        from privacy_shield import __version__
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True):
            result = runner.invoke(main, ["doctor", "--quick"])
            assert f"Privacy-Shield Doctor v{__version__}" in result.output
            assert "======" in result.output

    def test_doctor_verbose_flag_accepted(self, runner):
        """doctor --verbose does not crash."""
        with patch("privacy_shield.cli._check_key", return_value=True), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True):
            result = runner.invoke(main, ["doctor", "--verbose", "--quick"])
            assert result.exit_code == 0


# ── Key-Assertion (t_86cd5f92: silent false-pass fix) ───────────────────

class TestDoctorKeyAssertion:
    """doctor must NOT exit 0 when no encryption key resolves.

    Regression for 1.9.x silent false-pass: without a key the plugin is
    disabled, Stage 1 (key-free scan) and Stage 2 (ephemeral token on stdout)
    both passed the stdout greps, and the cron wrapper wrote last_doctor_ok.
    """

    def test_quick_without_key_exits_2(self, runner):
        """doctor --quick with no key must NOT exit 0 (exit 2 = key missing)."""
        with patch("privacy_shield.cli._check_key", return_value=False), \
             patch("privacy_shield.cli._check_smoke", return_value=True), \
             patch("privacy_shield.cli._check_echt", return_value=True):
            result = runner.invoke(main, ["doctor", "--quick"])
            assert result.exit_code == 2
            assert result.exit_code != 0
            assert "encryption key missing" in result.output
            # The stage checks must never run on a disabled plugin.
            assert "Stage 1" not in result.output
            assert "Verdict: 2/2 OK" not in result.output

    def test_full_without_key_exits_2(self, runner):
        """doctor (full) without key exits 2 before any stage runs."""
        with patch("privacy_shield.cli._check_key", return_value=False):
            result = runner.invoke(main, ["doctor"])
            assert result.exit_code == 2
            assert "encryption key missing" in result.output
