#!/usr/bin/env python3
"""Privacy-Shield CLI — PII detection and pseudonymization.

Commands:
    privacy-shield detect <text>         Show PII types found with confidence
    privacy-shield anonymize <text>      Output pseudonymized text
    privacy-shield anonymize-file <in> <out>  File-based pseudonymization
    privacy-shield restore <text>        Restore tokens back to original PII
    privacy-shield map --list            List all mapping tokens
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import click

# ── Package bootstrap ──────────────────────────────────────────────────
# The plugin directory is "privacy-shield" (hyphen), which is not a valid
# Python identifier. We register it as the synthetic package "privacy_shield"
# so that relative imports inside pseudonymizer.py resolve correctly.

_PLUGIN_ROOT = Path(__file__).resolve().parent.parent
_PKG = "privacy_shield"
_DETECTORS = f"{_PKG}.detectors"


class _FakePackage:
    """Minimal package object for sys.modules registration."""

    def __init__(self, name: str, path: str):
        self.__name__ = name
        self.__package__ = name
        self.__path__ = [path]


def _load_module(rel_path: str, full_name: str) -> None:
    """Load a module file into sys.modules under *full_name*."""
    spec = importlib.util.spec_from_file_location(full_name, _PLUGIN_ROOT / rel_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {rel_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = mod
    spec.loader.exec_module(mod)


# Register synthetic packages
sys.modules[_PKG] = _FakePackage(_PKG, str(_PLUGIN_ROOT))
sys.modules[_DETECTORS] = _FakePackage(_DETECTORS, str(_PLUGIN_ROOT / "detectors"))

# Load modules in dependency order
_load_module("detectors/name_detector.py", f"{_DETECTORS}.name_detector")
_load_module("detectors/context_leak_detector.py", f"{_DETECTORS}.context_leak_detector")
_load_module("detectors/regex_detector.py", f"{_DETECTORS}.regex_detector")
_load_module("config.py", f"{_PKG}.config")
_load_module("pseudonymizer.py", f"{_PKG}.pseudonymizer")
_load_module("mapping_table.py", f"{_PKG}.mapping_table")

# Now safe to import via the synthetic package
from privacy_shield.detectors.regex_detector import RegexPIIDetector  # noqa: E402
from privacy_shield.pseudonymizer import Pseudonymizer  # noqa: E402
from privacy_shield.mapping_table import MappingTable  # noqa: E402
from privacy_shield.config import load_config  # noqa: E402


# ── Shared instances ──────────────────────────────────────────────────

def _get_detector() -> RegexPIIDetector:
    return RegexPIIDetector()


def _get_pseudonymizer() -> Pseudonymizer:
    cfg = load_config()
    return Pseudonymizer(
        token_style=cfg.token_style,
        token_prefix=cfg.token_prefix,
    )


def _get_mapper() -> MappingTable:
    cfg = load_config()
    return MappingTable(
        storage_path=cfg.storage_path,
        encryption_key=cfg.encryption_key,
    )


# ── CLI Group ──────────────────────────────────────────────────────────

@click.group()
def cli() -> None:
    """Privacy-Shield — PII detection and pseudonymization."""


# ── detect ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("text")
def detect(text: str) -> None:
    """Scan TEXT for PII and show detected types with confidence."""
    detector = _get_detector()
    matches = detector.scan(text)

    if not matches:
        click.echo("No PII detected.")
        return

    click.echo(f"Found {len(matches)} PII entit{'y' if len(matches) == 1 else 'ies'}:\n")
    for m in matches:
        display_value = m.value
        if len(display_value) > 40:
            display_value = display_value[:37] + "..."
        click.echo(f"  {m.type:20s}  confidence={m.confidence:.2f}  rule={m.rule:30s}  value={display_value}")


# ── anonymize ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("text")
def anonymize(text: str) -> None:
    """Pseudonymize TEXT and output the sanitized version."""
    detector = _get_detector()
    pseudonymizer = _get_pseudonymizer()
    mapper = _get_mapper()

    matches = detector.scan(text)
    if not matches:
        click.echo(text)
        return

    sanitized, mapping = pseudonymizer.replace(text, matches)
    mapper.store(mapping)

    click.echo(sanitized)


# ── anonymize-file ─────────────────────────────────────────────────────

@cli.command("anonymize-file")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("output_path", type=click.Path(dir_okay=False))
def anonymize_file(input_path: str, output_path: str) -> None:
    """Read INPUT_PATH, pseudonymize, write to OUTPUT_PATH."""
    detector = _get_detector()
    pseudonymizer = _get_pseudonymizer()
    mapper = _get_mapper()

    # Path-traversal guard (Smith MED-004): output must be within CWD
    resolved = Path(output_path).resolve()
    cwd = Path.cwd().resolve()
    if not str(resolved).startswith(str(cwd)):
        raise click.BadParameter(
            f"Output path must be within current directory. "
            f"Got: {output_path} (resolves to {resolved})"
        )

    text = Path(input_path).read_text(encoding="utf-8")
    matches = detector.scan(text)

    if not matches:
        click.echo(f"No PII detected in {input_path} — writing unchanged.")
        Path(output_path).write_text(text, encoding="utf-8")
        return

    sanitized, mapping = pseudonymizer.replace(text, matches)
    mapper.store(mapping)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(sanitized, encoding="utf-8")

    click.echo(
        f"Pseudonymized {len(matches)} PII entit{'y' if len(matches) == 1 else 'ies'} "
        f"→ {output_path}"
    )


# ── restore ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("text")
@click.option("--session-id", "-s", default="", help="Session ID for targeted lookup")
def restore(text: str, session_id: str) -> None:
    """Restore TOKEN_TYPE_NNN placeholders back to original PII values.

    Scans TEXT for tokens like TOKEN_EMAIL_001 and replaces them with
    the original PII values from the mapping table. Tokens that cannot
    be resolved are left as-is (fallback).
    """
    mapper = _get_mapper()
    restored = mapper.restore_text(text)
    click.echo(restored)


# ── map ────────────────────────────────────────────────────────────────

@cli.group(name="map", invoke_without_command=True)
@click.option("--list", "list_flag", is_flag=True, help="List all stored mapping tokens")
@click.option("--cleanup-expired", "cleanup_flag", is_flag=True, help="Delete all expired mappings")
@click.option("--close-session", "close_session_id", default=None, help="Delete all mappings for a session ID")
@click.pass_context
def map_cmd(ctx: click.Context, list_flag: bool, cleanup_flag: bool, close_session_id: str | None) -> None:
    """Mapping table operations."""
    if close_session_id is not None:
        _do_close_session(close_session_id)
        ctx.exit()
    if cleanup_flag:
        _do_cleanup_expired()
        ctx.exit()
    if list_flag or ctx.invoked_subcommand is None:
        _do_map_list()
        ctx.exit()


@map_cmd.command("list")
def map_list() -> None:
    """List all stored mapping tokens."""
    _do_map_list()


def _do_map_list() -> None:
    """Shared implementation for map --list and map list."""
    mapper = _get_mapper()
    entries = mapper.list_all()

    if not entries:
        click.echo("Mapping table is empty.")
        return

    click.echo(f"{'TOKEN':30s}  {'TYPE':20s}  {'HASH (first 12)':16s}")
    click.echo("-" * 72)
    for e in entries:
        hash_short = e["original_hash"][:12]
        click.echo(f"{e['token']:30s}  {e['type']:20s}  {hash_short}")


def _do_cleanup_expired() -> None:
    """Delete all expired mappings."""
    mapper = _get_mapper()
    expired_before = mapper.expired_count()
    deleted = mapper.prune_expired()
    click.echo(f"Expired before cleanup: {expired_before}")
    click.echo(f"Deleted: {deleted}")
    click.echo(f"Remaining: {mapper.count()}")


def _do_close_session(session_id: str) -> None:
    """Delete all mappings for a session."""
    mapper = _get_mapper()
    deleted = mapper.close_session(session_id)
    click.echo(f"Closed session {session_id}: removed {deleted} mappings")
    click.echo(f"Remaining: {mapper.count()}")


@map_cmd.command("cleanup-expired")
def map_cleanup_expired() -> None:
    """Delete all expired mappings."""
    _do_cleanup_expired()


@map_cmd.command("close-session")
@click.argument("session_id")
def map_close_session(session_id: str) -> None:
    """Delete all mappings for a session ID."""
    _do_close_session(session_id)


# ── setup ───────────────────────────────────────────────────────────────

@cli.group(name="setup", invoke_without_command=True)
@click.option("--key-install", "key_install", is_flag=True, help="Generate and store encryption key in pass")
@click.pass_context
def setup_cmd(ctx: click.Context, key_install: bool) -> None:
    """Setup helpers for Privacy-Shield."""
    if key_install or ctx.invoked_subcommand is None:
        _do_key_install()
        ctx.exit()


@setup_cmd.command("key-install")
def setup_key_install() -> None:
    """Generate and store encryption key in pass."""
    _do_key_install()


def _do_key_install() -> None:
    """Generate a 256-bit key and store it via pass insert."""
    import secrets
    import subprocess

    key = secrets.token_hex(32)

    # Check if pass is available
    try:
        result = subprocess.run(
            ["pass", "insert", "hermes/privacy-shield-key"],
            input=key + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            click.echo("Encryption key stored in pass: hermes/privacy-shield-key")
            click.echo(f"Key length: {len(key)} chars ({len(key) // 2} bytes) — AES-256 ready")
        else:
            click.echo(f"pass insert failed: {result.stderr.strip()}", err=True)
            click.echo(f"Fallback: export PRIVACY_SHIELD_KEY='{key}'", err=True)
            raise SystemExit(1)
    except FileNotFoundError:
        click.echo("pass not found. Install pass or set PRIVACY_SHIELD_KEY manually:", err=True)
        click.echo(f"export PRIVACY_SHIELD_KEY='{key}'", err=True)
        raise SystemExit(1)


# ── Entry point ────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()
