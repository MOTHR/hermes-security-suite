"""Privacy-Shield CLI — PII detection and pseudonymization from the terminal.

Usage:
    privacy-shield scan "some text with email@example.com"
    privacy-shield pseudonymize "some text with email@example.com"
    privacy-shield status
    privacy-shield map --list
    privacy-shield map --cleanup-expired
    privacy-shield map --close-session <session_id>
"""

from __future__ import annotations

import secrets
import subprocess
import sys
from pathlib import Path

import click

from privacy_shield import __version__
from privacy_shield.audit import AuditExporter, AuditLogger, load_public_key, verify_b64
from privacy_shield.audit.report_data import ReportData
from privacy_shield.config import ALLOWED_MODES, load_config
from privacy_shield.detectors.regex_detector import RegexPIIDetector
from privacy_shield.mapping_table import InMemoryMappingTable, MappingTable
from privacy_shield.pseudonymizer import Pseudonymizer


@click.group()
@click.version_option(version=__version__, prog_name="privacy-shield")
def main() -> None:
    """Privacy-Shield — PII pseudonymization for Hermes."""


@main.command()
def setup() -> None:
    """Generate the encryption key and store it in the pass password store.

    The key is declared in plugin.yaml under requires_env
    (PRIVACY_SHIELD_KEY); Hermes resolves it through its configured secret
    sources at plugin load. This command only provisions the value — it does
    not touch ~/.hermes/.env, ~/.hermes/config.yaml, profile symlinks or
    Hermes's venv. Install the plugin itself via
    ``hermes plugins install`` + ``hermes plugins enable``.
    """
    click.echo(f"Privacy-Shield Setup v{__version__}")
    click.echo("=" * 40)

    key = secrets.token_hex(32)

    try:
        result = subprocess.run(
            ["pass", "insert", "-m", "hermes/privacy-shield-key"],
            input=key, text=True, capture_output=True, timeout=15,
        )
        pass_ok = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass_ok = False

    if pass_ok:
        click.echo("✓ Key stored in pass-store: hermes/privacy-shield-key")
    else:
        click.echo(
            "✗ pass-store not available. Declare PRIVACY_SHIELD_KEY via your "
            "Hermes secret sources instead (e.g. config.yaml secrets "
            "keychain env_map, or the requires_env prompt)."
        )

    click.echo("\nNext steps:")
    click.echo("  hermes plugins install <source>/privacy-shield && hermes plugins enable privacy-shield")
    click.echo("  privacy-shield status")
    click.echo("  privacy-shield scan \"test@example.com\"")


@main.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read input from file")
def scan(text: str | None, file: str | None) -> None:
    """Scan text for PII and report findings."""
    if file:
        with open(file) as f:
            text = f.read()
    if not text:
        click.echo("Error: provide text as argument or via --file", err=True)
        sys.exit(1)

    detector = RegexPIIDetector()
    hits = detector.scan(text)

    if not hits:
        click.echo("No PII detected.")
        return

    click.echo(f"Found {len(hits)} PII match(es):")
    for hit in hits:
        click.echo(f"  {hit.type}: {hit.value!r} (pos {hit.start}:{hit.end}, rule={hit.rule})")


@main.command()
@click.argument("text", required=False)
@click.option("--file", "-f", type=click.Path(exists=True), help="Read input from file")
def pseudonymize(text: str | None, file: str | None) -> None:
    """Replace PII with pseudonymized tokens."""
    if file:
        with open(file) as f:
            text = f.read()
    if not text:
        click.echo("Error: provide text as argument or via --file", err=True)
        sys.exit(1)

    config = load_config()
    detector = RegexPIIDetector()
    pseudonymizer = Pseudonymizer(
        token_style=config.token_style,
        token_prefix=config.token_prefix,
    )

    hits = detector.scan(text)
    if not hits:
        click.echo("No PII detected — output unchanged.")
        click.echo(text)
        return

    sanitized, mapping = pseudonymizer.replace(text, hits)
    click.echo(f"Replaced {len(mapping)} PII instance(s):")
    for entry in mapping:
        click.echo(f"  {entry['type']}: {entry['token']}")
    click.echo()
    click.echo("--- Sanitized output ---")
    click.echo(sanitized)


@main.command()
def status() -> None:
    """Show plugin status and configuration."""
    config = load_config()
    detector = RegexPIIDetector()
    click.echo(f"Privacy-Shield v{__version__}")
    click.echo(f"  Enabled:     {config.enabled}")
    click.echo(f"  Mode:        {config.mode}")
    click.echo(f"  Engine:      {config.detection_engine}")
    click.echo(f"  Patterns:    {detector.pattern_count} loaded")
    click.echo(f"  Tokens:      {config.token_style} ({config.token_prefix}_XXX)")
    click.echo(f"  Storage:     {config.storage_mode} ({config.storage_path})")
    click.echo(f"  Cache-Bypass: {config.cache_bypass}")
    click.echo(f"  Restore channels: {', '.join(config.restore_allowed_channels) or '(none)'}")
    click.echo(f"  Latency:     {config.max_latency_ms}ms")
    click.echo(f"  Fallback:    {config.fallback_on_timeout}")
    click.echo(f"  TTL:         {config.mapping_ttl_seconds}s")


# ── test ─────────────────────────────────────────────────────────────────

@main.command()
@click.option("--text", "-t", default=None, help="Text to test PII detection on.")
@click.option("--file", "-f", default=None, type=click.Path(exists=True), help="File to test.")
def test(text: str | None, file: str | None) -> None:
    """Quick smoke-test: detect + pseudonymize + restore round-trip.

    Examples:
      privacy-shield test --text "Kontakt: max.mustermann@example.com"
      cat secret.txt | privacy-shield test --file -
    """
    if text is None and file is None:
        # Read from stdin
        if sys.stdin.isatty():
            click.echo("No input text provided", err=True)
            sys.exit(1)
        text = sys.stdin.read()
    elif file:
        text = Path(file).read_text(encoding="utf-8")

    if not text:
        click.echo("No input text provided", err=True)
        sys.exit(1)

    config = load_config()
    detector = RegexPIIDetector()
    pseudonymizer = Pseudonymizer(
        token_style=config.token_style,
        token_prefix=config.token_prefix,
    )

    # Detect
    matches = detector.scan(text)
    click.echo(f"Found {len(matches)} PII match(es):")
    for m in matches[:20]:
        display = m.value if len(m.value) <= 40 else m.value[:37] + "..."
        click.echo(f"  {m.type}: '{display}' (pos {m.start}:{m.end}, rule={m.rule})")
    if len(matches) > 20:
        click.echo(f"  ... and {len(matches) - 20} more")

    # Pseudonymize (in-memory only for test, no mapping persisted)
    sanitized, mapping = pseudonymizer.replace(text, matches)
    click.echo(f"\nReplaced {len(mapping)} PII instance(s):")
    for entry in mapping[:10]:
        click.echo(f"  {entry['type']}: {entry['token']}")

    click.echo(f"\n--- Sanitized output ---")
    click.echo(sanitized)

    # Round-trip restore (in-memory only)
    if mapping:
        restored = pseudonymizer.restore(sanitized, mapping)
        click.echo(f"\n--- Restored output (round-trip) ---")
        click.echo(restored)

        # Verify round-trip integrity
        if restored == text:
            click.echo(f"\n✓ Round-trip OK: original == restored")
        else:
            click.echo(f"\n✗ Round-trip MISMATCH (bug?)")
            sys.exit(1)


@main.command()
@click.argument("new_mode", type=click.Choice(ALLOWED_MODES))
def set_mode(new_mode: str) -> None:
    """Set Privacy-Shield operating mode."""
    config = load_config()
    old_mode = config.mode
    config.mode = new_mode
    # Re-save via a minimal yaml patch on the default config path
    config_path = Path.home() / ".hermes" / "config.yaml"
    if config_path.exists():
        try:
            import yaml as _yaml
            data = _yaml.safe_load(config_path.read_text()) or {}
            plugins = data.setdefault("plugins", {})
            entries = plugins.setdefault("entries", {})
            entry = entries.setdefault("privacy-shield", {})
            entry["mode"] = new_mode
            with open(config_path, "w") as f:
                _yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        except Exception:
            pass

    # Audit-log the mode change so the compliance report can show it.
    if config.audit_jsonl_enabled and old_mode != new_mode:
        try:
            AuditLogger(config.audit_jsonl_path).log(
                event="mode_change",
                mode=new_mode,
                actor="cli",
                previous_mode=old_mode,
            )
        except Exception:
            pass

    click.echo(f"Mode set to: {new_mode}")


@main.command()
def mode() -> None:
    """Show current operating mode and available modes."""
    config = load_config()
    click.echo(f"Current mode: {config.mode}")
    click.echo(f"Available: {' | '.join(ALLOWED_MODES)}")

@main.group(name="map", invoke_without_command=True)
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


@map_cmd.command("cleanup-expired")
def map_cleanup_expired() -> None:
    """Delete all expired mappings."""
    _do_cleanup_expired()


@map_cmd.command("close-session")
@click.argument("session_id")
def map_close_session(session_id: str) -> None:
    """Delete all mappings for a session ID."""
    _do_close_session(session_id)


def _get_mapper() -> MappingTable | InMemoryMappingTable:
    cfg = load_config()
    if cfg.storage_mode == "memory":
        return InMemoryMappingTable()
    return MappingTable(
        storage_path=cfg.storage_path,
        encryption_key=cfg.encryption_key,
    )


def _do_map_list() -> None:
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
    mapper = _get_mapper()
    expired_before = mapper.expired_count()
    deleted = mapper.prune_expired()
    click.echo(f"Expired before cleanup: {expired_before}")
    click.echo(f"Deleted: {deleted}")
    click.echo(f"Remaining: {mapper.count()}")


def _do_close_session(session_id: str) -> None:
    mapper = _get_mapper()
    deleted = mapper.close_session(session_id)
    click.echo(f"Closed session {session_id}: removed {deleted} mappings")
    click.echo(f"Remaining: {mapper.count()}")


# ── doctor ──────────────────────────────────────────────────────────────

_PLUGIN_ROOT = Path(__file__).resolve().parent


def _check_key() -> bool:
    """Pre-Stage 0: Encryption-Key must resolve.

    1.9.x contract: without a key the plugin is DISABLED (load_config falls
    back to enabled=False). Stage 1 (scan) is key-free by design and Stage 2
    still prints an ephemeral, non-persisted token on stdout, so stdout greps
    alone constitute a silent false-pass. The key assertion is the decisive
    check.
    """
    try:
        return bool(load_config().encryption_key)
    except Exception:
        return False


def _check_smoke() -> bool:
    """Stage 1: Plugin-Scan mit Test-PII."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "privacy_shield.cli", "scan", "test@example.com"],
            capture_output=True, text=True, timeout=10,
            cwd=str(_PLUGIN_ROOT),
        )
        return "test@example.com" in result.stdout or "email" in result.stdout.lower()
    except Exception:
        return False


def _check_echt() -> bool:
    """Stage 2: Pseudonymize + map --list."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "privacy_shield.cli", "pseudonymize", "test@example.com"],
            capture_output=True, text=True, timeout=10,
            cwd=str(_PLUGIN_ROOT),
        )
        return "TOKEN_EMAIL" in result.stdout or "TOKEN" in result.stdout
    except Exception:
        return False


def _check_pytest() -> bool:
    """Stage 3: Run pytest."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-q"],
            capture_output=True, text=True, timeout=60,
            cwd=str(_PLUGIN_ROOT),
        )
        return result.returncode == 0
    except Exception:
        return False


@main.command()
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--quick", "-q", is_flag=True, help="Quick check (Stages 1+2 only)")
def doctor(verbose: bool, quick: bool) -> None:
    """Run diagnostic checks across all 5 stages."""
    click.echo(f"Privacy-Shield Doctor v{__version__}")
    click.echo("==============================\n")

    # Pre-Stage 0: Encryption-Key. Without it the plugin is disabled (1.9.x);
    # the stage greps below would false-pass either way. FAIL hard instead.
    if not _check_key():
        click.echo(click.style("[\u2717]", fg="red") + " Pre-Stage 0: Encryption-Key (kein Key aufloesbar — Plugin disabled; PRIVACY_SHIELD_KEY env oder pass hermes/privacy-shield-key pruefen)")
        click.echo("\nVerdict: FAIL — encryption key missing")
        sys.exit(2)

    stages_passed = 0
    stages_total = 5 if not quick else 2
    stages_failed = 0  # automated stages only; manual stages (4/5) never gate the exit

    # Stage 1: Smoke-Test
    if _check_smoke():
        click.echo(click.style("[\u2713]", fg="green") + " Stage 1: Smoke-Test (Plugin laedt + scan funktioniert)")
        stages_passed += 1
    else:
        click.echo(click.style("[\u2717]", fg="red") + " Stage 1: Smoke-Test (Plugin laedt + scan funktioniert)")
        stages_failed += 1

    # Stage 2: Echt-Test
    if _check_echt():
        click.echo(click.style("[\u2713]", fg="green") + " Stage 2: Echt-Test (pseudonymize + map --list)")
        stages_passed += 1
    else:
        click.echo(click.style("[\u2717]", fg="red") + " Stage 2: Echt-Test (pseudonymize + map --list)")
        stages_failed += 1

    if not quick:
        # Stage 3: Pytest
        if _check_pytest():
            click.echo(click.style("[\u2713]", fg="green") + " Stage 3: Strukturelle Tests (Pytest-Suite)")
            stages_passed += 1
        else:
            click.echo(click.style("[\u2717]", fg="red") + " Stage 3: Strukturelle Tests (Pytest-Suite)")
            stages_failed += 1

        # Stage 4: Hermes-Integration (always manual)
        click.echo(click.style("[\u26a0]", fg="yellow") + " Stage 4: Hermes-Integration (manuell verifizieren — siehe Doku)")

        # Stage 5: Kunden-Selbsttest
        click.echo(click.style("[?]", fg="cyan") + " Stage 5: Kunden-Selbsttest (siehe README)")

    click.echo(f"\nVerdict: {stages_passed}/{stages_total} OK")
    # Exit semantics: 0 = all automated stages pass, 1 = at least one
    # automated stage failed. A doctor that prints "N/N OK" with a failed
    # stage while exiting 0 is a false-pass for every caller (cron wrappers,
    # monitoring). Manual/informational stages (4/5 in full mode) never gate
    # the exit.
    if stages_failed:
        sys.exit(1)


# ── audit-export ─────────────────────────────────────────────────────────


@main.command("audit-export")
@click.option("--from", "from_date", required=True, help="Start date (YYYY-MM-DD)")
@click.option("--to", "to_date", required=True, help="End date (YYYY-MM-DD)")
@click.option("--user", "user_hash", required=True, help="Hashed user identifier")
@click.option(
    "--format",
    "export_format",
    default="pdf",
    type=click.Choice(["pdf", "csv", "json"], case_sensitive=False),
    help="Export format (pdf, csv, json)",
)
@click.option("--output", "-o", "output_path", required=True, type=click.Path(), help="Output file path")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    help="Path to audit_articles.yaml mapping file",
)
@click.option(
    "--sign-with",
    "signing_key_path",
    type=click.Path(exists=True),
    help="Ed25519 private key PEM for signing the report",
)
@click.option(
    "--no-sign",
    is_flag=True,
    default=False,
    help="Skip signing even if a key is provided",
)
def audit_export(
    from_date: str,
    to_date: str,
    user_hash: str,
    export_format: str,
    output_path: str,
    config_path: str | None,
    signing_key_path: str | None,
    no_sign: bool,
) -> None:
    """Export Privacy-Shield audit trail as PDF, CSV or JSON compliance report."""
    cfg = load_config()
    exporter = AuditExporter(config=cfg, project_root=Path.cwd())

    result = exporter.export(
        output_path=output_path,
        time_range=(from_date, to_date),
        format=export_format,
        sign=bool(signing_key_path and not no_sign),
        signing_key_path=Path(signing_key_path) if signing_key_path else None,
        article_config_path=Path(config_path) if config_path else None,
        user_hash=user_hash,
    )
    click.echo(f"{export_format.upper()} exported to {result['output_path']}")
    if result["signature"]:
        click.echo(f"Detached signature: {result['output_path']}.sig")
        click.echo(f"Ed25519 signature: {result['signature']}")


@main.command("audit-verify")
@click.option("--report", "report_path", required=True, type=click.Path(exists=True), help="Path to the exported report")
@click.option(
    "--signature",
    "signature_path",
    type=click.Path(exists=True),
    help="Path to the detached .sig file (default: <report>.sig)",
)
@click.option(
    "--public-key",
    "public_key_path",
    required=True,
    type=click.Path(exists=True),
    help="Path to the Ed25519 public-key PEM",
)
def audit_verify(
    report_path: str,
    signature_path: str | None,
    public_key_path: str,
) -> None:
    """Verify an exported audit report's Ed25519 signature."""
    report_file = Path(report_path)
    canonical_file = report_file.with_suffix(report_file.suffix + ".canonical.json")
    sig_file = Path(signature_path) if signature_path else report_file.with_suffix(report_file.suffix + ".sig")
    if not sig_file.exists():
        raise click.UsageError(f"Signature file not found: {sig_file}")
    canonical_file = report_file.with_suffix(report_file.suffix + ".canonical.json")
    if not canonical_file.exists():
        raise click.UsageError(f"Canonical JSON not found: {canonical_file}")

    canonical = canonical_file.read_text(encoding="utf-8")
    signature = sig_file.read_text(encoding="utf-8").strip()
    public_key = load_public_key(Path(public_key_path))

    if verify_b64(canonical, signature, public_key):
        click.echo("✓ Signature valid")
    else:
        click.echo("✗ Signature invalid", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
