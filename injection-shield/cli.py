"""Injection-Shield CLI — runtime introspection and maintenance.

Subcommands:
    validate-config  Load plugin.yaml + config.py, validate schema, exit 0/1
    prune-logs       Run DSGVO retention prune (90-day auto-cleanup)
    status           Print version, hook count, audit log size, session hash
    version          Print __version__ and exit
"""

from __future__ import annotations

import argparse
import sys
import typing
from pathlib import Path

from injection_shield.config import load_config, validate_config

from injection_shield import __version__


def _load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        return {}
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def cmd_validate_config(_args: argparse.Namespace) -> int:
    """Validate plugin.yaml and runtime config."""
    issues: list[str] = []

    # 1. Validate plugin.yaml shape
    yaml_path = Path(__file__).resolve().parent / "plugin.yaml"
    manifest = _load_yaml(yaml_path)
    if not isinstance(manifest, dict):
        issues.append("plugin.yaml is not a valid YAML dict")
    else:
        if "name" not in manifest:
            issues.append("plugin.yaml missing 'name'")
        if "version" not in manifest:
            issues.append("plugin.yaml missing 'version'")
        hooks = manifest.get("provides_hooks", [])
        if not isinstance(hooks, list) or len(hooks) == 0:
            issues.append("plugin.yaml provides_hooks is empty or malformed")

    # 2. Validate runtime config
    cfg = load_config()
    cfg_issues = validate_config(cfg)
    issues.extend(cfg_issues)

    if issues:
        print("Config validation FAILED:", file=sys.stderr)
        for issue in issues:
            print(f"  - {issue}", file=sys.stderr)
        return 1

    print("Config validation OK")
    return 0


def cmd_prune_logs(_args: argparse.Namespace) -> int:
    """Run audit-log retention prune."""
    from injection_shield.plugin import InjectionShieldPlugin

    plugin = InjectionShieldPlugin()
    plugin._prune_expired_entries()
    print("Audit log prune completed.")
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    """Print runtime status."""
    from injection_shield.plugin import InjectionShieldPlugin, _hash_session_key

    plugin = InjectionShieldPlugin()
    audit_log = plugin.audit_log
    audit_size = audit_log.stat().st_size if audit_log.exists() else 0
    session_hash = _hash_session_key("")

    # Hook count from plugin.yaml
    yaml_path = Path(__file__).resolve().parent / "plugin.yaml"
    manifest = _load_yaml(yaml_path)
    hooks = manifest.get("provides_hooks", [])
    hook_count = len(hooks)

    print(f"version:        {__version__}")
    print(f"hooks:          {hook_count}")
    print(f"audit_log_size: {audit_size}")
    print(f"session_hash:   {session_hash}")
    return 0


def cmd_mcp_status(_args: argparse.Namespace) -> int:
    """Print MCP trust levels for all known servers."""
    from injection_shield.mcp.trust_store import TrustStore

    store = TrustStore()
    summary = store.summary()
    servers = ["obsidian", "telegram", "github", "vault_search", "browseos"]

    print(f"{'Server':<15} {'Trust':<12} {'Hashes':<8} {'First Seen':<25} {'Last Seen'}")
    print("-" * 90)
    for sid in servers:
        entry = summary.get(sid, {})
        level = entry.get("level", "unknown")
        hashes = entry.get("hash_count", 0)
        first = entry.get("first_seen", "—")[:24]
        last = entry.get("last_seen", "—")[:24]
        print(f"{sid:<15} {level:<12} {hashes:<8} {first:<25} {last}")
    return 0


def cmd_mcp_verify(args: argparse.Namespace) -> int:
    """Trigger manual hash verification for a specific MCP server."""
    from injection_shield.mcp.integrity import ResponseHasher
    from injection_shield.mcp.trust_store import TrustLevel, TrustStore

    server_id: str = args.server
    store = TrustStore()
    hasher = ResponseHasher()

    current = store.get(server_id)
    print(f"Server:       {server_id}")
    print(f"Trust level:  {current.value}")

    if current == TrustLevel.UNKNOWN:
        print("\nNo baseline found. The next observed response will establish one.")
        print("Run an MCP tool for this server and check again.")
        return 0

    entries = hasher.read_log(server_id)
    print(f"Hash entries: {len(entries)}")
    if entries:
        print(f"Last digest:  {entries[-1].get('digest', '—')}")
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_attacks_list(args: argparse.Namespace) -> int:
    """List detections filtered by OWASP or ATLAS framework."""
    from injection_shield.owasp_atlas_mapping import (
        all_mappings,
        mappings_by_atlas,
        mappings_by_owasp,
    )

    framework: str = args.framework

    if framework == "owasp":
        # Group by OWASP risk code
        risks = sorted({m.owasp_risk for m in all_mappings() if m.owasp_risk})
        for risk in risks:
            ms = mappings_by_owasp(risk)
            print(f"\nOWASP {risk} — {ms[0].owasp_name if ms else 'Unknown'}")
            for m in ms:
                print(f"  • {m.detector_name} | ATLAS: {m.atlas_technique or '—'}")
    elif framework == "atlas":
        # Group by ATLAS technique
        techniques = sorted({m.atlas_technique for m in all_mappings() if m.atlas_technique})
        for tech in techniques:
            ms = mappings_by_atlas(tech)
            print(f"\n{tech} — {ms[0].atlas_name if ms else 'Unknown'}")
            for m in ms:
                print(f"  • {m.detector_name} | OWASP: {m.owasp_risk or '—'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="injection-shield",
        description="Injection-Shield — prompt-injection defense CLI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Print version and exit",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("validate-config", help="Validate plugin.yaml + runtime config")
    sub.add_parser("prune-logs", help="Run DSGVO audit-log retention prune")
    sub.add_parser("status", help="Print version, hooks, audit size, session hash")
    sub.add_parser("version", help="Print version and exit")

    # v0.3.3 OWASP/ATLAS attack listing subcommand
    attacks_parser = sub.add_parser("attacks", help="List attack categories mapped to OWASP/ATLAS")
    attacks_sub = attacks_parser.add_subparsers(dest="attacks_command")
    attacks_list_parser = attacks_sub.add_parser("list", help="List detections by framework")
    attacks_list_parser.add_argument(
        "--framework",
        choices=["owasp", "atlas"],
        required=True,
        help="Framework filter: owasp or atlas",
    )

    # v0.4.0 MCP Integrity subcommands
    mcp_parser = sub.add_parser("mcp", help="MCP integrity commands")
    mcp_sub = mcp_parser.add_subparsers(dest="mcp_command")
    mcp_sub.add_parser("status", help="Show trust levels for all MCP servers")
    mcp_verify_parser = mcp_sub.add_parser("verify", help="Manually verify an MCP server")
    mcp_verify_parser.add_argument("server", help="MCP server ID (e.g. obsidian, github)")

    args = parser.parse_args(argv)
    if args.command is None:
        # Default to version so `injection-shield --version` and a bare
        # invocation both print the version string.
        args.command = "version"
    mapping: dict[str, typing.Callable[[argparse.Namespace], int]] = {
        "validate-config": cmd_validate_config,
        "prune-logs": cmd_prune_logs,
        "status": cmd_status,
        "version": cmd_version,
    }
    handler = mapping.get(args.command)
    if handler is None:
        # Could be an mcp or attacks subcommand
        if args.command == "mcp" and hasattr(args, "mcp_command") and args.mcp_command:
            mcp_mapping = {
                "status": cmd_mcp_status,
                "verify": cmd_mcp_verify,
            }
            mcp_handler = mcp_mapping.get(args.mcp_command)
            if mcp_handler:
                return mcp_handler(args)
        if args.command == "attacks" and hasattr(args, "attacks_command") and args.attacks_command:
            attacks_mapping: dict[str, typing.Callable[[argparse.Namespace], int]] = {
                "list": cmd_attacks_list,
            }
            attacks_handler = attacks_mapping.get(args.attacks_command)
            if attacks_handler:
                return attacks_handler(args)
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
