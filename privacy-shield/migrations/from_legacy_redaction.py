#!/usr/bin/env python3
"""Migration from legacy redact_pii to Privacy-Shield Plugin.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 5.12

Converts:
  config.yaml: redact_pii: true
  → config.yaml: privacy_shield.enabled: true + plugin config

Idempotent: running multiple times produces the same result.
Backup: creates config.yaml.bak before any changes.
Existing [EMAIL] markers are NOT reversed (non-reversible per Spec).

Usage:
  python from_legacy_redaction.py [--dry-run] [--config PATH]
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


def find_hermes_config(config_path: str | None = None) -> Path:
    """Find Hermes config.yaml."""
    if config_path:
        return Path(config_path).expanduser()

    # Default locations
    candidates = [
        Path.home() / ".hermes" / "config.yaml",
        Path.home() / ".hermes" / "hermes-agent" / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    print("ERROR: Could not find Hermes config.yaml")
    print("Specify with --config PATH")
    sys.exit(1)


def backup_config(config_path: Path) -> Path:
    """Create timestamped backup of config file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = config_path.with_suffix(f".yaml.bak.{timestamp}")
    shutil.copy2(config_path, backup_path)
    print(f"Backup created: {backup_path}")
    return backup_path


def has_legacy_redaction(config: dict[str, Any]) -> bool:
    """Check if config has legacy redact_pii: true."""
    return config.get("redact_pii", False) is True


def has_privacy_shield(config: dict[str, Any]) -> bool:
    """Check if privacy_shield is already configured."""
    ps = config.get("privacy_shield", {})
    return ps.get("enabled", False) is True


def migrate_config(config: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Migrate config from legacy redaction to privacy-shield.

    Returns: (migrated_config, changes_made)
    """
    changes: list[str] = []

    # Check if migration is needed
    if not has_legacy_redaction(config):
        return config, changes

    if has_privacy_shield(config):
        print("Privacy-Shield already enabled — nothing to migrate.")
        return config, changes

    # Add privacy_shield section
    config["privacy_shield"] = {
        "enabled": True,
        "mode": "limited",
        "detection": {
            "engine": "regex",
            "regex_patterns": ["email", "phone", "ip_address", "iban", "tax_id", "address"],
        },
        "pseudonymization": {
            "token_style": "deterministic",
            "token_prefix": "TOKEN",
            "preserve_context": True,
        },
        "storage": {
            "mapping_table": "sqlite",
            "sqlite_path": "~/.hermes/privacy/mapping.db",
            "encryption_key_source": "env",
            "encryption_key_env": "PRIVACY_SHIELD_KEY",
        },
        "performance": {
            "max_latency_ms": 80,
            "fallback_on_timeout": "block",
        },
    }
    changes.append("Added privacy_shield.enabled: true with Phase 1 defaults")

    # Keep redact_pii for backward compatibility (Spec: Phase 4 removes it)
    # but add a comment marker
    changes.append("Kept redact_pii: true for backward compatibility (Phase 4 removal)")

    return config, changes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Migrate from legacy redact_pii to Privacy-Shield Plugin"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without writing",
    )
    parser.add_argument(
        "--config",
        help="Path to Hermes config.yaml (auto-detected if omitted)",
    )
    args = parser.parse_args()

    config_path = find_hermes_config(args.config)
    print(f"Config: {config_path}")

    # Read current config
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    # Check if migration is needed
    if not has_legacy_redaction(config):
        print("No legacy redact_pii: true found — nothing to migrate.")
        return

    if has_privacy_shield(config):
        print("Privacy-Shield already enabled — nothing to migrate (idempotent).")
        return

    # Migrate
    new_config, changes = migrate_config(config)

    if args.dry_run:
        print("\n=== DRY RUN — Changes that would be made ===")
        for change in changes:
            print(f"  • {change}")
        print("\n=== New config (preview) ===")
        print(yaml.dump(new_config, default_flow_style=False, allow_unicode=True))
        return

    # Backup
    backup_config(config_path)

    # Write
    with open(config_path, "w") as f:
        yaml.dump(new_config, f, default_flow_style=False, allow_unicode=True)

    print("\n=== Migration complete ===")
    for change in changes:
        print(f"  ✓ {change}")
    print(f"\nConfig updated: {config_path}")
    print("Next steps:")
    print("  1. Install plugin: hermes plugin install privacy-shield")
    print("  2. Set encryption key: export PRIVACY_SHIELD_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')")
    print("  3. Restart gateway: hermes gateway restart")


if __name__ == "__main__":
    main()
