#!/usr/bin/env python3
"""Cross-platform profile auto-setup for privacy-shield.

Walks every directory under ``~/.hermes/profiles`` and appends
``privacy-shield`` to each profile's ``plugins.enabled`` list in
``config.yaml``. Idempotent: profiles where the plugin is already listed are
skipped (counted as ``skipped``).

Usage::

    python scripts/setup_profiles.py

Exit codes:
    0 — all profiles processed (enabled or skipped)
    1 — fatal error (profiles dir missing or plugin not installed)

Ported from injection-shield FIX-3C (R3 CRIT-3) for privacy-shield
(BUTLER-PS-5).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

DEFAULT_PROFILES_DIR = Path.home() / ".hermes" / "profiles"
PLUGIN_NAME = "privacy-shield"
DEFAULT_PLUGIN_DIRS = (
    Path.home() / ".hermes" / "plugins" / PLUGIN_NAME,
    Path.home() / ".hermes" / "plugins" / "privacy_shield",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enable the privacy-shield plugin across every Hermes profile."
    )
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        default=DEFAULT_PROFILES_DIR,
        help=f"Profiles directory (default: {DEFAULT_PROFILES_DIR})",
    )
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=None,
        help="Override the plugin existence check (used for testing). "
             "Defaults to checking ~/.hermes/plugins/{privacy-shield,privacy_shield}.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    profiles_dir: Path = args.profiles_dir
    plugin_override: Path | None = args.plugin_dir

    if not profiles_dir.exists():
        print(f"ERROR: {profiles_dir} not found")
        return 1

    if plugin_override is not None:
        if not plugin_override.exists():
            print(f"ERROR: Plugin {PLUGIN_NAME} not found at {plugin_override}")
            return 1
    elif not any(p.exists() for p in DEFAULT_PLUGIN_DIRS):
        print(f"ERROR: Plugin {PLUGIN_NAME} not found in ~/.hermes/plugins/")
        return 1

    profiles = sorted(p.name for p in profiles_dir.iterdir() if p.is_dir())
    print(f"Found {len(profiles)} profiles: {', '.join(profiles)}\n")

    enabled_count = 0
    skipped_count = 0
    error_count = 0

    for profile in profiles:
        config_path = profiles_dir / profile / "config.yaml"
        if not config_path.exists():
            print(f"WARN {profile}: no config.yaml, skipping")
            skipped_count += 1
            continue

        try:
            with open(config_path, encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            plugins = config.setdefault("plugins", {})
            if not isinstance(plugins, dict):
                print(f"FAIL {profile}: 'plugins' is not a mapping ({type(plugins).__name__})")
                error_count += 1
                continue

            enabled = plugins.setdefault("enabled", [])
            if not isinstance(enabled, list):
                print(f"FAIL {profile}: 'plugins.enabled' is not a list")
                error_count += 1
                continue

            if PLUGIN_NAME in enabled:
                print(f"OK   {profile}: already enabled")
                skipped_count += 1
                continue

            enabled.append(PLUGIN_NAME)

            with open(config_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

            print(f"OK   {profile}: enabled")
            enabled_count += 1
        except yaml.YAMLError as exc:
            print(f"FAIL {profile}: YAML parse error — {exc}")
            error_count += 1
        except OSError as exc:
            print(f"FAIL {profile}: I/O error — {exc}")
            error_count += 1

    print(f"\n=== Setup complete ===")
    print(f"Enabled: {enabled_count}, Skipped: {skipped_count}, Errors: {error_count}")
    print(f"\nVerify: hermes plugins list | grep {PLUGIN_NAME}")

    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
