#!/usr/bin/env python3
"""Enable privacy-shield in Hermes profile config.yaml.

Idempotent: profiles that already have privacy-shield enabled are left
unchanged. Supports canary deployments via --canary-profiles and exclusions
via --exclude-profiles.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

PROFILES_DIR = Path.home() / ".hermes" / "profiles"


def _parse_comma_list(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(part.strip() for part in value.split(",") if part.strip())


def enable_profile(
    profile_dir: Path,
    *,
    canary: frozenset[str],
    exclude: frozenset[str],
) -> str:
    name = profile_dir.name
    config_path = profile_dir / "config.yaml"

    if name in exclude:
        return f"{name}: EXCLUDED"

    if canary and name not in canary:
        return f"{name}: SKIPPED (CANARY: not in target set)"

    if not config_path.exists():
        return f"{name}: NO_CONFIG"

    try:
        text = config_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
    except (OSError, yaml.YAMLError) as exc:
        return f"{name}: PARSE_ERROR ({exc})"

    plugins = data.setdefault("plugins", {})
    enabled = plugins.setdefault("enabled", [])

    if "privacy-shield" in enabled:
        return f"{name}: OK"

    enabled.append("privacy-shield")

    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        return f"{name}: ENABLED"
    except OSError as exc:
        return f"{name}: WRITE_ERROR ({exc})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enable privacy-shield in Hermes profile config.yaml files."
    )
    parser.add_argument(
        "--canary-profiles",
        metavar="NAMES",
        default="",
        help="Comma-separated list of profiles to touch; all others are skipped.",
    )
    parser.add_argument(
        "--exclude-profiles",
        metavar="NAMES",
        default="",
        help="Comma-separated list of profiles to leave untouched.",
    )
    args = parser.parse_args(argv)

    canary = _parse_comma_list(args.canary_profiles)
    exclude = _parse_comma_list(args.exclude_profiles)

    if not PROFILES_DIR.exists():
        print(f"Profiles directory not found: {PROFILES_DIR}", file=sys.stderr)
        return 1

    results: list[str] = []
    for profile_dir in sorted(PROFILES_DIR.iterdir()):
        if profile_dir.is_dir():
            results.append(enable_profile(profile_dir, canary=canary, exclude=exclude))

    for r in results:
        if canary or "EXCLUDED" in r:
            print(f"CANARY: {r}")
        else:
            print(r)

    if any("ENABLED" in r or "OK" in r for r in results):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
