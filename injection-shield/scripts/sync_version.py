#!/usr/bin/env python3
"""FIX-IS-DRIFT (LinkDevOps R3 LINK-1): Sync version between plugin.yaml
(human-readable mirror) and __init__.py (canonical single-source-of-truth).

Run from anywhere — paths are resolved relative to this script:

    python scripts/sync_version.py           # sync to __init__.py version
    python scripts/sync_version.py --check   # verify sync, exit 1 if drift

Architecture (post-FIX-IS-DRIFT):

  * ``__init__.py:__version__`` is the canonical SSO source.
  * ``plugin.yaml:version`` is a human-readable mirror, kept in sync by
    this script. (Hermes' ``plugins info`` loader reads
    ``importlib.metadata`` which itself comes from the installed wheel —
    so ``plugin.yaml`` is informational only, but it must still agree
    so operators reading the YAML directly see the right version.)
  * ``pyproject.toml`` declares ``dynamic = ["version"]`` and reads
    ``injection_shield.__version__`` via
    ``[tool.setuptools.dynamic] attr = "injection_shield.__version__"``
    at build time. The wheel/SDIST inherit the canonical version
    automatically; this script does NOT touch pyproject.toml.

Strict mode (default for ``--check``): a drift between
``__init__.py`` and ``plugin.yaml`` returns exit code 1 with a precise
diff on stderr. This is the behaviour the release pipeline wants —
silent drift is the bug we are fixing.

The script intentionally does NOT auto-bump the version. The human
operator edits ``__init__.py`` (canonical) and re-runs the sync; that
keeps a single source of truth and a clear audit trail.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Resolve all paths relative to the plugin root (parent of scripts/).
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_YAML = PLUGIN_ROOT / "plugin.yaml"
INIT_PY = PLUGIN_ROOT / "__init__.py"
# Additional version-bearing files that must agree with the canonical
# version (link-devops review t_d6d44679: they drifted while the canonical
# sources stayed in sync because sync_version never looked at them).
EXTRA_VERSION_SOURCES = (
    PLUGIN_ROOT / "plugin.de.yaml",
    PLUGIN_ROOT / "dashboard" / "manifest.json",
)

# Covers both shapes: YAML `version: "1.2.3"` and JSON `"version": "1.2.3"`.
_VERSION_LINE_RE = re.compile(
    r'(?P<mode>^\s*"version"\s*:|^\s*version:)\s*"(?P<v>[^"]+)"',
    re.MULTILINE,
)


class VersionError(RuntimeError):
    """Raised when the version cannot be located or the file format is unexpected."""


def read_yaml_version(path: Path = PLUGIN_YAML) -> str:
    """Read the top-level ``version: "X.Y.Z"`` from plugin.yaml.

    We avoid pulling in PyYAML here: plugin.yaml is structurally simple
    (no nested anchors, no multi-doc), and a regex keeps the script
    runnable in any venv without extras.
    """
    text = path.read_text(encoding="utf-8")
    # Match the first line that is exactly ``version: "..."`` (quoted).
    # We deliberately do NOT match unquoted values — plugin.yaml uses
    # quotes consistently and we want to fail loudly if that changes.
    match = re.search(r"^version:\s*\"([^\"]+)\"\s*$", text, re.MULTILINE)
    if not match:
        raise VersionError(
            f'No quoted top-level `version: "X.Y.Z"` found in {path}'
        )
    return match.group(1)


def read_init_version(path: Path = INIT_PY) -> str:
    """Read the canonical ``__version__ = "X.Y.Z"`` from __init__.py.

    Allows an optional trailing comment (e.g. ``# SSO marker``) which
    is a convention we use to flag the SSO source line.
    """
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r"^__version__\s*=\s*\"([^\"]+)\"",
        text,
        re.MULTILINE,
    )
    if not match:
        raise VersionError(
            f'No `__version__ = "X.Y.Z"` found in {path}'
        )
    return match.group(1)


def _set_yaml_version(text: str, version: str) -> str:
    """Replace the top-level ``version: "X.Y.Z"`` line in plugin.yaml."""
    new_text, n = re.subn(
        r"^version:\s*\"[^\"]+\"\s*$",
        f'version: "{version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if n != 1:
        raise VersionError(
            f"Could not locate exactly one top-level `version:` line in {PLUGIN_YAML}"
        )
    return new_text


def _set_init_version(text: str, version: str) -> str:
    """Update the canonical ``__version__ = "X.Y.Z"`` line in __init__.py.

    Preserves any trailing comment on the existing line (e.g. the SSO
    marker comment).
    """
    pattern = re.compile(
        r"^(?P<prefix>__version__\s*=\s*\"[^\"]+\")(?P<trail>\s*#[^\n]*)?",
        re.MULTILINE,
    )

    def repl(m: re.Match[str]) -> str:
        trail = m.group("trail") or ""
        return f'__version__ = "{version}"{trail}'

    new_text, n = pattern.subn(repl, text, count=1)
    if n != 1:
        raise VersionError(
            f"Could not locate exactly one `__version__ = \"...\"` line in {INIT_PY}"
        )
    return new_text


def sync(version: str | None = None) -> str:
    """Write ``version`` (defaulting to ``__init__.py``'s current value)
    into plugin.yaml. Returns the version that was synced.

    The canonical source is ``__init__.py``; we do NOT touch
    pyproject.toml (dynamic attribution reads it at build time).
    """
    version = version or read_init_version()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise VersionError(
            f"Refusing to sync non-semver version: {version!r}"
        )

    yaml_text = PLUGIN_YAML.read_text(encoding="utf-8")
    PLUGIN_YAML.write_text(_set_yaml_version(yaml_text, version),
                           encoding="utf-8")

    for extra in EXTRA_VERSION_SOURCES:
        if not extra.exists():
            continue
        text = extra.read_text(encoding="utf-8")
        new_text, n = _VERSION_LINE_RE.subn(
            lambda m: f'{m.group("mode")} "{version}"', text, count=1
        )
        if n != 1:
            raise VersionError(f"Could not locate version line in {extra}")
        extra.write_text(new_text, encoding="utf-8")

    return version


def check() -> int:
    """Exit 0 if __init__.py and plugin.yaml agree on the version.
    Exit 1 (and print a precise diff) if not.

    Note: pyproject.toml is intentionally NOT checked here because it
    carries the canonical version via dynamic attribution
    (``[tool.setuptools.dynamic]``); the wheel/SDIST is the artefact
    that proves SSO is intact, and a separate test asserts
    ``importlib.metadata.version("injection-shield")`` matches.
    """
    yaml_v = read_yaml_version()
    init_v = read_init_version()

    if yaml_v == init_v:
        print(f"OK: __init__.py and plugin.yaml agree on version {init_v}")
        return 0

    print("VERSION DRIFT DETECTED:", file=sys.stderr)
    print(f"  plugin.yaml    : {yaml_v}", file=sys.stderr)
    print(f"  __init__.py    : {init_v}", file=sys.stderr)
    print("Run `python scripts/sync_version.py` to reconcile.",
          file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true",
                       help="Verify sync only; do not modify files.")
    group.add_argument("--set", metavar="VERSION",
                       help="Override __init__.py AND write the new "
                            "version into plugin.yaml.")
    args = parser.parse_args(argv)

    if args.check:
        return check()

    if args.set:
        if not re.fullmatch(r"\d+\.\d+\.\d+", args.set):
            print(f"error: refusing non-semver version {args.set!r}",
                  file=sys.stderr)
            return 2
        # Bump the canonical source first, then sync the mirror.
        init_text = INIT_PY.read_text(encoding="utf-8")
        INIT_PY.write_text(_set_init_version(init_text, args.set),
                           encoding="utf-8")
        version = sync(args.set)
    else:
        version = sync()

    print(f"Synced version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
