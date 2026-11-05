#!/usr/bin/env python3
"""FIX-PS5 (Privacy-Shield): Sync version from plugin.yaml (single source of truth)
to pyproject.toml and __init__.py.

Run from anywhere — paths are resolved relative to this script::

    python scripts/sync_version.py           # sync to plugin.yaml version
    python scripts/sync_version.py --check   # verify sync, exit 1 if drift

Strict mode (default for ``--check``): a drift between any of the three
sources returns exit code 1 with a precise diff on stderr. This is the
behaviour the release pipeline wants — silent drift is the bug we are
fixing.

The script intentionally does NOT auto-bump the version. The human
operator (or release script) edits ``plugin.yaml`` and re-runs the sync;
that keeps a single source of truth and a clear audit trail.

Ported from injection-shield FIX-3A (R3 CRIT-1) for privacy-shield
(BUTLER-PS-1 / BUTLER-PS-5).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Resolve all paths relative to the plugin root (parent of scripts/).
PLUGIN_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_YAML = PLUGIN_ROOT / "plugin.yaml"
PYPROJECT = PLUGIN_ROOT / "pyproject.toml"
INIT_PY = PLUGIN_ROOT / "__init__.py"


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


def _is_pyproject_dynamic(text: str) -> bool:
    """Return True when pyproject.toml uses dynamic ``version``."""
    return bool(
        re.search(r"^dynamic\s*=\s*\[\s*\"version\"\s*\]", text, re.MULTILINE)
        and '{attr = "privacy_shield.__version__"}' in text
    )


def _set_pyproject_version(text: str, version: str) -> str:
    """Ensure the ``[project]`` block declares a dynamic version.

    In v1.4.0+ the version is read from ``privacy_shield.__version__`` so
    pyproject.toml no longer hard-codes it. If the file still contains a
    static ``version = \"...\"`` line, replace it with ``dynamic`` and add
    the ``[tool.setuptools.dynamic]`` table. If it is already dynamic, leave
    it untouched.
    """
    if _is_pyproject_dynamic(text):
        return text

    pattern = re.compile(
        r"(?P<header>^\[project\]\s*\n)"
        r"(?P<body>(?:[^\[\n].*\n?)*?)"
        r"version\s*=\s*\"[^\"]+\"",
        re.MULTILINE,
    )

    dynamic_block = '\n[tool.setuptools.dynamic]\nversion = {attr = "privacy_shield.__version__"}\n'

    def repl(m: re.Match[str]) -> str:
        return f'{m.group("header")}{m.group("body")}dynamic = ["version"]{dynamic_block}'

    new_text, n = pattern.subn(repl, text, count=1)
    if n != 1:
        raise VersionError(
            f"Could not locate exactly one `[project]` version line in {PYPROJECT}"
        )
    return new_text


def _set_init_version(text: str, version: str) -> str:
    """Insert or update ``__version__ = "X.Y.Z"``.

    Placement rules (in priority order):

    1. If ``__version__`` already exists, replace it in place.
    2. Otherwise, insert it as the FIRST non-future, non-stdlib import
       block sits below the docstring. Concretely: find the docstring
       end, then walk past ``from __future__`` and stdlib imports
       (``from typing``, ``import os`` etc.), and place ``__version__``
       right before the first **relative** import (``from .plugin`` /
       ``from . import``) or the first third-party import.
    3. Fallback: if we cannot find any of the above anchors, append
       ``__version__`` immediately after the docstring.

    Why not "directly after docstring"? Because PEP 8 / language spec
    require ``from __future__ import annotations`` to be the FIRST
    import in the module; dropping ``__version__`` between the docstring
    and ``from __future__`` would shift that line down and break the
    SyntaxError contract — exactly the regression our first sync run
    introduced and these tests guard against.
    """
    if re.search(r"^__version__\s*=", text, re.MULTILINE):
        return re.sub(
            r"^__version__\s*=\s*\"[^\"]+\"",
            f'__version__ = "{version}"',
            text,
            count=1,
            flags=re.MULTILINE,
        )

    doc_re = re.compile(
        r'^(?P<quote>"""|\'\'\')(?P<body>.*?)^(?P=quote)\s*$',
        re.MULTILINE | re.DOTALL,
    )
    m = doc_re.search(text)
    if m is None:
        # No docstring — insert at the very top of the file.
        return f'__version__ = "{version}"\n\n{text}'

    # Walk forward from the docstring end, skipping future-imports and
    # plain stdlib imports. Stop at the first line that is either a
    # relative import (``from .x import ...``) or anything that is not
    # a future/stdlib import.
    future_or_stdlib = re.compile(
        r"^\s*(from\s+__future__\s+import\s+|"
        r"from\s+[a-zA-Z_][\w\.]*\s+import\s+|"
        r"import\s+[a-zA-Z_][\w\.]*)",
    )

    lines = text.splitlines(keepends=True)
    # Find line index where docstring ends (m.end() is char offset).
    char_end = m.end()
    line_idx = text[:char_end].count("\n")  # 0-indexed line just AFTER docstring

    insert_idx = line_idx  # default: right after docstring
    while insert_idx < len(lines):
        line = lines[insert_idx]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            insert_idx += 1
            continue
        if future_or_stdlib.match(line):
            insert_idx += 1
            continue
        # First non-future, non-stdlib line — insert just before it.
        break

    # Ensure exactly one blank line between the previous block and __version__.
    prefix = "".join(lines[:insert_idx])
    suffix = "".join(lines[insert_idx:])

    # Strip trailing whitespace from prefix and add a single blank line
    # separator so __version__ sits in its own paragraph.
    prefix_stripped = prefix.rstrip() + "\n\n"
    return f'{prefix_stripped}__version__ = "{version}"\n\n{suffix}'


def sync(version: str | None = None) -> str:
    """Write ``version`` (defaulting to plugin.yaml's current value) into
    __init__.py and ensure pyproject.toml declares a dynamic version.
    Returns the version that was synced.
    """
    version = version or read_yaml_version()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise VersionError(
            f"Refusing to sync non-semver version: {version!r}"
        )

    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    PYPROJECT.write_text(_set_pyproject_version(pyproject_text, version),
                         encoding="utf-8")

    init_text = INIT_PY.read_text(encoding="utf-8")
    INIT_PY.write_text(_set_init_version(init_text, version),
                       encoding="utf-8")

    return version


def check() -> int:
    """Exit 0 if plugin.yaml and __init__.py agree and pyproject.toml is
    dynamic. Exit 1 (and print a precise diff) if not.
    """
    yaml_v = read_yaml_version()

    pyproject_text = PYPROJECT.read_text(encoding="utf-8")
    if _is_pyproject_dynamic(pyproject_text):
        pyproject_v = f"dynamic -> {yaml_v}"
    else:
        pyproject_m = re.search(
            r"^\[project\][\s\S]*?^\s*version\s*=\s*\"([^\"]+)\"",
            pyproject_text,
            re.MULTILINE,
        )
        pyproject_v = pyproject_m.group(1) if pyproject_m else "<missing>"

    init_text = INIT_PY.read_text(encoding="utf-8")
    init_m = re.search(r"^__version__\s*=\s*\"([^\"]+)\"",
                       init_text, re.MULTILINE)
    init_v = init_m.group(1) if init_m else "<missing>"

    if yaml_v == init_v and (pyproject_v.startswith("dynamic") or pyproject_v == init_v):
        print(f"OK: all sources agree on version {yaml_v}")
        return 0

    print("VERSION DRIFT DETECTED:", file=sys.stderr)
    print(f"  plugin.yaml    : {yaml_v}", file=sys.stderr)
    print(f"  pyproject.toml : {pyproject_v}", file=sys.stderr)
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
                       help="Override plugin.yaml AND write the new "
                            "version into pyproject.toml + __init__.py.")
    args = parser.parse_args(argv)

    if args.check:
        return check()

    if args.set:
        if not re.fullmatch(r"\d+\.\d+\.\d+", args.set):
            print(f"error: refusing non-semver version {args.set!r}",
                  file=sys.stderr)
            return 2
        # Bump the source of truth first, then sync everything else.
        text = PLUGIN_YAML.read_text(encoding="utf-8")
        new_text, n = re.subn(
            r"^version:\s*\"[^\"]+\"\s*$",
            f'version: "{args.set}"',
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n != 1:
            raise VersionError("Could not locate plugin.yaml version line")
        PLUGIN_YAML.write_text(new_text, encoding="utf-8")
        version = sync(args.set)
    else:
        version = sync()

    print(f"Synced version {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
