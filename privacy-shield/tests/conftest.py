"""Test configuration for privacy-shield plugin.

The plugin directory is named 'privacy-shield' (hyphenated, per Hermes convention)
which is not a valid Python package name. A symlink privacy_shield -> privacy-shield
in the plugins directory bridges the gap so pytest can import it as a package.
"""

import os
import sys
import tempfile
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent
# Import-path selection: plugins/privacy-shield is a symlink to the active
# worktree, so Path(__file__) always resolves INTO the worktree tree — the
# plugins dir that holds the privacy_shield (underscore) symlink is not
# derivable from __file__. Prefer PRIVACY_SHIELD_PLUGINS_DIR, else the
# canonical Hermes plugins dir; the worktree parent is only a fallback.
_PLUGIN_PARENT_CANDIDATES = (
    os.environ.get("PRIVACY_SHIELD_PLUGINS_DIR"),
    str(Path.home() / ".hermes" / "plugins"),
    str(PLUGIN_DIR.parent),
)


def pytest_configure(config):
    """Ensure the plugins directory is on sys.path so 'import privacy_shield' works."""
    # The repo root must win import resolution: pytest prepends rootdir, but
    # this hook re-inserted ~/.hermes/plugins at index 0, so 'import
    # privacy_shield' resolved to the DEPLOYED copy (c001 worktree via
    # symlink) instead of the code under test — the finalize-hook tests
    # silently tested the wrong package (no on_session_finalize there).
    # Repo root first puts the tested copy ahead of the deployed symlink.
    repo_root = str(PLUGIN_DIR)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    for candidate in _PLUGIN_PARENT_CANDIDATES:
        if (
            not candidate
            or not Path(candidate, "privacy_shield", "__init__.py").exists()
        ):
            continue
        plugins_dir = str(candidate)
        if plugins_dir not in sys.path:
            sys.path.insert(0, plugins_dir)
        break

    # Pin the package to the code under test BEFORE any test module
    # imports it. The repo is itself the package (flat layout, __init__.py
    # at repo root), so plain sys.path ordering cannot override a
    # plugins-dir candidate that contains a privacy_shield/ subtree — that
    # shipped a stale copy (PS-REST-003 test runs silently exercised it:
    # plugin.py/processors.py resolved to the c001 worktree while
    # fs_hardening resolved to the repo). Pre-seeding sys.modules makes
    # every submodule import (privacy_shield.plugin, .processors, ...)
    # resolve against the repo deterministically.
    if "privacy_shield" not in sys.modules:
        import importlib.util

        pkg_spec = importlib.util.spec_from_file_location(
            "privacy_shield",
            str(PLUGIN_DIR / "__init__.py"),
            submodule_search_locations=[repo_root],
        )
        pkg = importlib.util.module_from_spec(pkg_spec)
        sys.modules["privacy_shield"] = pkg
        pkg_spec.loader.exec_module(pkg)
    elif (
        Path(getattr(sys.modules["privacy_shield"], "__file__", "")).resolve()
        != (PLUGIN_DIR / "__init__.py").resolve()
    ):
        # Already imported from the wrong copy (e.g. a pytest plugin
        # imported privacy_shield first) — replace it deterministically.
        import importlib

        del sys.modules["privacy_shield"]
        for stale in [m for m in list(sys.modules) if m.startswith("privacy_shield.")]:
            del sys.modules[stale]
        sys.path.insert(0, repo_root)
        importlib.import_module("privacy_shield")

    # Test-log isolation: redirect the rotating operator log to pytest's
    # tmp base dir so test fixtures never append to the production
    # privacy-shield.log. setdefault keeps a pre-set value authoritative.
    try:
        tmp_base = config._tmp_path_factory.getbasetemp()
    except AttributeError:
        tmp_base = Path(tempfile.gettempdir()) / "privacy-shield-pytest"
    os.environ.setdefault(
        "PRIVACY_SHIELD_AUDIT_LOG_PATH",
        str(tmp_base / "privacy-shield-test.log"),
    )
