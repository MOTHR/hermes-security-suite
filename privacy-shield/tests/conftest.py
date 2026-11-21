"""Test configuration for privacy-shield plugin.

The plugin directory is named 'privacy-shield' (hyphenated, per Hermes convention)
which is not a valid Python package name. A symlink privacy_shield -> privacy-shield
in the plugins directory bridges the gap so pytest can import it as a package.
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

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

# Issue #8 (t_70e1ea18): the isolation seam must be importable before the
# first pytest_configure line runs — tests/ is not on sys.path yet here.
_TESTS_DIR = str(Path(__file__).resolve().parent)
if _TESTS_DIR not in sys.path:
    sys.path.insert(0, _TESTS_DIR)
from _ps_test_isolation import (  # noqa: E402
    PS_TEST_SINK_ENV,
    apply_test_isolation,
    assert_rotating_handlers_inside,
)


@pytest.fixture(autouse=True)
def _ps_sinks_stay_under_pytest_tmp():
    """Issue #8 Layer-3: assert, per-test, that every rotating handler
    attached to ``privacy_shield*`` loggers writes inside the pytest
    sink base. Regression instead of silent leakage (orakel K2:
    function-scoped, not session-start)."""
    yield
    sink = os.environ.get(PS_TEST_SINK_ENV)
    if sink:
        offenders = assert_rotating_handlers_inside(sink)
        assert not offenders, (
            "Issue #8: privacy_shield rotating handler(s) attached OUTSIDE "
            f"the pytest sink base {sink}: {offenders}"
        )


def pytest_sessionfinish(session, exitstatus):
    """Issue #8 Layer-3 belt: report any non-compliant sink after the run."""
    sink = os.environ.get(PS_TEST_SINK_ENV)
    if not sink:
        return
    offenders = assert_rotating_handlers_inside(sink)
    if offenders:
        sys.stderr.write(
            "WARNING (Issue #8): privacy_shield rotating handler(s) OUTSIDE "
            f"the pytest sink base {sink}: {offenders}\n"
        )


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    """Ensure the plugins directory is on sys.path + publish isolation.

    ``trylast`` (Issue #8): pytest's tempdir plugin sets
    ``config._tmp_path_factory`` in its own ``pytest_configure``; running
    after it lets the isolation redirect onto the SAME session basetemp
    the ``tmp_path`` fixture files land under. Hook ordering still fires
    this strictly before collection, so no test module (and no plugin
    ``__init__``) runs unisolated.
    """
    # ── Layer-1 isolation FIRST: fake-home redirect + hard-set sinks. ─────
    # The attach happens at plugin-INIT (never at import), so the hard-set
    # must be in place before ANY test module is collected or imported and
    # ambient production env must be overridden, not merely defaulted to
    # if-unset semantics (the old env fallback respected a pre-set
    # production value — orakel probe B3).
    try:
        tmp_base = Path(config._tmp_path_factory.getbasetemp())
    except AttributeError:
        from _pytest.tmpdir import TempPathFactory

        factory = TempPathFactory.from_config(config, _ispytest=True)
        config._tmp_path_factory = factory
        tmp_base = factory.getbasetemp()
    apply_test_isolation(tmp_base)

    # The repo root must win import resolution: pytest prepends rootdir, but
    # this hook re-inserted ~/.hermes/plugins at index 0, so 'import
    # privacy_shield' resolved to the DEPLOYED copy (c001 worktree via
    # symlink) instead of the code under test — the finalize-hook tests
    # silently tested the wrong package (no on_session_finalize there).
    # Repo root first puts the tested copy ahead of the deployed symlink.
    repo_root = str(PLUGIN_DIR)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    # tests/ itself is importable (shared seam helpers for v1.9.0 contract tests).
    if _TESTS_DIR not in sys.path:
        sys.path.insert(0, _TESTS_DIR)
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
