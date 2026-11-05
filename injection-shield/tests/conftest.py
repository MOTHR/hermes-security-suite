"""Test configuration for injection-shield plugin."""

from __future__ import annotations

import sys
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def pytest_configure(config):  # noqa: ARG001
    """Ensure the plugins directory is on sys.path so imports work."""
    plugins_dir = str(PLUGIN_DIR.parent)
    if plugins_dir not in sys.path:
        sys.path.insert(0, plugins_dir)
