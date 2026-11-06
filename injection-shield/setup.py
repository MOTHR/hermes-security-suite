"""Setuptools hooks for injection-shield.

v0.5.0 (Desktop-Controls): on ``pip install`` / ``pip install -e .`` we copy
``desktop/`` into ``~/.hermes/desktop-plugins/injection-shield-controls/``
so the bundled desktop UI is available immediately. The backend files under
``dashboard/`` are shipped in the wheel via MANIFEST.in and mounted by the
Hermes dashboard plugin system.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.develop import develop as _develop
from setuptools.command.install import install as _install

logger = logging.getLogger(__name__)

DEST_NAME = "injection-shield-controls"


def _install_desktop_plugin() -> None:
    """Copy bundled desktop plugin into the Hermes desktop-plugins directory."""
    source = Path(__file__).resolve().parent / "desktop"
    if not source.exists():
        logger.warning("injection-shield: desktop plugin source not found at %s", source)
        return

    dest = Path.home() / ".hermes" / "desktop-plugins" / DEST_NAME
    try:
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(source, dest)
        logger.info("injection-shield: installed desktop plugin to %s", dest)
    except Exception as exc:  # noqa: BLE001 - best-effort installation
        logger.warning("injection-shield: failed to install desktop plugin: %s", exc)


class install(_install):
    def run(self) -> None:
        super().run()
        _install_desktop_plugin()


class develop(_develop):
    def run(self) -> None:
        super().run()
        _install_desktop_plugin()


setup(
    cmdclass={
        "install": install,
        "develop": develop,
    },
)
