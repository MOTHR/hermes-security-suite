"""Setuptools shim for injection-shield.

All metadata lives in pyproject.toml; Hermes ships the plugin's ``desktop/``
and ``dashboard/`` halves itself via ``hermes plugins install`` +
``hermes plugins enable``. No install-time side effects.
"""

from setuptools import setup

setup()
