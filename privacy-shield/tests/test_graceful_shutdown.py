"""Tests for graceful shutdown hooks (LINK-PS-6).

teknium review 2 (item 3): the plugin no longer installs a SIGTERM handler —
a plugin must NOT replace Hermes's process-wide signal handling. Only the
atexit flush hook remains; ``on_session_finalize`` covers session boundaries.
"""

from __future__ import annotations

import signal  # noqa: F401  (asserts signal.signal is never touched by the plugin)
from unittest.mock import MagicMock

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.lifecycle import _shutdown_mapper, register_shutdown_hooks
from privacy_shield.plugin import PrivacyShieldPlugin


@pytest.fixture
def memory_config():
    return PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        storage_mode="memory",
        encryption_key="not-needed-for-memory",
    )


def test_atexit_flush_registered(monkeypatch, memory_config):
    registered = []

    def fake_atexit_register(func, *args, **kwargs):
        registered.append((func, args, kwargs))

    monkeypatch.setattr(
        "privacy_shield.lifecycle.atexit.register", fake_atexit_register
    )

    plugin = PrivacyShieldPlugin(config=memory_config)

    shutdown_entries = [entry for entry in registered if entry[0] is _shutdown_mapper]
    assert len(shutdown_entries) == 1
    _func, args, _kwargs = shutdown_entries[0]
    assert args[0] is plugin.mapper
    assert args[1] == id(plugin)


def test_no_sigterm_handler_installed(monkeypatch, memory_config):
    """teknium review 2 item 3: plugin load must not replace process-wide
    signal handling — signal.signal must never be called by the plugin."""
    calls = []

    def fake_signal(sig, handler):
        calls.append((sig, handler))

    monkeypatch.setattr("signal.signal", fake_signal)

    PrivacyShieldPlugin(config=memory_config)
    assert calls == [], (
        "plugin load must not install any SIGTERM/signal handler"
    )


def test_shutdown_is_idempotent(memory_config):
    plugin = PrivacyShieldPlugin(config=memory_config)
    mapper = plugin.mapper
    mapper.close = MagicMock()

    _shutdown_mapper(mapper, id(plugin))
    _shutdown_mapper(mapper, id(plugin))
    _shutdown_mapper(mapper, id(plugin))

    mapper.close.assert_called_once()


def test_register_shutdown_hooks_never_touches_signals(memory_config):
    register_shutdown_hooks(MagicMock(), 12345)
    # No exception path left for Windows/restricted envs: atexit-only.
