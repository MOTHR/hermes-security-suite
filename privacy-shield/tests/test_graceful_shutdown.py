"""Tests for graceful shutdown hooks (LINK-PS-6)."""

from __future__ import annotations

import signal
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


def test_atexit_and_sigterm_registered(monkeypatch, memory_config):
    registered = []
    signals = []

    def fake_atexit_register(func, *args, **kwargs):
        registered.append((func, args, kwargs))

    def fake_signal(sig, handler):
        signals.append((sig, handler))

    monkeypatch.setattr(
        "privacy_shield.lifecycle.atexit.register", fake_atexit_register
    )
    monkeypatch.setattr("privacy_shield.lifecycle.signal.signal", fake_signal)
    monkeypatch.setattr("privacy_shield.lifecycle.signal.SIGTERM", signal.SIGTERM)

    plugin = PrivacyShieldPlugin(config=memory_config)

    shutdown_entries = [entry for entry in registered if entry[0] is _shutdown_mapper]
    assert len(shutdown_entries) == 1
    _func, args, _kwargs = shutdown_entries[0]
    assert args[0] is plugin.mapper
    assert args[1] == id(plugin)

    assert len(signals) == 1
    assert signals[0][0] == signal.SIGTERM


def test_shutdown_is_idempotent(memory_config):
    plugin = PrivacyShieldPlugin(config=memory_config)
    mapper = plugin.mapper
    mapper.close = MagicMock()

    _shutdown_mapper(mapper, id(plugin))
    _shutdown_mapper(mapper, id(plugin))
    _shutdown_mapper(mapper, id(plugin))

    mapper.close.assert_called_once()


def test_register_shutdown_hooks_swallows_windows_signal_errors(
    monkeypatch, memory_config
):
    def failing_signal(sig, handler):
        raise AttributeError("SIGTERM not available")

    monkeypatch.setattr("privacy_shield.lifecycle.signal.signal", failing_signal)

    # Should not raise even when SIGTERM registration fails.
    mapper = MagicMock()
    register_shutdown_hooks(mapper, 12345)
