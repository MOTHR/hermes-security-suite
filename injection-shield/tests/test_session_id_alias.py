"""Tests for the session_id / session_key alias in the plugin entry point.

FIX-IS-R4-002 (Architect R4 ARCH-IS-002 HIGH): the public hook signature
must accept either ``session_key`` (the legacy IS name) or ``session_id``
(the Privacy-Shield v1.3.0 name) so the two plugins can share an audit
correlation key without operators having to translate manually.

The plugin's *internal* contract still uses ``session_key`` because that
is what the four hooks on ``InjectionShieldPlugin`` already accept
(renaming would touch ~20 call sites + tests for no functional gain).
The alias lives entirely in the ``register()`` adapter.
"""

from __future__ import annotations

from typing import Any


class _RecordingContext:
    """Minimal stand-in for the Hermes plugin ctx — captures the hooks."""

    def __init__(self) -> None:
        self.hooks: dict[str, Any] = {}

    def register_hook(self, name: str, fn: Any) -> None:
        self.hooks[name] = fn


def _invoke(hook: Any, **kwargs: Any) -> Any:
    # Hermes v0.20.5 invokes hook callbacks synchronously, so the
    # registered hooks are plain functions — call them directly.
    return hook(**kwargs)


def _make_register_with_spy(
    hook_name: str,
) -> tuple[Any, dict[str, str], Any]:
    """Return (register_fn, captured_dict, ctx) where the hook at
    ``hook_name`` on the registered plugin instance records every
    session_key it sees."""
    from injection_shield.plugin import InjectionShieldPlugin

    from injection_shield import register as real_register

    captured: dict[str, str] = {}

    original_init = InjectionShieldPlugin.__init__

    if hook_name in ("pre_tool_call", "post_tool_call"):
        def fake_hook(**kwargs: Any) -> dict | None:  # type: ignore[no-redef]
            captured["session_key"] = kwargs.get("session_key", "")
            return None

        def _init(self: Any) -> None:
            original_init(self)
            self.__setattr__(hook_name, fake_hook)  # type: ignore[arg-type]

        InjectionShieldPlugin.__init__ = _init  # type: ignore[assignment]
    # pre_llm_call / post_llm_call don't take session_key on the
    # plugin class — we just verify they accept the kwarg without
    # raising.

    ctx = _RecordingContext()
    real_register(ctx)

    def _cleanup() -> None:
        InjectionShieldPlugin.__init__ = original_init  # type: ignore[assignment]

    return ctx, captured, _cleanup


def test_session_id_alias_on_pre_tool_call() -> None:
    """session_id must be forwarded to the plugin as session_key."""
    ctx, captured, cleanup = _make_register_with_spy("pre_tool_call")
    try:
        # session_id should be forwarded as session_key to the plugin.
        _invoke(
            ctx.hooks["pre_tool_call"],
            tool_name="terminal",
            args={"cmd": "ls"},
            session_id="abc-123",
        )
        assert captured["session_key"] == "abc-123", (
            f"session_id was not forwarded: got {captured.get('session_key')!r}"
        )

        # Plain session_key still works (backward compat).
        _invoke(
            ctx.hooks["pre_tool_call"],
            tool_name="terminal",
            args={"cmd": "ls"},
            session_key="legacy-key",
        )
        assert captured["session_key"] == "legacy-key"

        # session_id wins when both are supplied (forward-compat).
        _invoke(
            ctx.hooks["pre_tool_call"],
            tool_name="terminal",
            args={"cmd": "ls"},
            session_key="legacy-key",
            session_id="new-id",
        )
        assert captured["session_key"] == "new-id", (
            "session_id should win when both names are supplied"
        )
    finally:
        cleanup()


def test_session_id_alias_on_post_tool_call() -> None:
    """The post_tool_call adapter must also accept session_id."""
    ctx, captured, cleanup = _make_register_with_spy("post_tool_call")
    try:
        _invoke(
            ctx.hooks["post_tool_call"],
            tool_name="terminal",
            result="hello",
            session_id="from-ps",
        )
        assert captured["session_key"] == "from-ps"
    finally:
        cleanup()


def test_session_id_accepted_on_pre_and_post_llm_call() -> None:
    """The pre_llm_call / post_llm_call adapters must accept session_id
    without raising — even though the plugin method does not use it."""
    from injection_shield import register as real_register

    ctx = _RecordingContext()
    real_register(ctx)

    # The point is that neither call raises on the unknown kwarg.
    result_pre = _invoke(
        ctx.hooks["pre_llm_call"],
        messages=[{"role": "user", "content": "hi"}],
        model="test-model",
        session_id="abc",
    )
    result_post = _invoke(
        ctx.hooks["post_llm_call"],
        response={"content": "hi"},
        tokens=2,
        session_id="abc",
    )
    # pre_llm_call returns a decision dict (potentially with the
    # firewall system message prepended); post_llm_call returns
    # None on success. The contract is: no TypeError, no crash.
    assert isinstance(result_pre, dict)
    assert result_post is None


def test_adapter_does_not_break_when_neither_session_key_nor_id_supplied() -> None:
    """The hooks must remain callable with no session identifier at all
    (this matches the existing pre-FIX-IS-R4-002 behaviour)."""
    from injection_shield import register as real_register

    ctx = _RecordingContext()
    real_register(ctx)

    result = _invoke(
        ctx.hooks["pre_tool_call"],
        tool_name="terminal",
        args={"cmd": "ls"},
    )
    # pre_tool_call returns an {"action": "allow" | "deny"} decision.
    assert isinstance(result, dict)
    assert result["action"] in ("allow", "deny")
