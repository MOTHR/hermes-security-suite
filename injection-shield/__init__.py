"""Injection-Shield Plugin — prompt-injection defense for Hermes agents."""

from __future__ import annotations

from typing import Any

__version__ = "0.7.1"  # SSO — see pyproject.toml [tool.setuptools.dynamic]

try:
    from .plugin import InjectionShieldPlugin
except ImportError:
    InjectionShieldPlugin = None  # type: ignore[assignment,misc]

try:
    from .owasp_atlas_mapping import (
        OwaspAtlasMapping,
        all_mappings,
        atlas_coverage_summary,
        enrich_log_entry,
        get_mapping,
        mappings_by_atlas,
        mappings_by_owasp,
        owasp_coverage_summary,
    )
except ImportError:
    OwaspAtlasMapping = None  # type: ignore[assignment,misc]
    all_mappings = None  # type: ignore[assignment,misc]
    atlas_coverage_summary = None  # type: ignore[assignment,misc]
    enrich_log_entry = None  # type: ignore[assignment,misc]
    get_mapping = None  # type: ignore[assignment,misc]
    mappings_by_atlas = None  # type: ignore[assignment,misc]
    mappings_by_owasp = None  # type: ignore[assignment,misc]
    owasp_coverage_summary = None  # type: ignore[assignment,misc]

__all__ = [
    "InjectionShieldPlugin",
    "OwaspAtlasMapping",
    "__version__",
    "all_mappings",
    "atlas_coverage_summary",
    "enrich_log_entry",
    "get_mapping",
    "mappings_by_atlas",
    "mappings_by_owasp",
    "owasp_coverage_summary",
    "register",
]


def register(ctx: Any) -> None:
    """Plugin entry point — registers all four defense hooks.

    Hermes v0.20.5 invokes hook callbacks synchronously via
    ``PluginManager._invoke_hook_callback``; the registered callbacks and
    the plugin methods they call are therefore plain (non-coroutine)
    functions.

    For cross-plugin parity with Privacy-Shield v1.3.0, every hook
    accepts ``session_id`` as an alias for ``session_key``. Either name
    may be supplied; the adapter canonicalises to ``session_key`` before
    the plugin class ever sees it.
    """
    if InjectionShieldPlugin is None:
        return
    plugin = InjectionShieldPlugin()

    def _canonical_session_key(
        *,
        session_key: str = "",
        session_id: str = "",
    ) -> str:
        """Return whichever identifier the caller supplied.

        ``session_id`` wins if both are given — that matches the
        Privacy-Shield naming and keeps Hermes-Core's planned
        ``session_id`` convention forward-compatible.
        """
        return session_id or session_key or ""

    def on_pre_tool_call(
        *,
        tool_name: str = "",
        args: dict[str, Any] | None = None,
        session_key: str = "",
        session_id: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        return plugin.pre_tool_call(
            tool_name=tool_name,
            args=args or {},
            session_key=_canonical_session_key(
                session_key=session_key, session_id=session_id
            ),
        )

    def on_post_tool_call(
        *,
        tool_name: str = "",
        result: str = "",
        session_key: str = "",
        session_id: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        return plugin.post_tool_call(
            tool_name=tool_name,
            result=result,
            session_key=_canonical_session_key(
                session_key=session_key, session_id=session_id
            ),
        )

    def on_pre_llm_call(
        *,
        messages: list[dict[str, Any]] | None = None,
        model: str = "",
        session_key: str = "",
        session_id: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        # pre_llm_call does not currently propagate session_key to the
        # plugin method (the message itself carries the conversation
        # context), but the alias is accepted at the adapter so the
        # Hermes-Core call sites that pass ``session_id`` do not break.
        _ = (session_key, session_id)
        return plugin.pre_llm_call(
            messages=messages or [],
            model=model,
        )

    def on_post_llm_call(
        *,
        response: dict[str, Any] | None = None,
        tokens: int = 0,
        session_key: str = "",
        session_id: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        # post_llm_call does not currently take session_key in the
        # plugin class (audit-log path only), but the alias is accepted
        # at the adapter for cross-plugin parity.
        _ = (session_key, session_id)
        return plugin.post_llm_call(
            response=response or {},
            tokens=tokens,
        )

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)
    ctx.register_hook("post_llm_call", on_post_llm_call)
