"""Privacy-Shield Plugin — PII pseudonymization for Hermes.

Phase 1: Limited-Risk + Regex-Detection + Core-Hook Fail-Safe.

Architecture: Plugin (~/.hermes/plugins/privacy-shield/) + Hermes hook
interface (pre_llm_call). Defense-in-Depth per internal AI-Act architecture
spec, v1, Section 4 (not published).
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


__version__ = "1.9.0"

__plugin_id__ = "privacy-shield"

# ---------------------------------------------------------------------------
# Cross-Plugin Token-Format Contract (FIX-XPLUGIN-TOKEN).
#
# Privacy-Shield is the SINGLE-SOURCE-OF-TRUTH for the pseudonymization
# token shape.  Other Hermes plugins (notably ``injection-shield``) MUST
# import this constant + regex so the cross-plugin whitelist never drifts
# away from the actual emitter format again.
#
# Why this lives here and not in ``pseudonymizer.py``:
#   - The plugin entry point (``register``) is the importable surface
#     every other plugin can reach via ``privacy_shield`` without pulling
#     in the heavy detection pipeline (``regex_detector`` → ``presidio``
#     etc.) that ``pseudonymizer`` transitively imports.
#   - Keeping it in ``__init__.py`` lets the IS test-suite pin the regex
#     in a CI job that does NOT need the full PS dep tree installed.
#
# Contract (Privacy-Shield v1.3.x):
#   TOKEN_<TYPE>_<HASH>_<COUNTER>
#     TYPE     = uppercase letters + underscores
#     HASH     = DEFAULT_HASH_LENGTH (10) hex chars (lowercase)
#     COUNTER  = COUNTER_DIGITS (3) decimal digits, zero-padded
#
# Migration history:
#   v1.0 / v1.1 : HASH=8, COUNTER=4  (legacy)
#   v1.2+       : HASH=10, COUNTER=3 (current; bumped for stronger
#                 cross-session collision resistance and shorter URL
#                 footprint)
#
# The regex is written so it tolerates BOTH the legacy 8/4 and the
# current 10/3 shape.  This keeps injection-shield's whitelist functional
# for any rolling-restart deployment where one PS instance still emits
# the old shape while the cluster upgrades.
# ---------------------------------------------------------------------------
DEFAULT_HASH_LENGTH = 10  # hex chars; 10 = 40 bits, birthday 50% ~37k tokens
COUNTER_DIGITS = 3         # 000..999 per session; wraps after reaching 999

# FIX-RESTORE-BOUNDARY: token_pattern must match tokens that are embedded in
# larger compound strings (e.g. FAKE_API_KEY_TOKEN_PHONE_..._001abc). The
# boundary is a negative lookbehind that forbids alphanumeric characters
# directly before the token. The legacy no-counter branch and the counter
# suffix branch remain unchanged so cross-plugin callers keep working.
TOKEN_FORMAT_REGEX = (
    r"(?<![A-Za-z0-9])TOKEN_[A-Z][A-Z0-9_]*_[0-9a-f]{8,10}"
    r"(?:_\d{3,4})?\b"
)
TOKEN_FORMAT_PATTERN = re.compile(TOKEN_FORMAT_REGEX)

PrivacyShieldPlugin: type[_PrivacyShieldPluginClass] | None = None

try:
    from .plugin import PrivacyShieldPlugin as _PrivacyShieldPluginClass
    PrivacyShieldPlugin = _PrivacyShieldPluginClass
except ImportError as _exc:
    # Relative import fails when the directory is loaded standalone via its
    # filesystem name 'privacy-shield' (not a valid Python package name).
    # Fall back to absolute loading via the known path so the plugin still
    # registers.
    try:
        import importlib.util

        _plugin_dir = Path(__file__).resolve().parent
        _plugin_file = _plugin_dir / "plugin.py"
        _spec = importlib.util.spec_from_file_location(
            "privacy_shield.plugin", str(_plugin_file)
        )
        assert _spec is not None, "failed to create plugin module spec"
        _module = importlib.util.module_from_spec(_spec)
        sys.modules.setdefault("privacy_shield.plugin", _module)
        assert _spec.loader is not None, "plugin module spec has no loader"
        _spec.loader.exec_module(_module)
        PrivacyShieldPlugin = _module.PrivacyShieldPlugin
    except Exception as _fallback_exc:
        logger.error(
            "Privacy-Shield: could not load PrivacyShieldPlugin (%s; fallback %s)",
            _exc,
            _fallback_exc,
        )
        PrivacyShieldPlugin = None


def register(ctx: Any) -> None:
    """Plugin entry point — registers pre_llm_call + transform_llm_output hooks.

    Called by Hermes plugin manager on discovery.
    """
    if PrivacyShieldPlugin is None:
        logger.error("Privacy-Shield: PrivacyShieldPlugin unavailable; hook not registered")
        return
    plugin = PrivacyShieldPlugin()

    def on_pre_llm_call(
        *,
        session_id: str = "",
        user_message: str = "",
        turn_id: str = "",
        is_first_turn: bool = False,
        model: str = "",
        platform: str = "",
        content_source: str = "",
        target_channel: str = "",
        **kwargs: Any,
    ) -> dict[str, str] | None:
        """pre_llm_call hook: veto or stage the sanitized prompt.

        Upstream contract: only ``{"action": "block", "message": ...}`` (turn
        veto) is consumed here. The sanitized prompt produced by the pipeline
        is staged for the ``llm_request`` middleware instead of returned.
        """
        if not turn_id:
            turn_id = str(kwargs.get("turn_id") or "")
        return plugin.pre_llm_call(
            prompt=user_message,
            context={
                "session_id": session_id,
                "turn_id": turn_id,
                "model": model,
                "platform": platform,
                "is_first_turn": is_first_turn,
                "content_source": content_source,
                "target_channel": target_channel,
            },
        )

    ctx.register_hook("pre_llm_call", on_pre_llm_call)

    def on_llm_request(
        *,
        request: dict[str, Any] | None = None,
        turn_id: str = "",
        session_id: str = "",
        model: str = "",
        platform: str = "",
        provider: str = "",
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """llm_request middleware: rewrite the user message in the outgoing
        request with the staged sanitized prompt.

        The middleware chain only propagates a payload under the ``request``
        key; returning None leaves the request untouched.
        """
        return plugin.apply_shield_to_request(
            request,
            provider=provider,
            session_id=session_id,
            model=model,
            platform=platform,
            turn_id=turn_id,
        )

    ctx.register_middleware("llm_request", on_llm_request)

    def on_post_llm_call(
        *,
        assistant_response: str = "",
        session_id: str = "",
        task_id: str = "",
        turn_id: str = "",
        user_message: str = "",
        conversation_history: list[Any] | None = None,
        model: str = "",
        platform: str = "",
        **kwargs: Any,
    ) -> None:
        """post_llm_call hook: audit-log side-effect for fresh PII in response.

        The hook is intentionally a void side-effect: it never mutates the
        response.  Mutation happens in ``transform_llm_output`` where the
        configured target-channel rules can decide whether to restore
        tokens back to the original values.
        """
        plugin.post_llm_call(
            assistant_response=assistant_response,
            session_id=session_id,
            model=model,
            platform=platform,
            conversation_history=conversation_history,
            **kwargs,
        )

    ctx.register_hook("post_llm_call", on_post_llm_call)

    def on_post_api_request(
        *,
        assistant_message: Any = None,
        session_id: str = "",
        model: str = "",
        platform: str = "",
        **kwargs: Any,
    ) -> None:
        """post_api_request hook: pre-intake reasoning redaction (v1.7.0).

        Fires directly after response intake — BEFORE ``_persist_session``
        and before ``build_assistant_message`` reads the reasoning fields.
        Mutating the live ``assistant_message`` here closes the GB-009
        state.db persistence gap (plugin-only, no core patch).
        """
        try:
            plugin.redact_reasoning_on_message(
                assistant_message,
                session_id=session_id,
                model=model,
                platform=platform,
            )
        except Exception as exc:  # noqa: BLE001 -- fail-open
            logger.warning("Privacy-Shield: post_api_request hook failed: %s", exc)

    ctx.register_hook("post_api_request", on_post_api_request)

    def on_transform_llm_output(
        *,
        response_text: str = "",
        session_id: str = "",
        model: str = "",
        platform: str = "",
        target_channel: str = "",
        **kwargs: Any,
    ) -> str | None:
        """transform_llm_output hook: restore PII tokens in the LLM response.

        Only restores tokens when the output is going to an explicitly
        allowed user-facing channel (e.g. a configured Telegram chat). For all other
        targets (write_file, kanban_complete, terminal, MCP) the tokens
        remain pseudonymized so PII cannot leak through other egress routes.
        """
        if not response_text:
            return None
        # Hermes core (agent/turn_finalizer.py) invokes transform_llm_output
        # without target_channel; platform is the only egress signal it passes.
        # Fall back so channel-based restoration rules can still match.
        if not target_channel:
            target_channel = platform or ""
        restored = plugin.post_llm_response(
            text=response_text,
            session_id=session_id,
            target_channel=target_channel,
        )
        if not restored or restored == response_text:
            return None
        return restored

    ctx.register_hook("transform_llm_output", on_transform_llm_output)

    def on_session_finalize(
        *,
        session_id: str = "",
        reason: str = "",
        **kwargs: Any,
    ) -> None:
        """on_session_finalize hook: purge the session's mappings.

        Retention = session lifetime (DSGVO Art. 5(1)(e); operator decision,
        2026-10-10).
        Fired by Hermes core at real session boundaries — notably ``/new``
        (reason="new_session"). NOT purged for reason="shutdown": a
        gateway restart is a PROCESS restart, the CONVERSATION continues
        with the same session_id, so its mappings must stay resolvable
        (the 2026-10-10 mapping-miss incident). Purging on shutdown would
        reintroduce exactly the bug this change fixes — the TTL remains
        the crash fallback for sessions that never see a finalize.
        """
        if reason in ("shutdown", "gateway_restart"):
            return
        if not session_id:
            return
        try:
            plugin.on_session_end(session_id)
        except Exception as exc:  # noqa: BLE001 -- fail-open, never block finalize
            logger.warning(
                "Privacy-Shield: on_session_finalize purge failed: %s", exc
            )

    ctx.register_hook("on_session_finalize", on_session_finalize)


__all__ = [
    "register",
    "TOKEN_FORMAT_REGEX",
    "TOKEN_FORMAT_PATTERN",
    "_build_finalize_hook",
]


def _build_finalize_hook(purge: Any) -> Any:
    """Return an on_session_finalize-style hook around a ``purge`` callable.

    Test + reuse seam: the reason-gating policy lives here so it stays
    identical between the registered hook and any future caller.
    """
    from typing import Any as _Any

    def on_session_finalize(
        *,
        session_id: str = "",
        reason: str = "",
        **kwargs: _Any,
    ) -> None:
        if reason in ("shutdown", "gateway_restart"):
            return
        if not session_id:
            return
        try:
            purge(session_id)
        except Exception as exc:  # noqa: BLE001 -- fail-open, never block finalize
            logger.warning("Privacy-Shield: on_session_finalize purge failed: %s", exc)

    return on_session_finalize
