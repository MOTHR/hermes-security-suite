"""Issue #6 (MOTHR/hermes-security-suite): reprint suppression via transform_is_inline.

Streaming surfaces paint the pseudonymized response live, then the
``transform_llm_output`` restore pass rewrites TOKEN_* spans *in the middle* of
the text. The CLI reprint fast-path only handles prefix extensions, so it fell
back to reprinting the entire response — output twice.

Plugin-side signal required by the fix: when the rewrite is NOT a prefix
extension of the streamed text, the hook returns a ``str`` subclass carrying
``transform_is_inline=True``. ``isinstance(r, str)`` still matches the upstream
transform contract (hooks.md: "first non-empty string replaces the response"),
so old cores ignore the attribute harmlessly; a core that knows the attribute
suppresses the reprint.
"""

from __future__ import annotations

import re

from privacy_shield import register
from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin

PII_PROMPT = "Mail an max.mustermann@firma-gmbh.de"
TOKEN_EMAIL_RE = re.compile(r"TOKEN_EMAIL_[0-9a-f]{10}_\d{3}")


def _make_plugin(tmp_path):
    cfg = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        storage_path=str(tmp_path / "mapping.db"),
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        audit_jsonl_enabled=False,
    )
    return PrivacyShieldPlugin(config=cfg)


class _FakeCtx:
    def __init__(self):
        self.hooks: dict = {}

    def register_hook(self, name, cb):
        self.hooks[name] = cb

    def register_middleware(self, name, cb):
        self.middleware: dict = {name: cb}


def _make_hook(monkeypatch, tmp_path):
    """Registered ``transform_llm_output`` hook around a plugin whose prompt
    PII (a fresh TOKEN_EMAIL_*) was already minted in turn1's staged shield."""
    import privacy_shield as ps_pkg

    plugin = _make_plugin(tmp_path)
    plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT_ID",)
    monkeypatch.setattr(ps_pkg, "PrivacyShieldPlugin", lambda: plugin)
    ctx = _FakeCtx()
    register(ctx)
    hook = ctx.hooks["transform_llm_output"]
    token = _stage_token(plugin)
    return hook, plugin, token


def _stage_token(plugin) -> str:
    staged = plugin.pre_llm_call(
        PII_PROMPT,
        context={
            "session_id": "s1",
            "turn_id": "turn1",
            "model": "m",
            "platform": "telegram",
            "is_first_turn": True,
        },
    )
    match = TOKEN_EMAIL_RE.search(plugin._staged_shields["turn1"]["sanitized"])
    assert match, "no token generated"
    return match.group(0)


class TestInlineTransformSignal:
    def test_midstring_restore_sets_transform_is_inline(self, monkeypatch, tmp_path):
        """Issue #6 core case: a token sits mid-text; the restore is an inline
        substitution, not a prefix extension."""
        hook, plugin, token = _make_hook(monkeypatch, tmp_path)
        result = hook(
            response_text=f"Vorheriger Text. Mail: {token} Danke, bis später.",
            session_id="s1",
            model="m",
            platform="telegram",
            target_channel="telegram:TEST_CHAT_ID",
        )
        assert result is not None
        assert isinstance(result, str)
        assert getattr(result, "transform_is_inline", False) is True

    def test_noop_restore_returns_none(self, monkeypatch, tmp_path):
        hook, _plugin, _token = _make_hook(monkeypatch, tmp_path)
        assert hook(
            response_text="No tokens in this response.",
            session_id="s1",
            model="m",
            platform="telegram",
            target_channel="telegram:TEST_CHAT_ID",
        ) is None

    def test_flag_object_is_ordinary_string(self, monkeypatch, tmp_path):
        """Upstream cores that ignore the attribute must keep transforming —
        the flagged object has to behave byte-for-byte like the restored str."""
        hook, _plugin, token = _make_hook(monkeypatch, tmp_path)
        result = hook(
            response_text=f"Mail: {token}",
            session_id="s1",
            model="m",
            platform="telegram",
            target_channel="telegram:TEST_CHAT_ID",
        )
        assert result is not None
        assert "max.mustermann@firma-gmbh.de" in str(result)
        assert "TOKEN_EMAIL_" not in str(result)
        assert result.strip() == result  # plain str API intact (strip/len/...)
