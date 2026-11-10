"""End-to-end regression tests for the Privacy-Shield replace contract (v1.9.0).

The plugin uses ONLY upstream Hermes contracts now (v1.9.0, PR #150309
review): ``pre_llm_call`` must NOT return ``{"user_message": ...}`` or
``{"blocked": True}`` — upstream ignores both. Instead:

  1. Veto:  strict (with a known cloud provider) / paranoid mode return
            ``{"action": "block", "message": ...}``.
  2. Mask:  the sanitized prompt is STAGED and the ``llm_request``
            middleware (:meth:`apply_shield_to_request`) rewrites the last
            user message inside the outgoing ``api_kwargs`` payload.
"""

from __future__ import annotations

import json
import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin


PII_PROMPT = "Bitte schreib an max.mustermann@firma-gmbh.de"
TOKEN_RE = re.compile(r"TOKEN_EMAIL_[0-9a-f]{10}_\d{3}")

REQUEST = {
    "messages": [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "assistant", "content": "hi"},
        {"role": "user", "content": PII_PROMPT},
    ]
}


def _make_plugin(
    tmp_path,
    *,
    enabled=True,
    mode="limited",
    audit=True,
):
    cfg = PrivacyShieldConfig(
        enabled=enabled,
        mode=mode,
        storage_path=str(tmp_path / "mapping.db"),
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        audit_jsonl_enabled=audit,
    )
    return PrivacyShieldPlugin(config=cfg)


def _run_shield(plugin, *, turn_id="turn1", provider=""):
    result = plugin.pre_llm_call(
        PII_PROMPT,
        context={
            "session_id": "s1",
            "turn_id": turn_id,
            "provider": provider,
            "model": "m",
            "platform": "",
        },
    )
    return result, plugin._staged_shield


class TestShieldContract:
    """pre_llm_call returns ONLY the veto contract; masking is staged."""

    def test_masked_prompt_stages_and_returns_none(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        result, staged = _run_shield(plugin)
        assert result is None, (
            "limited mode must NOT return a mask payload upstream "
            "(only the {'action': 'block', ...} veto is consumed there)"
        )
        assert staged is not None, "masked prompt must be staged for the middleware"
        assert "max.mustermann@firma-gmbh.de" not in staged["sanitized"]
        assert "TOKEN_EMAIL_" in staged["sanitized"]

    def test_no_pii_returns_none_and_does_not_stage(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        r = plugin.pre_llm_call("hallo, wie geht es dir?", context={})
        assert r is None
        assert plugin._staged_shield is None

    def test_disabled_returns_none(self, tmp_path):
        plugin = _make_plugin(tmp_path, enabled=False)
        r = plugin.pre_llm_call(PII_PROMPT, context={})
        assert r is None

    def test_strict_known_cloud_provider_vetoes_with_block_contract(self, tmp_path):
        plugin = _make_plugin(tmp_path, mode="strict")
        r = plugin.pre_llm_call(
            PII_PROMPT,
            context={"provider": "anthropic", "session_id": "s1", "turn_id": "t"},
        )
        assert r is not None and r.get("action") == "block"
        assert "Privacy-Shield" in r["message"]
        # a veto must not stage a mask
        assert plugin._staged_shield is None

    def test_strict_unknown_provider_defers_to_mask(self, tmp_path):
        """Upstream pre_llm_call provides no provider → no veto, mask instead."""
        plugin = _make_plugin(tmp_path, mode="strict")
        result, staged = _run_shield(plugin)
        assert result is None
        assert staged is not None and "TOKEN_EMAIL_" in staged["sanitized"]
        data = open(tmp_path / "audit.jsonl", encoding="utf-8").read().splitlines()
        events = [json.loads(line) for line in data if line.strip()]
        assert any(e.get("event") == "strict_block_deferred" for e in events)

    def test_paranoid_vetoes_regardless_of_provider(self, tmp_path):
        plugin = _make_plugin(tmp_path, mode="paranoid")
        # no provider in ctx at all (upstream shape)
        r = plugin.pre_llm_call(PII_PROMPT, context={"session_id": "s1"})
        assert r is not None and r.get("action") == "block"
        assert plugin._staged_shield is None


class TestMiddlewareApplication:
    """The llm_request middleware rewrites the outgoing user message."""

    def test_rewrites_last_user_message_string(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin)
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        result = plugin.apply_shield_to_request(
            request, provider="anthropic", session_id="s1", turn_id="turn1"
        )
        assert result is not None and "request" in result
        user_msgs = [m for m in request["messages"] if m.get("role") == "user"]
        assert len(user_msgs) == 1
        content = user_msgs[0]["content"]
        assert "max.mustermann@firma-gmbh.de" not in content
        assert "TOKEN_EMAIL_" in content
        # system/assistant rows untouched
        assert request["messages"][0]["content"] == "You are a helpful assistant."

    def test_rewrites_multimodal_text_part_only(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin)
        request = {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": PII_PROMPT},
                        {"type": "image_url", "image_url": {"url": "file://x"}},
                    ],
                }
            ]
        }
        result = plugin.apply_shield_to_request(
            request, provider="anthropic", turn_id="turn1"
        )
        assert result is not None
        parts = request["messages"][0]["content"]
        assert "max.mustermann@firma-gmbh.de" not in parts[0]["text"]
        assert parts[1] == {"type": "image_url", "image_url": {"url": "file://x"}}

    def test_local_provider_is_exempt(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin)
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        result = plugin.apply_shield_to_request(
            request, provider="ollama", turn_id="turn1"
        )
        assert result is None
        assert request["messages"][2]["content"] == PII_PROMPT

    def test_no_staged_shield_leaves_request_untouched(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        assert plugin.apply_shield_to_request(request, provider="anthropic") is None
        assert request["messages"][2]["content"] == PII_PROMPT

    def test_staged_slot_persists_across_attempts(self, tmp_path):
        """Orakel review t_c0a50b6f F-1 regression: the core rebuilds the
        request payload PER api attempt and re-fires the middleware — the
        staged slot must NOT be consumed once, or attempt 2+ sends raw PII."""
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turnX")
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        first = plugin.apply_shield_to_request(request, provider="anthropic", turn_id="turnX")
        assert first is not None
        request2 = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        second = plugin.apply_shield_to_request(request2, provider="anthropic", turn_id="turnX")
        assert second is not None, (
            "stage must STILL apply on the second attempt of the same turn "
            "(per-attempt middleware reload) — consumed-once leaks raw PII"
        )
        assert "max.mustermann@firma-gmbh.de" not in request2["messages"][2]["content"]

    def test_sidecar_context_suffix_survives(self, tmp_path):
        """Orakel F-2 regression: the wire content carries the core's sidecar
        (raw live prompt + '\\n\\n' + injected context). The rewrite must keep
        the context suffix byte-exact, not replace the whole message."""
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turnX")  # stages sanitized for the raw PII prompt
        stage = plugin._staged_shield
        context_suffix = "\n\nPROMPT INJECTION FIREWALL (injected context)"
        wire = stage["raw_prompt"] + context_suffix
        request = {"messages": [{"role": "user", "content": wire}]}
        result = plugin.apply_shield_to_request(
            request, provider="anthropic", turn_id="turnX"
        )
        assert result is not None
        out = request["messages"][0]["content"]
        # The sanitized live prompt replaces ONLY the live portion…
        assert "max.mustermann@firma-gmbh.de" not in out
        assert "TOKEN_EMAIL_" in out
        # …and the injected context suffix survives byte-exact.
        assert out.endswith(context_suffix)

    def test_unknown_shape_falls_back_to_full_masking(self, tmp_path):
        """No raw-prompt match -> mask the whole wire content (fail-safe),
        never ship the unmasked original."""
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turnX")
        request = {"messages": [{"role": "user", "content":
            "REWRITTEN PREFIX: mail an max.mustermann@firma-gmbh.de now"}]}
        result = plugin.apply_shield_to_request(
            request, provider="anthropic", turn_id="turnX"
        )
        assert result is not None
        assert "max.mustermann@firma-gmbh.de" not in request["messages"][0]["content"]

    def test_empty_turn_id_cannot_read_foreign_shield(self, tmp_path):
        """Smith review t_5d7e23ce/001: an empty turn_id is NOT a wildcard —
        a surface that loses its turn id must not read another turn's staged
        mask (cross-turn contamination)."""
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turn-A")
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        assert plugin.apply_shield_to_request(request, provider="anthropic", turn_id="") is None
        assert request["messages"][2]["content"] == PII_PROMPT

    def test_both_empty_turn_ids_still_match(self, tmp_path):
        """Both ids empty (surfaces without turn ids) match — the local
        patched core passes turn_id at both call sites, so this branch exists
        only for id-less surfaces reading their OWN stage."""
        plugin = _make_plugin(tmp_path)
        plugin.pre_llm_call(PII_PROMPT, context={"session_id": "s1", "turn_id": ""})
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        assert plugin.apply_shield_to_request(request, provider="anthropic", turn_id="") is not None
        assert "max.mustermann@firma-gmbh.de" not in request["messages"][2]["content"]

    def test_turn_mismatch_does_not_apply_stale_shield(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turnA")
        request = {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]}
        assert plugin.apply_shield_to_request(
            request, provider="anthropic", turn_id="turnB"
        ) is None
        assert request["messages"][2]["content"] == PII_PROMPT

    def test_audit_applied_event_only_on_real_rewrite(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turn1")
        plugin.apply_shield_to_request(
            {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]},
            provider="anthropic",
            turn_id="turn1",
        )
        data = open(tmp_path / "audit.jsonl", encoding="utf-8").read().splitlines()
        events = [json.loads(line) for line in data if line.strip()]
        assert any(e.get("event") == "pseudonymization_applied" for e in events)

    def test_audit_not_logged_for_exempt_local_provider(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _run_shield(plugin, turn_id="turn2")
        plugin.apply_shield_to_request(
            {**REQUEST, "messages": [dict(m) for m in REQUEST["messages"]]},
            provider="ollama_local",
            turn_id="turn2",
        )
        audit_path = tmp_path / "audit.jsonl"
        if not audit_path.exists():
            return  # nothing at all written — no applied event, as expected
        data = open(audit_path, encoding="utf-8").read().splitlines()
        events = [json.loads(line) for line in data if line.strip()]
        assert not any(e.get("event") == "pseudonymization_applied" for e in events)


# ── Hook wiring: pre_llm_call + llm_request middleware + restore hook ─────


class _FakeCtx:
    """Minimal PluginContext that records register_hook/register_middleware."""

    def __init__(self):
        self.hooks: dict = {}
        self.middleware: dict = {}

    def register_hook(self, name, cb):
        self.hooks[name] = cb

    def register_middleware(self, kind, cb):
        self.middleware[kind] = cb


class TestHookWiring:
    def _ctx_with_plugin(self, monkeypatch, tmp_path):
        import privacy_shield as ps_pkg

        plugin = _make_plugin(tmp_path)
        # register() constructs PrivacyShieldPlugin() with load_config(); inject
        # our pre-built plugin so the test never touches the real key/DB.
        monkeypatch.setattr(ps_pkg, "PrivacyShieldPlugin", lambda: plugin)
        ctx = _FakeCtx()
        ps_pkg.register(ctx)
        return ctx, plugin

    def test_registers_middleware_and_hooks(self, monkeypatch, tmp_path):
        ctx, _ = self._ctx_with_plugin(monkeypatch, tmp_path)
        assert ctx.hooks.get("pre_llm_call")
        assert ctx.middleware.get("llm_request"), (
            "masking must be delivered via the llm_request middleware"
        )
        assert "transform_llm_output" in ctx.hooks
        assert "post_llm_response" not in ctx.hooks, (
            "must NOT register the dead 'post_llm_response' name"
        )

    def test_restore_callback_restores_tokens(self, monkeypatch, tmp_path):
        ctx, plugin = self._ctx_with_plugin(monkeypatch, tmp_path)
        plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT_ID",)
        redacted = ctx.hooks["pre_llm_call"](
            user_message="mail an max.mustermann@firma-gmbh.de",
            session_id="s1", model="m", platform="", is_first_turn=True,
        )
        assert redacted is None  # the mask path stages instead of returning
        staged = plugin._staged_shield
        assert staged is not None
        tokenized = staged["sanitized"]
        token_match = TOKEN_RE.search(tokenized)
        assert token_match, "no token generated"
        real_token = token_match.group(0)
        # Provider echoes the token; transform_llm_output must restore it for the allowed channel.
        response = f"Bestätige Empfang: Mail an {real_token}"
        restored = ctx.hooks["transform_llm_output"](
            response_text=response, session_id="s1", model="m", platform="",
            target_channel="telegram:TEST_CHAT_ID",
        )
        assert restored is not None
        assert "max.mustermann@firma-gmbh.de" in restored
        assert "TOKEN_EMAIL_" not in restored

    def test_restore_callback_returns_none_when_no_tokens(self, monkeypatch, tmp_path):
        ctx, _ = self._ctx_with_plugin(monkeypatch, tmp_path)
        result = ctx.hooks["transform_llm_output"](
            response_text="Guten Tag, keine Tokens hier.",
            session_id="s1", model="m", platform="",
        )
        assert result is None
