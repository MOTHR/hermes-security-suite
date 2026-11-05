"""End-to-end regression tests for the Privacy-Shield replace contract.

These tests guard against the original defect: the plugin returned
``{"context": sanitized}``, but the Hermes ``pre_llm_call`` channel is
append-only, so the original PII was still sent to the provider. The fix is
a ``{"user_message": sanitized}`` return key, stamped as the ``api_content``
sidecar by the Core patches (OVERRIDE_CAPTURE / OVERRIDE_STAMP).

Two layers are tested:
  1. Contract: the plugin returns ``user_message`` (not ``context``), with no PII.
  2. Core flow: the auto_apply patches, applied to a turn_context-shaped fixture,
     drive a sanitized ``api_content`` sidecar to the provider while the clean
     transcript is preserved, and the sidecar is what replay substitutes.
"""

from __future__ import annotations

import re
import sys
import types
from pathlib import Path

import pytest

# Make scripts/ importable (auto_apply_hook lives in scripts/)
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import auto_apply_hook as aah  # noqa: E402

from privacy_shield.config import PrivacyShieldConfig  # noqa: E402
from privacy_shield.plugin import PrivacyShieldPlugin  # noqa: E402


# ── Fixture: a minimal turn_context.py with the real anchors ─────────────

# Indentation mirrors the live agent/turn_context.py: the hardblock region sits
# at 4-space (function body), the override regions at 8-space (inside the try /
# inside the guard that wraps the compose+stamp block).
TURN_CONTEXT_FIXTURE = """\
import logging
logger = logging.getLogger(__name__)


def compose_user_api_content(content, ext_prefetch_cache, plugin_user_context):
    if not isinstance(content, str):
        return None
    injections = []
    if ext_prefetch_cache:
        injections.append(ext_prefetch_cache)
    if plugin_user_context:
        injections.append(plugin_user_context)
    if not injections:
        return None
    return content + "\\n\\n" + "\\n\\n".join(injections)


def run_turn_start_compaction(agent, messages=(), **kwargs):
    return None


def _collect_pre_llm_call_context(agent, **kwargs):
    return ""


def build_turn_context(agent, user_message, conversation_history, messages,
                       effective_task_id, turn_id, current_turn_user_idx,
                       ext_prefetch_cache=""):
    original_user_message = user_message
    x = agent.provider
    compaction = run_turn_start_compaction(agent, messages=messages)
    plugin_user_context = _collect_pre_llm_call_context(
        agent, effective_task_id=effective_task_id, turn_id=turn_id,
    )
    plugin_user_context = ""
    try:
        _pre_results = invoke_hook("pre_llm_call", user_message=original_user_message,
                                    model=agent.model,
                                    platform=getattr(agent, "platform", None) or "")
        _ctx_parts = []
        for r in _pre_results:
            _piece = ""
            if isinstance(r, dict) and r.get("context"):
                _piece = str(r["context"])
            elif isinstance(r, str) and r.strip():
                _piece = r
            else:
                continue
            _ctx_parts.append(_piece)
        if _ctx_parts:
            plugin_user_context = "\\n\\n".join(_ctx_parts)
    except Exception as exc:
        logger.warning("pre_llm_call hook failed: %s", exc)

    if True:
        _turn_user_msg = messages[current_turn_user_idx]
        _api_content = compose_user_api_content(
            _turn_user_msg.get("content", ""), ext_prefetch_cache, plugin_user_context
        )
        if _api_content is not None and _api_content != _turn_user_msg.get("content"):
            _turn_user_msg["api_content"] = _api_content
    return messages
"""


@pytest.fixture
def patch_env(tmp_path, monkeypatch):
    """Redirect auto_apply backups/logs/target into a temp dir."""
    monkeypatch.setattr(aah, "BACKUP_DIR", tmp_path)
    monkeypatch.setattr(aah, "LOG_PATH", tmp_path / "auto-apply.log")
    tc = tmp_path / "turn_context.py"
    tc.write_text(TURN_CONTEXT_FIXTURE, encoding="utf-8")
    monkeypatch.setattr(aah, "TURN_CONTEXT_PATH", tc)
    return tc


@pytest.fixture
def hermes_stub(monkeypatch):
    """Stub hermes_cli.* so the HARDBLOCK patch deterministically no-ops.

    The HARDBLOCK patch imports ``hermes_cli.plugins._get_enabled_plugins`` and
    raises RuntimeError if privacy-shield is enabled but the hook is missing.
    In the test environment hermes may or may not be importable; we force the
    check to return an empty enabled-set so the hardblock branch is a no-op and
    the override flow is what's under test. monkeypatch restores sys.modules.
    """
    fake_cli = types.ModuleType("hermes_cli")
    fake_plugins = types.ModuleType("hermes_cli.plugins")
    fake_plugins._get_enabled_plugins = lambda: set()
    fake_lifecycle = types.ModuleType("hermes_cli.lifecycle")
    fake_lifecycle.has_hook = lambda name: False
    fake_cli.plugins = fake_plugins
    fake_cli.lifecycle = fake_lifecycle
    monkeypatch.setitem(sys.modules, "hermes_cli", fake_cli)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", fake_plugins)
    monkeypatch.setitem(sys.modules, "hermes_cli.lifecycle", fake_lifecycle)


def _exec_module(tc_path):
    """Compile + exec the patched fixture, returning its namespace."""
    content = tc_path.read_text(encoding="utf-8")
    code_obj = compile(content, str(tc_path), "exec")
    ns: dict = {"__name__": "tc_fixture"}
    exec(code_obj, ns)
    return ns


def _make_agent():
    return types.SimpleNamespace(
        platform="anthropic", model="glm-5", session_id="s1", provider="anthropic"
    )


PII_PROMPT = "Bitte schreib an max.mustermann@firma-gmbh.de"


# ── 1. Contract: the plugin returns user_message, not context ─────────────


def _make_plugin(tmp_path, enabled=True):
    cfg = PrivacyShieldConfig(
        enabled=enabled,
        storage_path=str(tmp_path / "mapping.db"),
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
    )
    return PrivacyShieldPlugin(config=cfg)


class TestReplaceContract:
    def test_returns_user_message_key_not_context(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        result = plugin.pre_llm_call("Bitte schreib an max.mustermann@firma-gmbh.de")
        assert result is not None, "PII present -> plugin must return an override"
        assert "user_message" in result, "must return the 'user_message' override key"
        assert "context" not in result, (
            "must NOT return the append-only 'context' key (that leaks the original PII)"
        )

    def test_override_has_no_pii_and_carries_token(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        sanitized = plugin.pre_llm_call("schreib an max.mustermann@firma-gmbh.de")["user_message"]
        assert "max.mustermann@firma-gmbh.de" not in sanitized
        assert "TOKEN_EMAIL_" in sanitized

    def test_no_pii_returns_none(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        assert plugin.pre_llm_call("hallo, wie geht es dir?") is None

    def test_disabled_returns_none(self, tmp_path):
        plugin = _make_plugin(tmp_path, enabled=False)
        assert plugin.pre_llm_call("schreib an max.mustermann@firma-gmbh.de") is None


# ── 2. Core flow: patches drive a sanitized api_content sidecar ────────────


class TestCoreFlowReplace:
    def test_patches_apply_and_compile(self, patch_env):
        ok, msg, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok, msg
        content = patch_env.read_text(encoding="utf-8")
        for spec in aah.ALL_SPECS:
            assert spec.marker in content, f"{spec.name} marker missing after apply"
        compile(content, str(patch_env), "exec")

    def test_apply_is_idempotent(self, patch_env):
        aah.apply_all(patch_env, dry_run=False)
        ok2, msg2, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok2
        assert all("already applied" in m.lower() for m in msg2.splitlines())

    def test_provider_gets_sanitized_sidecar(self, patch_env, hermes_stub):
        """The provider-bound api_content has no PII; the transcript keeps it."""
        ok, msg, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok, msg
        ns = _exec_module(patch_env)
        ns["invoke_hook"] = lambda *a, **k: [{"user_message": "Bitte schreib an TOKEN_EMAIL_001"}]
        messages = [{"role": "user", "content": PII_PROMPT}]
        ns["build_turn_context"](_make_agent(), PII_PROMPT, [], messages, "t1", "turn1", 0)
        msg = messages[0]
        # Transcript (stored content) retains the original PII:
        assert "max.mustermann@firma-gmbh.de" in msg["content"]
        # Provider-bound sidecar is set and PII-free:
        assert "api_content" in msg
        ac = msg["api_content"]
        assert "max.mustermann@firma-gmbh.de" not in ac
        assert "TOKEN_EMAIL_001" in ac

    def test_clean_prompt_no_sidecar(self, patch_env, hermes_stub):
        """No PII -> no override -> no api_content sidecar (clean passthrough)."""
        ok, msg, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok, msg
        ns = _exec_module(patch_env)
        ns["invoke_hook"] = lambda *a, **k: []  # no PII -> plugin returns None -> empty results
        messages = [{"role": "user", "content": PII_PROMPT}]
        ns["build_turn_context"](_make_agent(), PII_PROMPT, [], messages, "t1", "turn1", 0)
        msg = messages[0]
        assert "api_content" not in msg
        assert msg["content"] == PII_PROMPT

    def test_override_resets_between_turns(self, patch_env, hermes_stub):
        """The override attr is reset each turn (no stale leak across turns)."""
        ok, msg, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok, msg
        ns = _exec_module(patch_env)
        agent = _make_agent()

        # Turn 1: PII present -> override set
        ns["invoke_hook"] = lambda *a, **k: [{"user_message": "an TOKEN_EMAIL_001"}]
        m1 = [{"role": "user", "content": "an max.mustermann@firma-gmbh.de"}]
        ns["build_turn_context"](agent, m1[0]["content"], [], m1, "t", "t", 0)
        assert agent._privacy_shield_override == "an TOKEN_EMAIL_001"

        # Turn 2: no PII -> override reset to "" (no stale override leaks)
        ns["invoke_hook"] = lambda *a, **k: []
        m2 = [{"role": "user", "content": "hallo"}]
        ns["build_turn_context"](agent, m2[0]["content"], [], m2, "t", "t", 0)
        assert agent._privacy_shield_override == ""

    def test_replay_substitutes_sanitized_sidecar(self, patch_env, hermes_stub):
        """Turn N+1 replay sends the api_content sidecar, not the stored content.

        Mimics conversation_loop's historical-message substitution: pop the
        api_content sidecar and substitute it into content for the wire copy.
        """
        ok, msg, _ = aah.apply_all(patch_env, dry_run=False)
        assert ok, msg
        ns = _exec_module(patch_env)
        ns["invoke_hook"] = lambda *a, **k: [{"user_message": "Bitte schreib an TOKEN_EMAIL_001"}]
        messages = [{"role": "user", "content": PII_PROMPT}]
        ns["build_turn_context"](_make_agent(), PII_PROMPT, [], messages, "t1", "turn1", 0)
        msg = messages[0]
        # Replay (turn N+1) — the wire copy uses the sidecar, not the clean content:
        wire = msg.pop("api_content", None) or msg["content"]
        assert "max.mustermann@firma-gmbh.de" not in wire
        assert "TOKEN_EMAIL_001" in wire
        # The stored transcript still carries the original (for local display):
        assert "max.mustermann@firma-gmbh.de" in msg["content"]

    def test_revert_last_leaves_others_intact(self, patch_env):
        """Reverting the last-applied patch (STAMP) leaves CAPTURE + HARDBLOCK.

        revert_patch restores a full-file backup snapshot taken just before
        that patch was applied, so only the last-applied patch reverts cleanly
        in isolation — reverting an earlier patch would also wipe later ones.
        """
        aah.apply_all(patch_env, dry_run=False)
        ok, _ = aah.revert_patch(patch_env, spec=aah.OVERRIDE_STAMP_SPEC)
        assert ok
        content = patch_env.read_text(encoding="utf-8")
        assert aah.OVERRIDE_STAMP_MARKER not in content
        assert aah.OVERRIDE_CAPTURE_MARKER in content
        assert aah.HARDBLOCK_MARKER in content
        compile(content, str(patch_env), "exec")

    def test_revert_all_clears_every_marker(self, patch_env):
        """revert_all reverts in reverse apply order — every snapshot is clean."""
        aah.apply_all(patch_env, dry_run=False)
        ok, _, _ = aah.revert_all(patch_env)
        assert ok
        content = patch_env.read_text(encoding="utf-8")
        assert not any(s.marker in content for s in aah.ALL_SPECS)
        compile(content, str(patch_env), "exec")


# ── 3. Hook wiring: transform_llm_output (not the dead post_llm_response) ──


class _FakeCtx:
    """Minimal PluginContext that records register_hook calls."""

    def __init__(self):
        self.hooks: dict = {}

    def register_hook(self, name, cb):
        self.hooks[name] = cb


class TestHookWiring:
    """Regression for the live-found hook-name bug.

    The plugin previously registered ``post_llm_response``, which is NOT a
    Hermes hook name (Hermes fires ``transform_llm_output`` to replace the
    response, and ``post_llm_call`` — whose return is discarded — for side
    effects). So token restore never happened. This locks in the correct hook.
    """

    def _ctx_with_plugin(self, monkeypatch, tmp_path):
        import privacy_shield as ps_pkg
        plugin = PrivacyShieldPlugin(
            config=PrivacyShieldConfig(
                enabled=True,
                storage_path=str(tmp_path / "mapping.db"),
                encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
            )
        )
        # register() constructs PrivacyShieldPlugin() with load_config(); inject
        # our pre-built plugin so the test never touches the real key/DB.
        monkeypatch.setattr(ps_pkg, "PrivacyShieldPlugin", lambda: plugin)
        ctx = _FakeCtx()
        ps_pkg.register(ctx)
        return ctx, plugin

    def test_registers_transform_llm_output(self, monkeypatch, tmp_path):
        ctx, _ = self._ctx_with_plugin(monkeypatch, tmp_path)
        assert "transform_llm_output" in ctx.hooks, "must register the restore hook"
        assert "post_llm_response" not in ctx.hooks, (
            "must NOT register the dead 'post_llm_response' name"
        )
        assert "pre_llm_call" in ctx.hooks

    def test_restore_callback_restores_tokens(self, monkeypatch, tmp_path):
        ctx, plugin = self._ctx_with_plugin(monkeypatch, tmp_path)
        # Store a mapping via the redaction hook (session s1).
        plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT_ID",)
        redacted = ctx.hooks["pre_llm_call"](
            user_message="mail an max.mustermann@firma-gmbh.de",
            session_id="s1", model="m", platform="", is_first_turn=True,
        )
        assert redacted and redacted["user_message"] != "mail an max.mustermann@firma-gmbh.de"
        tokenized = redacted["user_message"]
        token_match = re.search(r"TOKEN_EMAIL_[0-9a-f]{10}_\d{3}", tokenized)
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
        # No tokens in the response → no transformation (leave unchanged).
        result = ctx.hooks["transform_llm_output"](
            response_text="Guten Tag, keine Tokens hier.",
            session_id="s1", model="m", platform="",
        )
        assert result is None