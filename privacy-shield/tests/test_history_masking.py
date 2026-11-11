"""R-1 History-Masking regressions (Option b, design report t_cf276f36).

Covers the four regression axes from the task spec:

  1. two user messages with PII are both masked (history + live, with and
     without a staged shield),
  2. multimodal text parts and the sidecar suffix are masked,
  3. the Ollama exemption is untouched,
  4. the per-message memo is idempotent per attempt and resets per turn.
"""

from __future__ import annotations

import json

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.plugin import PrivacyShieldPlugin


HIST_PROMPT = "Frueher Turn: Mail an max.mustermann@firma-gmbh.de"
LIVE_PROMPT = "Neue Frage: schreib an max.mustermann@firma-gmbh.de"
LIVE_NO_PII = "Welches Wetter ist heute gemeldet?"
SUFFIX = "\n\nMemory-Prefetch: Kontakt alice@example.com\n\n[plugin sidecar context]"


def _make_plugin(
    tmp_path,
    *,
    enabled=True,
    mode="limited",
    audit=True,
    mask_history=True,
    mask_sidecar_suffix=True,
):
    cfg = PrivacyShieldConfig(
        enabled=enabled,
        mode=mode,
        mask_history=mask_history,
        mask_sidecar_suffix=mask_sidecar_suffix,
        storage_path=str(tmp_path / "mapping.db"),
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
        audit_jsonl_path=str(tmp_path / "audit.jsonl"),
        audit_jsonl_enabled=audit,
    )
    return PrivacyShieldPlugin(config=cfg)


def _stage(plugin, prompt, *, turn_id="turn1", session_id="s1"):
    """Run the pre_llm_call staging the way the core does per turn."""
    plugin.pre_llm_call(
        prompt,
        context={
            "session_id": session_id,
            "turn_id": turn_id,
            "provider": "",
            "model": "m",
            "platform": "",
        },
    )
    return plugin._staged_shields.get(turn_id or "")


def _apply(plugin, request, *, turn_id="turn1", session_id="s1", provider="openai"):
    return plugin.apply_shield_to_request(
        request,
        provider=provider,
        session_id=session_id,
        model="m",
        platform="",
        turn_id=turn_id,
    )


def _request(*user_contents):
    """Build a request with a system preamble and N raw user messages."""
    messages = [{"role": "system", "content": "You are a helpful assistant."}]
    for i, content in enumerate(user_contents):
        messages.append({"role": "user", "content": content})
        if i == 0:
            messages.append({"role": "assistant", "content": "ok"})
    return {"messages": messages}


def _copy(request):
    return json.loads(json.dumps(request))


def _audit_events(tmp_path):
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TestHistoryMasking:
    """P2: every user message of the request is masked, staged or not."""

    def test_masks_live_and_history_with_staged_shield(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _stage(plugin, LIVE_PROMPT)  # live prompt has PII -> staged shield
        request = _request(HIST_PROMPT, LIVE_PROMPT)
        result = _apply(plugin, request)
        assert result is not None and "request" in result
        hist, live = request["messages"][1]["content"], request["messages"][3]["content"]
        for content in (hist, live):
            assert "max.mustermann@firma-gmbh.de" not in content
            assert "TOKEN_EMAIL_" in content
        # Restore contract: same (session, value) -> same deterministic token.
        hist_token = [t for t in hist.split() if t.startswith("TOKEN_EMAIL_")][0]
        live_token = [t for t in live.split() if t.startswith("TOKEN_EMAIL_")][0]
        assert hist_token == live_token

    def test_masks_history_without_staged_shield(self, tmp_path):
        """The R-1 defect: clean live prompt -> nothing staged -> raw history
        PII egressed. Now the middleware scans all user messages standalone."""
        plugin = _make_plugin(tmp_path)
        assert _stage(plugin, LIVE_NO_PII) is None
        request = _request(HIST_PROMPT, LIVE_NO_PII)
        result = _apply(plugin, request, turn_id="turn2")
        assert result is not None
        assert "max.mustermann@firma-gmbh.de" not in request["messages"][1]["content"]
        assert "TOKEN_EMAIL_" in request["messages"][1]["content"]
        assert request["messages"][3]["content"] == LIVE_NO_PII  # untouched, no PII
        assert "Wetter" in request["messages"][3]["content"]

    def test_multimodal_history_and_suffix_parts_masked(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _stage(plugin, LIVE_PROMPT)
        request = {
            "messages": [
                {"role": "user", "content": HIST_PROMPT},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": LIVE_PROMPT},
                        {"type": "text", "text": "Kontext: Mail alice@example.com"},
                        {"type": "image_url", "image_url": {"url": "file://x"}},
                    ],
                },
            ]
        }
        result = _apply(plugin, request)
        assert result is not None
        assert "max.mustermann@firma-gmbh.de" not in request["messages"][0]["content"]
        parts = request["messages"][1]["content"]
        for part_idx in (0, 1):
            assert "firma-gmbh.de" not in parts[part_idx]["text"]
            if "example.com" in parts[part_idx]["text"]:
                assert "alice@example.com" not in parts[part_idx]["text"]
                assert "TOKEN_EMAIL_" in parts[part_idx]["text"]
        assert parts[2] == {"type": "image_url", "image_url": {"url": "file://x"}}

    def test_ollama_exempt_including_history(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _stage(plugin, LIVE_PROMPT)
        request = _request(HIST_PROMPT, LIVE_PROMPT)
        for provider in ("ollama", "ollama_local"):
            raw = _copy(_request(HIST_PROMPT, LIVE_PROMPT))
            assert _apply(plugin, raw, provider=provider) is None
            assert raw["messages"][1]["content"] == HIST_PROMPT
            assert raw["messages"][3]["content"] == LIVE_PROMPT
        # audit stays silent for exempt traffic
        assert not _audit_events(tmp_path) or not any(
            e.get("event") == "pseudonymization_applied" for e in _audit_events(tmp_path)
        )


class TestMemo:
    """Per-message memo: idempotent per attempt, lifetime = turn."""

    def test_memo_idempotent_across_attempts(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _stage(plugin, LIVE_PROMPT, turn_id="turnX")
        spy_calls: list[str] = []
        orig_scan = plugin.detector.scan

        def spy(text):
            spy_calls.append(text)
            return orig_scan(text)

        plugin.detector.scan = spy
        r1 = _copy(_request(HIST_PROMPT, LIVE_PROMPT + SUFFIX))
        first = _apply(plugin, r1, turn_id="turnX")
        assert first is not None
        first_snapshot = json.dumps(r1)
        before = len(spy_calls)
        assert before >= 1  # history + sidecar suffix scanned on attempt 1

        r2 = _copy(_request(HIST_PROMPT, LIVE_PROMPT + SUFFIX))
        second = _apply(plugin, r2, turn_id="turnX")
        assert second is not None
        # Attempt 2: every user text is memoized -> no re-scan at all...
        assert len(spy_calls) == before
        # ...and the mask output is byte-identical to attempt 1 (idempotence).
        assert json.dumps(r2) == first_snapshot

    def test_memo_resets_between_turns(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        spy_calls: list[str] = []
        orig_scan = plugin.detector.scan

        def spy(text):
            spy_calls.append(text)
            return orig_scan(text)

        plugin.detector.scan = spy
        r1 = _request(HIST_PROMPT)
        first = _apply(plugin, r1, turn_id="T1", session_id="s1")
        assert first is not None
        hist1 = r1["messages"][1]["content"]
        assert "max.mustermann@firma-gmbh.de" not in hist1
        assert hist1.startswith("Frueher Turn: Mail an TOKEN_EMAIL_")
        calls_turn1 = len(spy_calls)
        assert calls_turn1 == 1

        r2 = _request(HIST_PROMPT)
        second = _apply(plugin, r2, turn_id="T2", session_id="s1")
        assert second is not None
        # New turn -> memo dropped -> fresh scan + fresh mapping rows.
        assert len(spy_calls) == calls_turn1 + 1
        assert r2["messages"][1]["content"] == hist1

    def test_one_audit_event_per_turn_including_standalone(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        assert _stage(plugin, LIVE_NO_PII) is None
        result = _apply(plugin, _request(HIST_PROMPT), turn_id="turn2")
        assert result is not None
        _apply(plugin, _request(HIST_PROMPT), turn_id="turn2")
        events = [
            e for e in _audit_events(tmp_path)
            if e.get("event") == "pseudonymization_applied"
        ]
        assert len(events) == 1
        # Audit lines are side-channel-safe: the count is magnitude-bucketed
        # ('1-1', '1-10', ...) — a hit happened, the exact count is not leaked.
        assert events[0]["masked_count_bucket"] in ("1-1", "1-10", "1-100")


class TestFlagSwitches:
    def test_mask_history_off_keeps_legacy_live_only(self, tmp_path):
        plugin = _make_plugin(tmp_path, mask_history=False)
        _stage(plugin, LIVE_PROMPT)
        request = _request(HIST_PROMPT, LIVE_PROMPT)
        assert _apply(plugin, request) is not None
        assert request["messages"][1]["content"] == HIST_PROMPT  # raw history
        assert "TOKEN_EMAIL_" in request["messages"][3]["content"]

    def test_mask_sidecar_suffix_off_keeps_bytes_exact(self, tmp_path):
        plugin = _make_plugin(tmp_path, mask_sidecar_suffix=False)
        _stage(plugin, LIVE_PROMPT)
        wire = LIVE_PROMPT + SUFFIX
        request = {"messages": [{"role": "user", "content": wire}]}
        assert _apply(plugin, request) is not None
        out = request["messages"][0]["content"]
        assert out.endswith(SUFFIX), "suffix must stay byte-exact with flag off"

    def test_mask_sidecar_suffix_masks_pii(self, tmp_path):
        plugin = _make_plugin(tmp_path)
        _stage(plugin, LIVE_PROMPT)
        wire = LIVE_PROMPT + SUFFIX
        request = {"messages": [{"role": "user", "content": wire}]}
        assert _apply(plugin, request) is not None
        out = request["messages"][0]["content"]
        assert "alice@example.com" not in out
        assert out.endswith("[plugin sidecar context]")
        assert LIVE_PROMPT not in out
        assert "TOKEN_EMAIL_" in out
