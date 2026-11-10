"""Tests for Phase-4 cache leak mitigation and egress prevention."""

import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.mapping_table import InMemoryMappingTable
from privacy_shield.plugin import PrivacyShieldPlugin
from _shield_contract_seam import staged_result as _staged_result


@pytest.fixture
def plugin(tmp_path):
    cfg = PrivacyShieldConfig(
        enabled=True,
        storage_mode="memory",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
    )
    return PrivacyShieldPlugin(config=cfg)


class TestInMemoryMappingTable:
    def test_no_disk_created(self, tmp_path):
        table = InMemoryMappingTable(storage_path=str(tmp_path / "never-created.db"))
        table.store(
            [{"original_hash": "h1", "original_value": "secret", "token": "TOKEN_EMAIL_001", "type": "email"}],
            session_id="s1",
        )
        # No file should be created
        assert not (tmp_path / "never-created.db").exists()

    def test_store_and_restore(self):
        table = InMemoryMappingTable()
        table.store(
            [{"original_hash": "h1", "original_value": "secret", "token": "TOKEN_EMAIL_a1b2c3d4e5_000", "type": "email"}],
            session_id="s1",
        )
        restored = table.restore_text("Mail an TOKEN_EMAIL_a1b2c3d4e5_000", session_id="s1")
        assert restored == "Mail an secret"

    def test_close_session_removes_mappings(self):
        table = InMemoryMappingTable()
        table.store(
            [{"original_hash": "h1", "original_value": "secret", "token": "TOKEN_EMAIL_a1b2c3d4e5_000", "type": "email"}],
            session_id="s1",
        )
        table.close_session("s1")
        assert table.count() == 0
        restored = table.restore_text("Mail an TOKEN_EMAIL_a1b2c3d4e5_000", session_id="s1")
        assert "TOKEN_EMAIL_a1b2c3d4e5_000" in restored

    def test_session_isolation(self):
        table = InMemoryMappingTable()
        table.store(
            [{"original_hash": "h1", "original_value": "alice", "token": "TOKEN_EMAIL_a1b2c3d4e5_000", "type": "email"}],
            session_id="s1",
        )
        table.store(
            [{"original_hash": "h2", "original_value": "bob", "token": "TOKEN_EMAIL_a1b2c3d4e5_000", "type": "email"}],
            session_id="s2",
        )
        assert table.restore_text("TOKEN_EMAIL_a1b2c3d4e5_000", session_id="s1") == "alice"
        assert table.restore_text("TOKEN_EMAIL_a1b2c3d4e5_000", session_id="s2") == "bob"


class TestVaultBypass:
    def test_vault_source_not_pseudonymized(self, plugin):
        text = "mail an alice@example.com"
        result = plugin.pre_llm_call(
            text, context={"content_source": "mcp__obsidian__obsidian_get_file_contents", "session_id": "s1"}
        )
        assert result is None

    def test_non_vault_source_pseudonymized(self, plugin):
        text = "mail an alice@example.com"
        result = _staged_result(
            plugin,
            plugin.pre_llm_call(text, context={"content_source": "web_extract", "session_id": "s1"}),
        )
        assert result is not None
        assert "alice@example.com" not in result["user_message"]


class TestEgressPrevention:
    def test_restore_allowed_for_telegram_test_chat(self, plugin):
        plugin.config.restore_allowed_channels = ("telegram:TEST_CHAT_ID",)
        text = "mail an alice@example.com"
        redacted = _staged_result(
            plugin, plugin.pre_llm_call(text, context={"session_id": "s1"})
        )["user_message"]
        token_match = re.search(r"TOKEN_EMAIL_[0-9a-f]{10}_\d{3}", redacted)
        assert token_match, "no token generated"
        real_token = token_match.group(0)
        response = f"Bestätige Empfang: Mail an {real_token}"
        restored = plugin.post_llm_response(response, session_id="s1", target_channel="telegram:TEST_CHAT_ID")
        assert "alice@example.com" in restored

    def test_restore_blocked_for_write_file(self, plugin):
        text = "mail an alice@example.com"
        redacted = _staged_result(
            plugin, plugin.pre_llm_call(text, context={"session_id": "s1"})
        )["user_message"]
        result = plugin.post_llm_response(redacted, session_id="s1", target_channel="write_file")
        assert "alice@example.com" not in result
        assert "TOKEN_EMAIL_" in result

    def test_restore_blocked_for_unknown_channel(self, plugin):
        text = "mail an alice@example.com"
        redacted = _staged_result(
            plugin, plugin.pre_llm_call(text, context={"session_id": "s1"})
        )["user_message"]
        result = plugin.post_llm_response(redacted, session_id="s1", target_channel="")
        assert "alice@example.com" not in result


class TestCacheBypassTag:
    def test_cache_bypass_prefix_added(self, plugin):
        text = "mail an alice@example.com"
        result = _staged_result(
            plugin, plugin.pre_llm_call(text, context={"session_id": "s1"})
        )
        assert "[Privacy-Shield Session:s1:" in result["user_message"]
        assert "[PS:s1:" in result["user_message"]
        assert "privacy-shield session=s1" in result["user_message"]

    def test_cache_bypass_changes_between_calls(self, plugin):
        text = "mail an alice@example.com"
        r1 = _staged_result(plugin, plugin.pre_llm_call(text, context={"session_id": "s1"}))
        r2 = _staged_result(plugin, plugin.pre_llm_call(text, context={"session_id": "s1"}))
        assert r1["user_message"] != r2["user_message"]
