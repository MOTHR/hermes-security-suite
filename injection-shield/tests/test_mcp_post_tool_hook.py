"""Tests for injection_shield.mcp.post_tool_hook module."""

from __future__ import annotations

import pytest

from injection_shield.mcp.post_tool_hook import (
    MCP_SERVER_PREFIXES,
    _extract_server_id,
    verify_response,
)
from injection_shield.mcp.trust_store import TrustLevel, TrustStore


class TestExtractServerId:
    """Unit tests for _extract_server_id."""

    @pytest.mark.parametrize(
        "tool_name, expected",
        [
            ("mcp__obsidian__read_page", "obsidian"),
            ("mcp__telegram__send_message", "telegram"),
            ("mcp__github__get_issue", "github"),
            ("mcp__vault_search__search", "vault_search"),
            ("mcp__browseos__navigate", "browseos"),
        ],
    )
    def test_known_servers(self, tool_name: str, expected: str) -> None:
        assert _extract_server_id(tool_name) == expected

    def test_non_mcp_tool(self) -> None:
        assert _extract_server_id("terminal") is None
        assert _extract_server_id("web_search") is None
        assert _extract_server_id("read_file") is None

    def test_mcp_prefixes_tuple(self) -> None:
        """Ensure all active servers are listed."""
        # v0.6.0 (ARCH-7): pipedrive + sevdesk added; verify_response itself
        # now matches any mcp__<server>__<tool> generically.
        assert len(MCP_SERVER_PREFIXES) == 7
        assert "mcp__obsidian__" in MCP_SERVER_PREFIXES
        assert "mcp__browseos__" in MCP_SERVER_PREFIXES


class TestVerifyResponse:
    """Unit tests for verify_response."""

    def test_non_mcp_tool_returns_empty(self) -> None:
        result = verify_response("terminal", "output")
        assert result["server_id"] == ""
        assert result["trust_level"] == ""
        assert result["alert"] is False

    def test_mcp_tool_first_encounter(self, tmp_path) -> None:
        from injection_shield.mcp.integrity import ResponseHasher
        from injection_shield.mcp.format_baseline import _baselines

        _baselines.clear()
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        store = TrustStore(store_dir=tmp_path)
        result = verify_response(
            "mcp__obsidian__read_page",
            {"content": "hello"},
            hasher=hasher,
            trust_store=store,
        )
        assert result["server_id"] == "obsidian"
        assert result["trust_level"] == "unverified"
        assert result["hash_matched"] is True
        assert result["alert"] is False

    def test_mcp_tool_with_anomaly(self, tmp_path) -> None:
        from injection_shield.mcp.integrity import ResponseHasher
        from injection_shield.mcp.format_baseline import _baselines

        _baselines.clear()
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        store = TrustStore(store_dir=tmp_path)
        # First call primes baseline
        verify_response(
            "mcp__obsidian__read_page",
            {"content": "hello"},
            hasher=hasher,
            trust_store=store,
        )
        # Second call with completely different keys triggers anomaly
        result = verify_response(
            "mcp__obsidian__read_page",
            {"totally_unrelated": "data"},
            hasher=hasher,
            trust_store=store,
        )
        assert result["alert"] is True
        assert "key_mismatch" in result["format_anomaly"]

    def test_mcp_tool_auto_promote_unknown(self, tmp_path) -> None:
        from injection_shield.mcp.integrity import ResponseHasher
        from injection_shield.mcp.format_baseline import _baselines

        _baselines.clear()
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        store = TrustStore(store_dir=tmp_path)
        # Ensure store starts unknown
        store.set_level("github", TrustLevel.UNKNOWN)
        _ = verify_response(
            "mcp__github__get_issue",
            {"id": 1, "title": "Bug"},
            hasher=hasher,
            trust_store=store,
        )
        # After first encounter, should be promoted to unverified
        assert store.get("github") == TrustLevel.UNVERIFIED

    def test_mcp_tool_size_anomaly(self, tmp_path) -> None:
        from injection_shield.mcp.integrity import ResponseHasher
        from injection_shield.mcp.format_baseline import _baselines

        _baselines.clear()
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        store = TrustStore(store_dir=tmp_path)
        # Prime with small responses
        for i in range(5):
            verify_response(
                "mcp__vault_search__search",
                {"matches": [f"a{i}"]},
                hasher=hasher,
                trust_store=store,
            )
        # Large response should trigger size anomaly
        result = verify_response(
            "mcp__vault_search__search",
            {"matches": ["x" * 10000]},
            hasher=hasher,
            trust_store=store,
        )
        assert result["alert"] is True
        assert "size_anomaly" in result["format_anomaly"]

    def test_mcp_tool_all_five_servers(self, tmp_path) -> None:
        """Verify all 5 active MCP servers are recognised."""
        from injection_shield.mcp.integrity import ResponseHasher
        from injection_shield.mcp.format_baseline import _baselines

        _baselines.clear()
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        store = TrustStore(store_dir=tmp_path)
        servers = [
            ("mcp__obsidian__read", {"content": "hello"}),
            ("mcp__telegram__send", {"message": "hi"}),
            ("mcp__github__get", {"id": 1}),
            ("mcp__vault_search__search", {"matches": []}),
            ("mcp__browseos__navigate", {"url": "https://example.com"}),
        ]
        for tool, resp in servers:
            result = verify_response(tool, resp, hasher=hasher, trust_store=store)
            assert result["server_id"] != ""
            assert result["trust_level"] in ("verified", "unverified", "unknown")
