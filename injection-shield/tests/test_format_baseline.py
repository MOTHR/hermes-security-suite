"""Tests for injection_shield.mcp.format_baseline module."""

from __future__ import annotations


from injection_shield.mcp.format_baseline import (
    FormatBaseline,
    _baselines,
    detect_format_anomaly,
)


class TestFormatBaseline:
    """Unit tests for FormatBaseline."""

    def test_init_static_seed(self) -> None:
        """Static seed from KNOWN_MCP_SERVERS primes the baseline."""
        fb = FormatBaseline("obsidian")
        assert "content" in fb.expected_keys
        assert "path" in fb.expected_keys
        assert len(fb.size_history) == 5

    def test_init_no_static_seed(self) -> None:
        fb = FormatBaseline("custom_server")
        assert fb.expected_keys == set()
        assert fb.size_history == []

    # ------------------------------------------------------------------ #
    # observe
    # ------------------------------------------------------------------ #
    def test_observe_dict(self) -> None:
        fb = FormatBaseline("obsidian")
        fb.observe({"title": "Note", "body": "Text"}, tool_name="read_page")
        assert "title" in fb.expected_keys
        assert "body" in fb.expected_keys
        assert len(fb.size_history) == 6

    def test_observe_non_dict(self) -> None:
        fb = FormatBaseline("obsidian")
        fb.observe("plain string", tool_name="read_page")
        # No keys extracted, size still recorded
        assert len(fb.size_history) == 6

    def test_observe_prunes_history(self) -> None:
        fb = FormatBaseline("obsidian")
        for i in range(60):
            fb.observe({"x": i}, tool_name="t")
        assert len(fb.size_history) == 50

    def test_observe_tool_shape(self) -> None:
        fb = FormatBaseline("github")
        fb.observe({"id": 1}, tool_name="get_issue")
        assert "get_issue" in fb.tool_shapes
        assert "id" in fb.tool_shapes["get_issue"]

    # ------------------------------------------------------------------ #
    # check_anomaly
    # ------------------------------------------------------------------ #
    def test_no_anomaly(self) -> None:
        fb = FormatBaseline("obsidian")
        # Prime with a few observations
        fb.observe({"content": "hello world"}, tool_name="read")
        fb.observe({"content": "hello again"}, tool_name="read")
        fb.observe({"content": "third time"}, tool_name="read")
        anomaly = fb.check_anomaly({"content": "normal"}, tool_name="read")
        assert anomaly == {}

    def test_key_mismatch(self) -> None:
        fb = FormatBaseline("obsidian")
        fb.observe({"content": "hello"}, tool_name="read")
        anomaly = fb.check_anomaly({"unexpected_only": "data"}, tool_name="read")
        assert "key_mismatch" in anomaly
        assert anomaly["key_mismatch"]["got_keys"] == ["unexpected_only"]

    def test_key_mismatch_empty_baseline(self) -> None:
        """Empty baseline should not flag key mismatch."""
        fb = FormatBaseline("empty_server")
        anomaly = fb.check_anomaly({"foo": "bar"})
        assert "key_mismatch" not in anomaly

    def test_size_anomaly(self) -> None:
        fb = FormatBaseline("obsidian")
        # Prime with small responses
        for _ in range(5):
            fb.observe({"content": "x"}, tool_name="read")
        # Large response should trigger
        big = {"content": "x" * 10000}
        anomaly = fb.check_anomaly(big, tool_name="read")
        assert "size_anomaly" in anomaly
        assert anomaly["size_anomaly"]["size"] > anomaly["size_anomaly"]["threshold"]

    def test_size_anomaly_insufficient_history(self) -> None:
        """With < 3 observations in history, size check is skipped."""
        fb = FormatBaseline("custom_server")  # No static seed → empty history
        fb.observe({"content": "x"}, tool_name="read")
        # History = 1 (< 3) → no size anomaly check
        anomaly = fb.check_anomaly({"content": "y" * 10000})
        assert "size_anomaly" not in anomaly

    # ------------------------------------------------------------------ #
    # detect_format_anomaly (module-level)
    # ------------------------------------------------------------------ #
    def test_detect_format_anomaly_no_alert(self) -> None:
        _baselines.clear()
        anomaly = detect_format_anomaly("obsidian", {"content": "hello"})
        assert anomaly == {}

    def test_detect_format_anomaly_with_learn(self) -> None:
        _baselines.clear()
        # First call establishes baseline
        detect_format_anomaly("vault_search", {"matches": ["a", "b"]}, learn=True)
        # Second identical call should not alert
        anomaly = detect_format_anomaly("vault_search", {"matches": ["a", "b"]}, learn=True)
        assert anomaly == {}

    def test_detect_format_anomaly_no_learn(self) -> None:
        _baselines.clear()
        # Baseline is seeded from static data
        anomaly = detect_format_anomaly("obsidian", {"content": "x"}, learn=False)
        assert anomaly == {}

    def test_detect_format_anomaly_key_mismatch(self) -> None:
        _baselines.clear()
        # Force a key mismatch by using a different key set
        anomaly = detect_format_anomaly(
            "obsidian",
            {"totally_unrelated_field": "data", "another": "field"},
            learn=False,
        )
        assert "key_mismatch" in anomaly

    # ------------------------------------------------------------------ #
    # _extract_keys edge cases
    # ------------------------------------------------------------------ #
    def test_extract_keys_nested(self) -> None:
        keys = FormatBaseline._extract_keys({"a": {"b": 1}, "c": [1, 2]})
        assert keys == {"a", "c"}

    def test_extract_keys_list(self) -> None:
        keys = FormatBaseline._extract_keys([1, 2, 3])
        assert keys == set()

    def test_extract_keys_none(self) -> None:
        keys = FormatBaseline._extract_keys(None)
        assert keys == set()
