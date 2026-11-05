"""Tests for injection_shield.mcp.integrity module."""

from __future__ import annotations

from pathlib import Path


from injection_shield.mcp.integrity import ResponseHasher, compute_response_hash


class TestResponseHasher:
    """Unit tests for ResponseHasher."""

    # ------------------------------------------------------------------ #
    # hash_response
    # ------------------------------------------------------------------ #
    def test_hash_response_dict(self) -> None:
        hasher = ResponseHasher()
        h1 = hasher.hash_response({"a": 1, "b": 2})
        h2 = hasher.hash_response({"b": 2, "a": 1})
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_response_list(self) -> None:
        hasher = ResponseHasher()
        h = hasher.hash_response([1, 2, 3])
        assert len(h) == 64

    def test_hash_response_str(self) -> None:
        hasher = ResponseHasher()
        h = hasher.hash_response("hello")
        assert len(h) == 64

    def test_hash_response_bytes(self) -> None:
        hasher = ResponseHasher()
        h = hasher.hash_response(b"raw bytes")
        assert len(h) == 64

    def test_hash_response_none(self) -> None:
        hasher = ResponseHasher()
        h = hasher.hash_response(None)
        assert len(h) == 64

    def test_hash_response_stable(self) -> None:
        hasher = ResponseHasher()
        h1 = hasher.hash_response({"x": True})
        h2 = hasher.hash_response({"x": True})
        assert h1 == h2

    # ------------------------------------------------------------------ #
    # log_hash / read_log
    # ------------------------------------------------------------------ #
    def test_log_and_read(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        digest = hasher.log_hash("obsidian", "read_page", {"content": "hello"})
        assert len(digest) == 64
        entries = hasher.read_log("obsidian")
        assert len(entries) == 1
        assert entries[0]["tool"] == "read_page"
        assert entries[0]["digest"] == digest

    def test_log_multiple_tools(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        hasher.log_hash("github", "get_issue", {"id": 1})
        hasher.log_hash("github", "get_issue", {"id": 2})
        entries = hasher.read_log("github")
        assert len(entries) == 2

    def test_read_log_empty(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        entries = hasher.read_log("nonexistent")
        assert entries == []

    def test_read_log_corrupt_line(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        log_path = hasher._log_path("obsidian")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text('{"tool": "x", "digest": "abc"}\ninvalid json\n')
        entries = hasher.read_log("obsidian")
        assert len(entries) == 1

    # ------------------------------------------------------------------ #
    # verify_against_log
    # ------------------------------------------------------------------ #
    def test_verify_against_log_empty_passes(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        ok = hasher.verify_against_log("obsidian", {"content": "hello"})
        assert ok is True

    def test_verify_against_log_match(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        resp = {"content": "hello"}
        hasher.log_hash("obsidian", "read_page", resp)
        ok = hasher.verify_against_log("obsidian", resp)
        assert ok is True

    def test_verify_against_log_mismatch(self, tmp_path: Path) -> None:
        hasher = ResponseHasher(hash_log_dir=tmp_path)
        hasher.log_hash("obsidian", "read_page", {"content": "hello"})
        ok = hasher.verify_against_log("obsidian", {"content": "world"})
        assert ok is False

    # ------------------------------------------------------------------ #
    # _canonical_bytes edge cases
    # ------------------------------------------------------------------ #
    def test_canonical_bytes_custom_object(self) -> None:
        hasher = ResponseHasher()
        class X:
            def __str__(self) -> str:
                return "custom"
        raw = hasher._canonical_bytes(X())
        # Falls through json.dumps(str(value)) → '"custom"' in UTF-8
        assert raw == b'"custom"'

    def test_canonical_bytes_circular_ref_falls_back(self) -> None:
        hasher = ResponseHasher()
        d: dict = {}
        d["self"] = d
        raw = hasher._canonical_bytes(d)
        # Falls back to str() representation
        assert isinstance(raw, bytes)
        assert len(raw) > 0

    # ------------------------------------------------------------------ #
    # Module-level compute_response_hash
    # ------------------------------------------------------------------ #
    def test_compute_response_hash(self) -> None:
        h1 = compute_response_hash({"a": 1})
        h2 = compute_response_hash({"a": 1})
        assert h1 == h2
        assert len(h1) == 64
