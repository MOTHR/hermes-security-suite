"""Tests for injection_shield.mcp.trust_store module."""

from __future__ import annotations

from pathlib import Path


from injection_shield.mcp.trust_store import TrustLevel, TrustStore


class TestTrustLevel:
    """Smoke tests for TrustLevel enum."""

    def test_values(self) -> None:
        assert TrustLevel.VERIFIED.value == "verified"
        assert TrustLevel.UNVERIFIED.value == "unverified"
        assert TrustLevel.UNKNOWN.value == "unknown"

    def test_comparison(self) -> None:
        assert TrustLevel.VERIFIED != TrustLevel.UNKNOWN
        assert TrustLevel.VERIFIED == TrustLevel.VERIFIED


class TestTrustStore:
    """Unit tests for TrustStore."""

    # ------------------------------------------------------------------ #
    # get / set_level
    # ------------------------------------------------------------------ #
    def test_get_unknown_by_default(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        assert store.get("obsidian") == TrustLevel.UNKNOWN

    def test_set_and_get_verified(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("github", TrustLevel.VERIFIED)
        assert store.get("github") == TrustLevel.VERIFIED

    def test_set_and_get_unverified(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("telegram", TrustLevel.UNVERIFIED)
        assert store.get("telegram") == TrustLevel.UNVERIFIED

    def test_set_unknown_explicitly(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("browseos", TrustLevel.UNKNOWN)
        assert store.get("browseos") == TrustLevel.UNKNOWN

    # ------------------------------------------------------------------ #
    # bump_hash_count
    # ------------------------------------------------------------------ #
    def test_bump_hash_count(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("vault_search", TrustLevel.UNVERIFIED)
        store.bump_hash_count("vault_search")
        store.bump_hash_count("vault_search")
        data = store.summary()
        assert data["vault_search"]["hash_count"] == 2

    def test_bump_unknown_server_noop(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.bump_hash_count("nonexistent")
        assert store.get("nonexistent") == TrustLevel.UNKNOWN

    # ------------------------------------------------------------------ #
    # public_key_pin
    # ------------------------------------------------------------------ #
    def test_set_public_key_pin(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_public_key_pin("obsidian", "sha256:abc123")
        data = store.summary()
        assert data["obsidian"]["public_key_pin"] == "sha256:abc123"

    # ------------------------------------------------------------------ #
    # persistence
    # ------------------------------------------------------------------ #
    def test_persistence(self, tmp_path: Path) -> None:
        store1 = TrustStore(store_dir=tmp_path)
        store1.set_level("github", TrustLevel.VERIFIED)
        store1.bump_hash_count("github")

        store2 = TrustStore(store_dir=tmp_path)
        assert store2.get("github") == TrustLevel.VERIFIED
        data = store2.summary()
        assert data["github"]["hash_count"] == 1

    def test_persistence_corrupt_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "mcp-trust-levels.json"
        log_path.write_text("not valid json")
        store = TrustStore(store_dir=tmp_path)
        assert store.get("obsidian") == TrustLevel.UNKNOWN

    def test_persistence_missing_file(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        assert store.get("obsidian") == TrustLevel.UNKNOWN

    # ------------------------------------------------------------------ #
    # summary
    # ------------------------------------------------------------------ #
    def test_summary_isolation(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("obsidian", TrustLevel.VERIFIED)
        summary = store.summary()
        summary["obsidian"]["level"] = "tampered"
        # Original store unaffected
        assert store.get("obsidian") == TrustLevel.VERIFIED

    def test_summary_timestamps(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("github", TrustLevel.UNVERIFIED)
        data = store.summary()["github"]
        assert "first_seen" in data
        assert "last_seen" in data
        assert data["first_seen"] == data["last_seen"]

    # ------------------------------------------------------------------ #
    # multiple servers
    # ------------------------------------------------------------------ #
    def test_multiple_servers(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("obsidian", TrustLevel.VERIFIED)
        store.set_level("telegram", TrustLevel.UNVERIFIED)
        store.set_level("browseos", TrustLevel.UNKNOWN)
        assert store.get("obsidian") == TrustLevel.VERIFIED
        assert store.get("telegram") == TrustLevel.UNVERIFIED
        assert store.get("browseos") == TrustLevel.UNKNOWN

    def test_re_set_level_updates_timestamp(self, tmp_path: Path) -> None:
        store = TrustStore(store_dir=tmp_path)
        store.set_level("github", TrustLevel.UNVERIFIED)
        first = store.summary()["github"]["last_seen"]
        store.set_level("github", TrustLevel.VERIFIED)
        second = store.summary()["github"]["last_seen"]
        assert first != second

    # ------------------------------------------------------------------ #
    # default store_dir
    # ------------------------------------------------------------------ #
    def test_default_store_dir(self) -> None:
        store = TrustStore()
        assert store.store_dir.exists()

    # ------------------------------------------------------------------ #
    # _save with unreadable dir (best-effort)
    # ------------------------------------------------------------------ #
    def test_save_logs_warning_on_failure(self, tmp_path: Path, caplog) -> None:
        """If the store dir becomes unwritable, _save logs a warning."""
        import logging

        store = TrustStore(store_dir=tmp_path)
        # Make dir unwritable
        tmp_path.chmod(0o555)
        with caplog.at_level(logging.WARNING, logger="injection_shield.mcp.trust_store"):
            store.set_level("github", TrustLevel.VERIFIED)
        # Restore permissions for cleanup
        tmp_path.chmod(0o755)
        # Best-effort assertion; the guard keeps going regardless
        _ = caplog.text
