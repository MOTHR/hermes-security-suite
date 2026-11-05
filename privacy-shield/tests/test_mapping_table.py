"""Tests for MappingTable — Phase 1."""

import hashlib
import os
import sqlite3
import tempfile

import pytest
from privacy_shield.detectors.regex_detector import PIIMatch
from privacy_shield.mapping_table import (
    InMemoryMappingTable,
    MappingTable,
    _compile_token_pattern,
)
from privacy_shield.pseudonymizer import Pseudonymizer


@pytest.fixture
def mapping_table():
    """Create a mapping table with a temp DB and known key.

    Uses kdf_iterations=1000 for test speed (production default is 600_000).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_mapping.db")
        table = MappingTable(
            storage_path=db_path,
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            kdf_iterations=1000,
        )
        yield table
        # Cleanup
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestMappingTable:
    """SQLite mapping table with AES-256-GCM encryption."""

    def test_store_and_lookup(self, mapping_table):
        mappings = [{
            "original_hash": "abc123def456",
            "token": "EMAIL_001",
            "type": "email",
        }]
        mapping_table.store(mappings, session_id="test-session")
        result = mapping_table.lookup_by_hash("abc123def456")
        assert result == "EMAIL_001"

    def test_lookup_nonexistent(self, mapping_table):
        result = mapping_table.lookup_by_hash("nonexistent")
        assert result is None

    def test_multiple_mappings(self, mapping_table):
        mappings = [
            {"original_hash": "hash1", "token": "EMAIL_001", "type": "email"},
            {"original_hash": "hash2", "token": "PHONE_001", "type": "phone"},
            {"original_hash": "hash3", "token": "IP_001", "type": "ip_address"},
        ]
        mapping_table.store(mappings, session_id="test")
        assert mapping_table.lookup_by_hash("hash1") == "EMAIL_001"
        assert mapping_table.lookup_by_hash("hash2") == "PHONE_001"
        assert mapping_table.lookup_by_hash("hash3") == "IP_001"

    def test_count(self, mapping_table):
        assert mapping_table.count() == 0
        mapping_table.store(
            [{"original_hash": "h1", "token": "T1", "type": "email"}],
            session_id="s1",
        )
        assert mapping_table.count() == 1
        mapping_table.store(
            [{"original_hash": "h2", "token": "T2", "type": "phone"}],
            session_id="s1",
        )
        assert mapping_table.count() == 2

    def test_empty_store(self, mapping_table):
        mapping_table.store([], session_id="test")
        assert mapping_table.count() == 0

    def test_reverse_lookup(self, mapping_table):
        mapping_table.store(
            [{"original_hash": "hash_abc", "token": "EMAIL_001", "type": "email"}],
            session_id="test",
        )
        result = mapping_table.lookup_by_token("EMAIL_001")
        assert result == "hash_abc"

    def test_reverse_lookup_nonexistent(self, mapping_table):
        result = mapping_table.lookup_by_token("NONEXISTENT")
        assert result is None

    def test_encryption_at_rest(self, mapping_table):
        """Verify token is encrypted in the database."""
        import sqlite3
        mapping_table.store(
            [{"original_hash": "hash_x", "token": "SECRET_TOKEN", "type": "email"}],
            session_id="test",
        )
        # Read raw DB
        conn = sqlite3.connect(str(mapping_table._storage_path))
        row = conn.execute(
            "SELECT token_encrypted FROM mappings WHERE original_hash = ?",
            ("hash_x",),
        ).fetchone()
        conn.close()
        # The stored value should NOT contain the plaintext token
        assert row is not None
        assert "SECRET_TOKEN" not in row[0]

    def test_session_isolation(self, mapping_table):
        mapping_table.store(
            [{"original_hash": "h1", "token": "T1", "type": "email"}],
            session_id="session-a",
        )
        mapping_table.store(
            [{"original_hash": "h2", "token": "T2", "type": "email"}],
            session_id="session-b",
        )
        # Both should be retrievable
        assert mapping_table.lookup_by_hash("h1") == "T1"
        assert mapping_table.lookup_by_hash("h2") == "T2"

    def test_reverse_lookup_uses_token_hash_index(self, mapping_table):
        """PERF-4: reverse lookup must work after token_hash column migration."""
        mapping_table.store(
            [{"original_hash": "hash_abc", "token": "EMAIL_001", "type": "email"}],
            session_id="test",
        )
        result = mapping_table.lookup_by_token("EMAIL_001")
        assert result == "hash_abc"

    def test_lookup_original_by_token_uses_token_hash_index(self, mapping_table):
        """PERF-4: original-value lookup must work after token_hash migration."""
        mapping_table.store(
            [{
                "original_hash": "hash_abc",
                "original_value": "alice@firma.de",
                "token": "TOKEN_EMAIL_a1b2c3d4e5_000",
                "type": "email",
            }],
            session_id="test",
        )
        result = mapping_table.lookup_original_by_token(
            "TOKEN_EMAIL_a1b2c3d4e5_000", session_id="test"
        )
        assert result == "alice@firma.de"

    def test_token_hash_index_exists(self, mapping_table):
        """PERF-4: idx_mappings_token_hash must exist on a fresh DB."""
        import sqlite3
        conn = sqlite3.connect(str(mapping_table._storage_path))
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='index' AND name='idx_mappings_token_hash'"
            ).fetchone()
            assert row is not None, "token_hash index missing"
        finally:
            conn.close()

    def test_backfill_token_hash_populates_legacy_rows(self, mapping_table):
        """PERF-4: _backfill_token_hash writes token_hash for empty rows."""
        mapping_table.store(
            [
                {
                    "original_hash": "h1",
                    "original_value": "v1",
                    "token": "T1",
                    "type": "email",
                }
            ],
            session_id="s1",
        )
        with sqlite3.connect(str(mapping_table._storage_path)) as conn:
            conn.execute("UPDATE mappings SET token_hash = ''")
            conn.commit()
        updated = mapping_table._backfill_token_hash()
        assert updated == 1
        with sqlite3.connect(str(mapping_table._storage_path)) as conn:
            row = conn.execute(
                "SELECT token_hash FROM mappings WHERE id = 1"
            ).fetchone()
            assert row[0] == hashlib.sha256("T1".encode()).hexdigest()

    def test_lookup_by_token_legacy_empty_hash_still_works(self, mapping_table):
        """PERF-4: legacy rows with empty token_hash still resolve via fallback."""
        mapping_table.store(
            [{"original_hash": "legacy_hash", "token": "LEGACY_123", "type": "email"}],
            session_id="legacy",
        )
        with sqlite3.connect(str(mapping_table._storage_path)) as conn:
            conn.execute("UPDATE mappings SET token_hash = ''")
            conn.commit()
        assert mapping_table.lookup_by_token("LEGACY_123") == "legacy_hash"


class TestTTLExpiry:
    """TTL-based auto-expiry: store → expire → prune → verify gone."""

    def test_store_with_ttl(self, mapping_table):
        """Store with ttl_seconds=3600 should set expires_at in the future."""
        mapping_table.store(
            [{"original_hash": "h_ttl", "token": "T_TTL", "type": "email"}],
            session_id="ttl-test",
            ttl_seconds=3600,
        )
        # Should be retrievable immediately
        assert mapping_table.lookup_by_hash("h_ttl") == "T_TTL"
        # Should not be expired
        assert mapping_table.expired_count() == 0

    def test_zero_ttl_immediately_expired(self, mapping_table):
        """Store with ttl_seconds=0 should be immediately expired."""
        mapping_table.store(
            [{"original_hash": "h_zero", "token": "T_ZERO", "type": "email"}],
            session_id="zero-ttl",
            ttl_seconds=0,
        )
        # Still retrievable (prune_expired hasn't run yet)
        assert mapping_table.lookup_by_hash("h_zero") == "T_ZERO"
        # But counted as expired
        assert mapping_table.expired_count() == 1

    def test_prune_expired_removes_only_expired(self, mapping_table):
        """prune_expired() should delete expired but keep active mappings."""
        # Store one with long TTL, one with zero TTL
        mapping_table.store(
            [{"original_hash": "h_active", "token": "T_ACTIVE", "type": "email"}],
            session_id="prune-test",
            ttl_seconds=3600,
        )
        mapping_table.store(
            [{"original_hash": "h_expired", "token": "T_EXPIRED", "type": "phone"}],
            session_id="prune-test",
            ttl_seconds=0,
        )

        assert mapping_table.count() == 2
        assert mapping_table.expired_count() == 1

        deleted = mapping_table.prune_expired()
        assert deleted == 1
        assert mapping_table.count() == 1
        assert mapping_table.expired_count() == 0

        # Active still there, expired gone
        assert mapping_table.lookup_by_hash("h_active") == "T_ACTIVE"
        assert mapping_table.lookup_by_hash("h_expired") is None

    def test_close_session_removes_all_for_session(self, mapping_table):
        """close_session() should delete all mappings for a session."""
        mapping_table.store(
            [{"original_hash": "h_a1", "token": "T_A1", "type": "email"}],
            session_id="session-a",
        )
        mapping_table.store(
            [{"original_hash": "h_a2", "token": "T_A2", "type": "phone"}],
            session_id="session-a",
        )
        mapping_table.store(
            [{"original_hash": "h_b1", "token": "T_B1", "type": "email"}],
            session_id="session-b",
        )

        assert mapping_table.count() == 3

        deleted = mapping_table.close_session("session-a")
        assert deleted == 2
        assert mapping_table.count() == 1

        # Session-a mappings gone
        assert mapping_table.lookup_by_hash("h_a1") is None
        assert mapping_table.lookup_by_hash("h_a2") is None
        # Session-b still there
        assert mapping_table.lookup_by_hash("h_b1") == "T_B1"

    def test_close_session_returns_zero_for_unknown(self, mapping_table):
        """close_session() on a non-existent session returns 0."""
        mapping_table.store(
            [{"original_hash": "h_x", "token": "T_X", "type": "email"}],
            session_id="real-session",
        )
        deleted = mapping_table.close_session("nonexistent")
        assert deleted == 0
        assert mapping_table.count() == 1

    def test_close_session_empty_id_noop(self, mapping_table):
        """close_session with empty string should be a no-op."""
        mapping_table.store(
            [{"original_hash": "h_x", "token": "T_X", "type": "email"}],
            session_id="real-session",
        )
        deleted = mapping_table.close_session("")
        assert deleted == 0
        assert mapping_table.count() == 1

    def test_expired_count_zero_when_none_expired(self, mapping_table):
        """expired_count should be 0 when all TTLs are in the future."""
        mapping_table.store(
            [{"original_hash": "h1", "token": "T1", "type": "email"}],
            session_id="s1",
            ttl_seconds=3600,
        )
        assert mapping_table.expired_count() == 0

    def test_prune_expired_empty_table(self, mapping_table):
        """prune_expired on empty table should return 0."""
        assert mapping_table.prune_expired() == 0
        assert mapping_table.count() == 0


class TestCrossSessionCollision:
    """Regression: two sessions map the same token to different originals.

    Before the fix, ``lookup_original_by_token`` scanned ALL rows and returned
    the first (oldest) match, so session B's restored response could surface
    session A's person — a cross-session PII leak. The session_id-scoped
    lookup must return each session's own original.
    """

    SAME_TOKEN = "TOKEN_EMAIL_a1b2c3d4e5_000"

    def _store(self, mapping_table, session_id, original_value, original_hash):
        mapping_table.store(
            [{
                "original_hash": original_hash,
                "original_value": original_value,
                "token": self.SAME_TOKEN,
                "type": "email",
            }],
            session_id=session_id,
        )

    def test_session_scoped_lookup_returns_own_original(self, mapping_table):
        self._store(mapping_table, "sess-a", "alice@firma.de", "hash-a")
        self._store(mapping_table, "sess-b", "bob@andere.de", "hash-b")

        assert (
            mapping_table.lookup_original_by_token(
                self.SAME_TOKEN, session_id="sess-a"
            )
            == "alice@firma.de"
        )
        assert (
            mapping_table.lookup_original_by_token(
                self.SAME_TOKEN, session_id="sess-b"
            )
            == "bob@andere.de"
        )

    def test_restore_text_session_scoped(self, mapping_table):
        """restore_text(session_id=...) resolves to the session's own PII."""
        self._store(mapping_table, "sess-a", "alice@firma.de", "hash-a")
        self._store(mapping_table, "sess-b", "bob@andere.de", "hash-b")

        text = f"Schick die Mail an {self.SAME_TOKEN}"
        assert (
            mapping_table.restore_text(text, session_id="sess-a")
            == "Schick die Mail an alice@firma.de"
        )
        assert (
            mapping_table.restore_text(text, session_id="sess-b")
            == "Schick die Mail an bob@andere.de"
        )

    def test_unscoped_restore_does_not_cross_wire(self, mapping_table):
        """Empty session_id scans all and returns the most recent mapping
        (id DESC) — deterministic, and never silently mixes the two."""
        self._store(mapping_table, "sess-a", "alice@firma.de", "hash-a")
        self._store(mapping_table, "sess-b", "bob@andere.de", "hash-b")

        text = f"Schick die Mail an {self.SAME_TOKEN}"
        restored = mapping_table.restore_text(text)
        # Most-recent (sess-b) wins; the point is it returns exactly one
        # consistent value, not a cross-session mix.
        assert restored == "Schick die Mail an bob@andere.de"

    def test_unknown_session_returns_token_as_is(self, mapping_table):
        """A session that stored no mapping for the token leaves it untouched."""
        self._store(mapping_table, "sess-a", "alice@firma.de", "hash-a")
        text = f"Mail an {self.SAME_TOKEN}"
        assert (
            mapping_table.restore_text(text, session_id="sess-unknown")
            == text
        )


# ── FIX-4A: Token-Prefix configurability (NEU-001) ───────────────────────


class TestTokenPatternCompiler:
    """Unit-tests for the shared ``_compile_token_pattern`` helper.

    The helper is the single source of truth for the restore-time regex.
    Both ``MappingTable.restore_text`` and ``InMemoryMappingTable.restore_text``
    build their pattern via this helper, so a bug here propagates to every
    restore call.
    """

    def test_default_pattern_includes_token_prefix(self):
        p = _compile_token_pattern("TOKEN", 10, 3)
        m = p.search("see TOKEN_EMAIL_a1b2c3d4e5_000 please")
        assert m is not None
        assert m.group(0) == "TOKEN_EMAIL_a1b2c3d4e5_000"

    def test_custom_prefix_ps(self):
        p = _compile_token_pattern("PS", 10, 3)
        m = p.search("see PS_EMAIL_a1b2c3d4e5_001 please")
        assert m is not None
        assert m.group(0) == "PS_EMAIL_a1b2c3d4e5_001"
        # And critically: TOKEN_ prefix does NOT match when the configured
        # prefix is PS. This is the bug FIX-4A fixes.
        assert p.search("TOKEN_EMAIL_a1b2c3d4e5_001") is None

    def test_custom_prefix_token_does_not_match_other_prefix(self):
        """Symmetric: a TOKEN_-prefixed pattern must NOT match PS_ tokens."""
        p = _compile_token_pattern("TOKEN", 10, 3)
        assert p.search("PS_EMAIL_a1b2c3d4e5_001") is None

    def test_counter_suffix_is_optional(self):
        """Backward-compat: tokens emitted before FIX-3C have no counter
        suffix. The pattern must still match them so old text round-trips."""
        p = _compile_token_pattern("TOKEN", 10, 3)
        m_no_counter = p.search("see TOKEN_EMAIL_a1b2c3d4e5 end")
        assert m_no_counter is not None
        assert m_no_counter.group(0) == "TOKEN_EMAIL_a1b2c3d4e5"
        # Counter group is None when not present
        assert m_no_counter.group(3) is None

    def test_token_boundary_inside_alphanumeric_word(self):
        """FIX-RESTORE-BOUNDARY: a token embedded after an underscore in a
        larger compound word (e.g. FAKE_API_KEY_TOKEN_PHONE_..._001abc) must
        still be matched and restored. The old \\b boundary failed because
        there is no word boundary between '_' and 'TOKEN'."""
        p = _compile_token_pattern("TOKEN", 10, 3)
        text = "FAKE_API_KEY_TOKEN_PHONE_a1b2c3d4e5_001abcdef"
        m = p.search(text)
        assert m is not None, "token should match after underscore boundary"
        assert m.group(0) == "TOKEN_PHONE_a1b2c3d4e5_001"
        # Punctuation/whitespace after token is allowed.
        assert p.search("x TOKEN_PHONE_a1b2c3d4e5_001. y").group(0) == "TOKEN_PHONE_a1b2c3d4e5_001"
        # A token followed by an extra leftover digit must NOT match the full
        # invalid token, but must still match the valid 3-digit token prefix.
        m2 = p.search("TOKEN_PHONE_a1b2c3d4e5_0002")
        assert m2 is not None
        assert m2.group(0) == "TOKEN_PHONE_a1b2c3d4e5_000"

    def test_ps_mask_006_token_preceded_by_alphanumerics_no_delimiter(self):
        """PS-MASK-006: token immediately preceded by alphanumerics (no delimiter)
        must still match. The negative lookbehind (?<![A-Za-z0-9]) was removed
        because the token prefix (TOKEN_/PS_) is globally unique in the output
        stream. Example: abcTOKEN_PHONE_a1b2c3d4e5_001 (compound string)."""
        p = _compile_token_pattern("TOKEN", 10, 3)
        text = "abcTOKEN_PHONE_a1b2c3d4e5_001"
        m = p.search(text)
        assert m is not None, "token should match when preceded by alphanumerics"
        assert m.group(0) == "TOKEN_PHONE_a1b2c3d4e5_001"
        # The match starts after "abc" (position 3)
        assert m.start() == 3
        # Also test with underscore prefix (the original FIX-RESTORE-BOUNDARY case)
        text2 = "FAKE_API_KEY_TOKEN_PHONE_a1b2c3d4e5_001abcdef"
        m2 = p.search(text2)
        assert m2 is not None
        assert m2.group(0) == "TOKEN_PHONE_a1b2c3d4e5_001"
        # Also test string start (no preceding char)
        text3 = "TOKEN_PHONE_a1b2c3d4e5_001end"
        m3 = p.search(text3)
        assert m3 is not None
        assert m3.group(0) == "TOKEN_PHONE_a1b2c3d4e5_001"

    def test_hash_length_is_honored(self):
        """A 16-hex hash variant should still match a 10-hex variant
        because ``{10}`` matches exactly 10 hex chars; the regex does NOT
        require the trailing chars to be non-hex. We assert by inspecting
        the compiled pattern."""
        p10 = _compile_token_pattern("TOKEN", 10, 3)
        p16 = _compile_token_pattern("TOKEN", 16, 3)
        # 10-hex token must match the 10-hex pattern…
        assert p10.search("TOKEN_EMAIL_a1b2c3d4e5_000") is not None
        # …and MUST NOT match the 16-hex pattern.
        assert p16.search("TOKEN_EMAIL_a1b2c3d4e5_000") is None
        # 16-hex token matches the 16-hex pattern.
        assert p16.search("TOKEN_EMAIL_a1b2c3d4e5ff0011_000") is not None

    def test_invalid_prefix_rejected(self):
        with pytest.raises(ValueError, match="invalid token_prefix"):
            _compile_token_pattern("", 10, 3)
        with pytest.raises(ValueError, match="invalid token_prefix"):
            _compile_token_pattern("TOKEN-WITH-DASH", 10, 3)
        with pytest.raises(ValueError, match="invalid token_prefix"):
            _compile_token_pattern("123starts_with_digit", 10, 3)

    def test_invalid_hash_length_rejected(self):
        with pytest.raises(ValueError, match="hash_length"):
            _compile_token_pattern("TOKEN", 3, 3)
        with pytest.raises(ValueError, match="hash_length"):
            _compile_token_pattern("TOKEN", 100, 3)

    def test_invalid_counter_digits_rejected(self):
        with pytest.raises(ValueError, match="counter_digits"):
            _compile_token_pattern("TOKEN", 10, -1)
        with pytest.raises(ValueError, match="counter_digits"):
            _compile_token_pattern("TOKEN", 10, 99)

    def test_special_chars_in_prefix_are_escaped(self):
        """Defence-in-depth: the validator first rejects non-identifier
        prefixes (``P.S`` contains a dot, ``re`` would treat it as a
        meta-char). Identifier-only prefixes are passed through
        ``re.escape`` so the regex still cannot be tricked by chars
        the identifier grammar does accept (``_`` etc.)."""
        # 1) Non-identifier prefixes are rejected up-front.
        with pytest.raises(ValueError, match="invalid token_prefix"):
            _compile_token_pattern("P.S", 10, 3)
        with pytest.raises(ValueError, match="invalid token_prefix"):
            _compile_token_pattern("a-b", 10, 3)

        # 2) Identifier prefixes that look regex-relevant after escape
        # still produce a literal match. The validator + escape combo is
        # defence in depth, not a guarantee that ``re.escape`` alone
        # would suffice (it does, but the validator already filters).
        p = _compile_token_pattern("PS_TOKEN", 10, 3)
        assert p.search("PS_TOKEN_EMAIL_a1b2c3d4e5_000") is not None
        # An underscore-only identifier must match literally.
        assert p.search("PSXTOKEN_EMAIL_a1b2c3d4e5_000") is None


class TestInMemoryRestoreWithCustomPrefix:
    """End-to-end: InMemoryMappingTable with a custom token prefix."""

    def test_round_trip_with_ps_prefix(self):
        """Pseudonymizer emits ``PS_*`` and the mapper restores it back to
        the original PII. Pre-fix this returned the token unchanged."""
        table = InMemoryMappingTable(
            token_prefix="PS", hash_length=10, counter_digits=3
        )
        p = Pseudonymizer(token_prefix="PS")
        text = "Kontakt: max.mustermann@example.com"
        matches = [
            PIIMatch(start=9, end=35, type="email", value="max.mustermann@example.com")
        ]
        sanitized, mapping = p.replace(text, matches, session_id="sess-ps")
        assert "PS_EMAIL_" in sanitized

        table.store(mapping, session_id="sess-ps")
        restored = table.restore_text(sanitized, session_id="sess-ps")
        assert restored == text

    def test_default_prefix_still_works(self):
        """Regression: the default TOKEN_ prefix must still round-trip."""
        table = InMemoryMappingTable()
        p = Pseudonymizer()
        text = "Mail an bob@example.com"
        matches = [
            PIIMatch(start=8, end=23, type="email", value="bob@example.com")
        ]
        sanitized, mapping = p.replace(text, matches, session_id="sess-tok")
        assert "TOKEN_EMAIL_" in sanitized

        table.store(mapping, session_id="sess-tok")
        assert table.restore_text(sanitized, session_id="sess-tok") == text

    def test_unknown_token_with_custom_prefix_left_as_is(self):
        """A PS_-prefixed mapper sees a TOKEN_ token (e.g. produced by a
        legacy session) — it is left untouched because the pattern no
        longer matches TOKEN_."""
        table = InMemoryMappingTable(token_prefix="PS")
        text = "Token still here: TOKEN_EMAIL_a1b2c3d4e5_000"
        assert table.restore_text(text, session_id="any") == text


class TestSqliteRestoreWithCustomPrefix:
    """End-to-end: SQLite-backed MappingTable with a custom token prefix."""

    def _make_table(self, tmpdir, prefix: str) -> MappingTable:
        return MappingTable(
            storage_path=os.path.join(tmpdir, f"m-{prefix}.db"),
            encryption_key="x" * 32,
            kdf_iterations=1000,
            token_prefix=prefix,
            hash_length=10,
            counter_digits=3,
        )

    def test_sqlite_round_trip_with_ps_prefix(self, tmp_path):
        table = self._make_table(str(tmp_path), "PS")
        p = Pseudonymizer(token_prefix="PS")
        text = "IBAN: DE89370400440532013000"
        # Add an explicit match for IBAN — we'll just test with email instead
        # since IBAN detection is not in the scope of this fix
        text = "Kontakt: max.mustermann@example.com"
        matches = [
            PIIMatch(start=9, end=35, type="email", value="max.mustermann@example.com")
        ]
        sanitized, mapping = p.replace(text, matches, session_id="sql-ps")
        assert "PS_EMAIL_" in sanitized

        table.store(mapping, session_id="sql-ps")
        assert table.restore_text(sanitized, session_id="sql-ps") == text

    def test_sqlite_default_prefix_unchanged(self, tmp_path):
        table = MappingTable(
            storage_path=str(tmp_path / "default.db"),
            encryption_key="x" * 32,
            kdf_iterations=1000,
            # token_prefix defaults to "TOKEN"
        )
        p = Pseudonymizer()
        text = "Mail: max.mustermann@example.com"
        matches = [
            PIIMatch(start=6, end=32, type="email", value="max.mustermann@example.com")
        ]
        sanitized, mapping = p.replace(text, matches, session_id="sql-tok")
        table.store(mapping, session_id="sql-tok")
        assert table.restore_text(sanitized, session_id="sql-tok") == text


class TestPluginWiresCustomPrefix:
    """Verify PrivacyShieldPlugin._build_mapper threads the configured
    token_prefix into both MappingTable and InMemoryMappingTable."""

    def test_in_memory_plugin_uses_configured_prefix(self, tmp_path, monkeypatch):
        """When config.token_prefix='PS' the InMemoryMappingTable's
        token_pattern must be the PS-prefixed pattern, not the default
        TOKEN_ one. This is the regression FIX-4A prevents."""
        from privacy_shield.config import PrivacyShieldConfig
        from privacy_shield.plugin import PrivacyShieldPlugin

        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="audit",  # disable pseudonymize side-effects for the test
            storage_mode="memory",
            token_prefix="PS",
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        assert plugin.mapper.token_prefix == "PS"
        assert "PS_" in plugin.mapper.token_pattern.pattern
        assert "TOKEN_" not in plugin.mapper.token_pattern.pattern

    def test_default_plugin_keeps_token_prefix(self, tmp_path):
        from privacy_shield.config import PrivacyShieldConfig
        from privacy_shield.plugin import PrivacyShieldPlugin

        cfg = PrivacyShieldConfig(enabled=True, mode="audit", storage_mode="memory")
        plugin = PrivacyShieldPlugin(config=cfg)
        assert plugin.mapper.token_prefix == "TOKEN"
        assert "TOKEN_" in plugin.mapper.token_pattern.pattern
