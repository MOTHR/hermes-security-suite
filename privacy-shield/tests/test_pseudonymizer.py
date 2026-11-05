"""Tests for Pseudonymizer — Phase 1."""

import pytest
from privacy_shield.pseudonymizer import Pseudonymizer
from privacy_shield.detectors.regex_detector import RegexPIIDetector, PIIMatch


@pytest.fixture
def pseudonymizer():
    return Pseudonymizer(token_style="deterministic", token_prefix="TOKEN")


@pytest.fixture
def detector():
    return RegexPIIDetector()


class TestPseudonymizer:
    """Deterministic token generation and replacement."""

    def test_email_replacement(self, pseudonymizer, detector):
        text = "Contact max@example.com for details."
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        assert "max@example.com" not in sanitized
        assert "TOKEN_EMAIL_" in sanitized
        assert len(mapping) == 1
        assert mapping[0]["type"] == "email"

    def test_phone_replacement(self, pseudonymizer, detector):
        text = "Rufen Sie +49 30 1234567 an."
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        assert "+49 30 1234567" not in sanitized
        assert "TOKEN_PHONE_" in sanitized
        assert len(mapping) == 1

    def test_determinism_same_input_same_token(self, pseudonymizer, detector):
        """Same input → same token within same session."""
        text1 = "Email max@example.com"
        text2 = "Another email max@example.com here"
        matches1 = detector.scan(text1)
        matches2 = detector.scan(text2)
        _, mapping1 = pseudonymizer.replace(text1, matches1)
        _, mapping2 = pseudonymizer.replace(text2, matches2)
        assert mapping1[0]["token"] == mapping2[0]["token"]

    def test_different_inputs_different_tokens(self, pseudonymizer, detector):
        """Different inputs → different tokens."""
        text1 = "Email a@b.com"
        text2 = "Email c@d.com"
        matches1 = detector.scan(text1)
        matches2 = detector.scan(text2)
        _, mapping1 = pseudonymizer.replace(text1, matches1)
        _, mapping2 = pseudonymizer.replace(text2, matches2)
        assert mapping1[0]["token"] != mapping2[0]["token"]

    def test_multiple_pii_types(self, pseudonymizer, detector):
        text = "Email max@example.com, Tel +49 30 1234567, IP 192.168.1.1"
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(text, matches)
        assert "max@example.com" not in sanitized
        assert "+49 30 1234567" not in sanitized
        assert "192.168.1.1" not in sanitized
        assert len(mapping) == 3
        types = {m["type"] for m in mapping}
        assert types == {"email", "phone", "ip_address"}

    def test_code_context_redacted(self, pseudonymizer, detector):
        text = "email = 'max@example.com'"
        matches = detector.scan(text)
        sanitized, mapping = pseudonymizer.replace(
            text, matches, code_context=True
        )
        assert "[REDACTED:email]" in sanitized
        assert "TOKEN_" not in sanitized

    def test_no_matches_returns_original(self, pseudonymizer):
        text = "No PII here."
        sanitized, mapping = pseudonymizer.replace(text, [])
        assert sanitized == text
        assert mapping == []

    def test_empty_text(self, pseudonymizer):
        sanitized, mapping = pseudonymizer.replace("", [])
        assert sanitized == ""
        assert mapping == []

    def test_mapping_contains_hash(self, pseudonymizer, detector):
        text = "Email max@example.com"
        matches = detector.scan(text)
        _, mapping = pseudonymizer.replace(text, matches)
        assert "original_hash" in mapping[0]
        assert len(mapping[0]["original_hash"]) == 64  # SHA-256 hex

    def test_is_code_context_detection(self, pseudonymizer):
        assert pseudonymizer.is_code_context("def foo(): return 42")
        assert pseudonymizer.is_code_context("import os\nfrom pathlib import Path")
        assert pseudonymizer.is_code_context("class Foo:\n    def bar(self): pass")
        assert not pseudonymizer.is_code_context("Hello, how are you?")
        assert not pseudonymizer.is_code_context("Das Wetter ist schön.")

    def test_token_isolation_across_sessions(self, pseudonymizer):
        """Same value in different sessions yields different tokens."""
        t1 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-a")
        t2 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-b")
        assert t1 != t2

    def test_token_stability_within_session(self, pseudonymizer):
        """Same value in the same session yields the same token."""
        t1 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-a")
        t2 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-a")
        assert t1 == t2

    def test_token_hash_format(self, pseudonymizer):
        token = pseudonymizer._make_token("email", "a@b.com", session_id="s")
        assert token.startswith("TOKEN_EMAIL_")
        parts = token.split("_")
        assert len(parts) == 4, f"Unexpected token format: {token}"
        hash_part, counter_part = parts[2], parts[3]
        assert len(hash_part) == Pseudonymizer.HASH_LENGTH
        assert len(counter_part) == Pseudonymizer.COUNTER_DIGITS
        assert all(c in "0123456789abcdef" for c in hash_part)
        assert counter_part.isdigit()

    def test_session_counter_increments_monotonically(self, pseudonymizer):
        t1 = pseudonymizer._make_token("email", "a@b.com", session_id="s")
        t2 = pseudonymizer._make_token("phone", "+123", session_id="s")
        c1 = int(t1.rsplit("_", 1)[1])
        c2 = int(t2.rsplit("_", 1)[1])
        assert c2 == c1 + 1

    def test_session_counter_isolation(self, pseudonymizer):
        pseudonymizer._make_token("email", "a@b.com", session_id="sess-a")
        t_b = pseudonymizer._make_token("email", "b@b.com", session_id="sess-b")
        assert t_b.endswith("_000")

    def test_lru_eviction_respects_max_size(self):
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN", max_cache_size=100)
        for i in range(150):
            p._make_token("email", f"user{i}@x.com", session_id="test")
        assert len(p._token_cache) == 100

    def test_lru_eviction_keeps_recently_used(self):
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN", max_cache_size=3)
        t1 = p._make_token("email", "a@x.com", session_id="s")
        t2 = p._make_token("email", "b@x.com", session_id="s")
        t3 = p._make_token("email", "c@x.com", session_id="s")
        # Access t1 so it becomes MRU.
        assert p._make_token("email", "a@x.com", session_id="s") == t1
        # Insert t4 -> eviction target is t2 (LRU). t4 gets the next counter.
        t4 = p._make_token("email", "d@x.com", session_id="s")
        assert len(p._token_cache) == 3
        assert ("s", "email", "a@x.com") in p._token_cache
        assert ("s", "email", "b@x.com") not in p._token_cache
        assert ("s", "email", "c@x.com") in p._token_cache
        assert ("s", "email", "d@x.com") in p._token_cache
        # t1 is still cached and stable.
        assert p._make_token("email", "a@x.com", session_id="s") == t1
        # t2 was evicted. With the session counter it gets a new suffix when
        # regenerated, but it is still a valid token for the same value.
        t2_regenerated = p._make_token("email", "b@x.com", session_id="s")
        assert t2_regenerated.startswith("TOKEN_EMAIL_")
        assert t2_regenerated != t2
        assert ("s", "email", "b@x.com") in p._token_cache

    def test_clear_cache(self):
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN")
        p._make_token("email", "a@b.com", session_id="s")
        assert len(p._token_cache) == 1
        p.clear_cache()
        assert len(p._token_cache) == 0

    def test_clear_cache_also_clears_session_salts(self):
        """clear_cache() must drop session salts too, not just the token cache.

        Regression test for FIX-3B-v2: previously clear_cache only touched
        _token_cache, leaving per-session salts in memory forever.
        """
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN")
        p._make_token("email", "a@b.com", session_id="s1")
        p._make_token("email", "b@b.com", session_id="s2")
        assert len(p._session_salts) == 2
        assert len(p._session_counters) == 2
        p.clear_cache()
        assert len(p._token_cache) == 0
        assert len(p._session_salts) == 0
        assert len(p._session_counters) == 0

    def test_max_session_salts_minimum_one(self):
        p = Pseudonymizer(
            token_style="deterministic",
            token_prefix="TOKEN",
            max_session_salts=0,
        )
        assert p.max_session_salts == 1

    def test_session_salts_bounded_lru(self):
        """FIX-3B-v2: _session_salts must be bounded by LRU eviction.

        Regression test for HIGH-001: _session_salts was an unbounded dict.
        """
        p = Pseudonymizer(
            token_style="deterministic",
            token_prefix="TOKEN",
            max_session_salts=100,
        )
        for i in range(200):
            p._make_token("email", "x@y.com", session_id=f"session-{i}")
        assert len(p._session_salts) <= 100, (
            f"Session-Salts unbounded: {len(p._session_salts)}"
        )
        assert len(p._session_counters) <= 100, (
            f"Session-Counters unbounded: {len(p._session_counters)}"
        )

    def test_lru_session_eviction_drops_tokens(self):
        """When a session is evicted, its tokens must be removed from the cache.

        Regression test for FIX-3B-v2: cross-cache consistency — orphan tokens
        for an evicted session would waste memory and (more dangerously) keep
        mapping entries the user thought were crypto-shredded.
        """
        p = Pseudonymizer(
            token_style="deterministic",
            token_prefix="TOKEN",
            max_session_salts=2,
        )
        p._make_token("email", "a@x.com", session_id="s1")
        p._make_token("email", "a@x.com", session_id="s2")
        # s1 should be the LRU now
        assert ("s1", "email", "a@x.com") in p._token_cache
        # Adding s3 forces eviction of s1 (LRU)
        p._make_token("email", "a@x.com", session_id="s3")
        assert "s1" not in p._session_salts
        assert "s1" not in p._session_counters
        # And s1's tokens must be gone too
        assert not any(k[0] == "s1" for k in p._token_cache)
        # s2 and s3 still tracked
        assert "s2" in p._session_salts
        assert "s3" in p._session_salts

    def test_lru_session_access_promotes_to_mru(self):
        """Accessing an existing session must mark it as most-recently-used."""
        p = Pseudonymizer(
            token_style="deterministic",
            token_prefix="TOKEN",
            max_session_salts=2,
        )
        p._make_token("email", "a@x.com", session_id="s1")
        p._make_token("email", "a@x.com", session_id="s2")
        # Touch s1 so it becomes MRU. s2 is now the LRU.
        p._make_token("email", "a@x.com", session_id="s1")
        # Adding s3 should evict s2 (the LRU), not s1.
        p._make_token("email", "a@x.com", session_id="s3")
        assert "s1" in p._session_salts
        assert "s2" not in p._session_salts
        assert "s3" in p._session_salts

    def test_100k_inserts_stay_bounded(self):
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN")
        for i in range(100_000):
            p._make_token("email", f"user{i}@x.com", session_id="test")
        assert len(p._token_cache) <= 10_000

    def test_max_cache_size_minimum_one(self):
        p = Pseudonymizer(token_style="deterministic", token_prefix="TOKEN", max_cache_size=0)
        assert p.max_cache_size == 1

    def test_session_salt_independence(self, pseudonymizer):
        """Even a hash collision would not span sessions because salts differ."""
        # Force same hash suffix by construction is impossible; verify different
        # sessions produce different tokens for the same value.
        t1 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-a")
        t2 = pseudonymizer._make_token("email", "a@b.com", session_id="sess-b")
        assert t1 != t2
        assert pseudonymizer._session_salts["sess-a"] != pseudonymizer._session_salts["sess-b"]

    def test_collision_resistance_50k(self, pseudonymizer):
        """50k distinct emails in one session must not collide (counter guarantee)."""
        seen = set()
        for i in range(50_000):
            token = pseudonymizer._make_token("email", f"user{i}@x.com", session_id="long-session")
            assert token not in seen, f"Collision at i={i}: {token}"
            seen.add(token)
        assert len(seen) == 50_000

    def test_collision_resistance_37k(self, pseudonymizer):
        """37k distinct emails in one session must not collide (birthday 50% threshold)."""
        seen = set()
        for i in range(37_000):
            token = pseudonymizer._make_token("email", f"user{i}@x.com", session_id="long-session")
            assert token not in seen, f"Collision at i={i}: {token}"
            seen.add(token)
        assert len(seen) == 37_000

    def test_close_session_clears_salt_and_cache(self, pseudonymizer):
        pseudonymizer._make_token("email", "a@b.com", session_id="s1")
        assert "s1" in pseudonymizer._session_salts
        removed = pseudonymizer.close_session("s1")
        assert removed == 1
        assert "s1" not in pseudonymizer._session_salts
        assert not any(k[0] == "s1" for k in pseudonymizer._token_cache)

    def test_close_session_unknown_returns_zero(self, pseudonymizer):
        assert pseudonymizer.close_session("nonexistent") == 0
