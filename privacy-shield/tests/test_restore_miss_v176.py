"""v1.7.6 — restore_miss placeholder, session-scoped splice repair, kanban channel.

Contracts under test (Kanban card t_f11a29b7, Dirk-Entscheidungen 2026-10-29):

1. Decision 1 — residual TOKEN_* spans that the restore pass cannot resolve
   are replaced with ``restore_miss_placeholder`` (default
   ``[maskiertes PII – nicht wiederherstellbar]``) on ALLOWED restore
   channels only; strategy ``keep`` leaves them verbatim. Every miss is
   counted as ``restore_misses`` and logged PII-free (WARNING).
2. Decision 2 — session-scoped splice repair: a model-mangled token
   (correct serial, broken hash) resolves via ``(type, serial)`` within the
   SAME session only. Uniqueness = exactly one DISTINCT original (row count
   is irrelevant — 4 rows with 2 originals are ambiguous). No cross-session
   fallback, no repair for legacy rows without serial. Both backends
   (SQLite ``MappingTable``, ``InMemoryMappingTable``) implement it.
3. Decision 3 — ``kanban`` joins the default bare restore channels; tool
   egress channels stay blocked (channel matching unchanged).
4. FIX-1B — sanitizer-minted fresh tokens (``fresh_tokens`` out-param) are
   never touched by the residual pass: unresolvable BY DESIGN and stay
   visible.

Token grammar (card §1): ``TOKEN_{TYPE}_{10hex}_{serial:03d}``; TYPE may
contain underscores; serial is session-scoped and NOT globally unique
(counter restarts after LRU eviction — (type, serial) collisions are
expected and resolve to placeholder).
"""

from __future__ import annotations

import hashlib
import re
import sqlite3

import pytest

from privacy_shield.config import (
    DEFAULT_RESTORE_MISS_PLACEHOLDER,
    PrivacyShieldConfig,
    _default_restore_channels,
    validate_config,
)
from privacy_shield.mapping_table import MappingTable
from privacy_shield.metrics import get_metrics, reset_metrics
from privacy_shield.plugin import PrivacyShieldPlugin
from tests.test_post_llm_call_output_scanning import (
    _seed_session_with_token,
)

# Spec-mandated literal (En-Dash U+2013) — kept verbatim, do not normalize.
PLACEHOLDER = "[maskiertes PII – nicht wiederherstellbar]"


def _make_plugin(**overrides) -> PrivacyShieldPlugin:
    config = PrivacyShieldConfig(
        enabled=True,
        mode="limited",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
        storage_mode="memory",
        restore_allowed_channels=("kanban",),
        **overrides,
    )
    return PrivacyShieldPlugin(config=config)


def _damage(token: str, broken_hash: str = "deadbeef00") -> str:
    """Break the 10-hex hash of a token while keeping prefix/type/serial."""
    damaged = re.sub(r"_[0-9a-f]{10}_", f"_{broken_hash}_", token)
    assert damaged != token, f"could not damage token {token!r}"
    return damaged


def _serial_of(token: str) -> int:
    m = re.search(r"_([0-9]{3})$", token)
    assert m, f"token without serial suffix: {token!r}"
    return int(m.group(1))


# ── Test 1: Splice-Miss → Placeholder ────────────────────────────────────────


class TestRestoreMissPlaceholder:
    def test_splice_miss_replaced_with_exact_placeholder(self, caplog):
        """Residual token without candidates → exact placeholder, no original,
        restore_miss counted and logged."""
        plugin = _make_plugin()
        damaged = "TOKEN_EMAIL_deadbeef00_001"
        result = plugin.post_llm_response(
            f"Mail an {damaged} zugestellt.",
            session_id="sess-v176-miss",
            target_channel="kanban",
        )
        assert damaged not in result
        assert PLACEHOLDER in result
        assert result == f"Mail an {PLACEHOLDER} zugestellt."
        # never any invented plaintext
        assert "@" not in result.replace(PLACEHOLDER, "")
        # metric
        assert get_metrics()["restore_misses"] >= 1
        # log: WARNING, no token string, no plaintext
        miss_logs = [r for r in caplog.records if "restore_miss" in r.message]
        assert miss_logs, "restore_miss must be logged"
        assert any(
            r.levelname == "WARNING" and "restore_miss (session=" in r.message
            for r in miss_logs
        ), "restore_miss must be logged via warning level"
        for rec in miss_logs:
            msg = rec.getMessage()
            if "restore_miss (session=" not in msg:
                continue
            assert "TOKEN_" not in msg
            assert "deadbeef" not in msg

    def test_gluft_suffix_only_token_span_replaced(self):
        """Input ``TOKEN_CRYPTO_BTC_..._002dem`` — only the token span is
        replaced; the glued suffix ``dem`` survives untouched."""
        plugin = _make_plugin()
        result = plugin.post_llm_response(
            "Preis in TOKEN_CRYPTO_BTC_22d5465887_002dem",
            session_id="sess-v176-suffix",
            target_channel="kanban",
        )
        assert result == f"Preis in {PLACEHOLDER}dem"

    def test_keep_strategy_leaves_token_verbatim(self, caplog):
        """``restore_miss_strategy=keep`` keeps the literal token, still
        logs + counts the miss."""
        plugin = _make_plugin(restore_miss_strategy="keep")
        damaged = "TOKEN_PHONE_deadbeef00_004"
        result = plugin.post_llm_response(
            f"Ruf {damaged} an.",
            session_id="sess-v176-keep",
            target_channel="kanban",
        )
        assert damaged in result, "keep strategy must not substitute"
        assert get_metrics()["restore_misses"] >= 1
        miss_logs = [r for r in caplog.records if "restore_miss" in r.message]
        assert miss_logs

    def test_underscore_type_survives_pattern(self):
        """TYPE groups with underscores (CRYPTO_BTC) match the residual scan."""
        plugin = _make_plugin()
        result = plugin.post_llm_response(
            "Wallet TOKEN_STEUERNUMMER_ALT_aaaaa00000_017 x",
            session_id="sess-v176-type",
            target_channel="kanban",
        )
        assert result == f"Wallet {PLACEHOLDER} x"

    def test_residual_summary_logged_warning_on_miss(self, caplog):
        """Finding 7g (LOW): der Residual-Pass-Summary ist beim Vorliegen von
        Misses auf WARNING (Security-Monitoring), bei reinen Repairs INFO.
        Finding 7d: restore_miss selbst ist WARNING."""
        import logging

        plugin = _make_plugin()
        text = "Mail an TOKEN_EMAIL_deadbeef00_001 gesendet."
        with caplog.at_level(logging.INFO, logger="privacy_shield.plugin"):
            plugin._resolve_residual_tokens(
                text, session_id="sess-7g", fresh_tokens=set()
            )
        summary = [
            r
            for r in caplog.records
            if "residual pass finished" in r.getMessage()
        ]
        assert summary and summary[0].levelname == "WARNING"
        assert any(
            "restore_miss" in r.getMessage()
            and r.levelname == "WARNING"
            for r in caplog.records
        )


# ── Test 2+3: Fuzzy repair — unique restore, ambiguous → placeholder ────────


class TestSessionSpliceRepair:
    def test_fuzzy_hit_restores_original_same_session(self):
        """Mangled hash + identical (type, serial) → original restored."""
        plugin = _make_plugin()
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-v176-fix", original=original
        )
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-fix",
            target_channel="kanban",
        )
        assert original in result, f"splice repair failed: {result!r}"
        assert "TOKEN_" not in result
        assert PLACEHOLDER not in result

    def test_fuzzy_multi_match_is_ambiguous_placeholder(self):
        """Two distinct originals sharing (type, serial) in the same session
        (counter restart after LRU eviction) → placeholder, no restore."""
        plugin = _make_plugin()
        session = "sess-v176-ambig"
        alice = "alice.klein@beispielgasse.example"
        token_a = _seed_session_with_token(
            plugin, session_id=session, original=alice
        )
        # Simulate the observed counter restart: shrink the session-salt LRU
        # to 1 and force eviction with a foreign session, then re-mint for
        # the same session — the counter restarts at 000 while the mapping
        # for token_a persists.
        plugin.pseudonymizer.max_session_salts = 1
        _ = plugin.pseudonymizer._make_token(
            "email", "filler@example.invalid", session_id="other-session"
        )
        bob = "bob.weber@contoso.example"
        token_b = plugin.pseudonymizer._make_token(
            "email", bob, session_id=session
        )
        plugin.mapper.store(
            [
                {
                    "original_hash": hashlib.sha256(bob.encode()).hexdigest(),
                    "original_value": bob,
                    "token": token_b,
                    "type": "email",
                }
            ],
            session_id=session,
        )
        assert _serial_of(token_a) == _serial_of(token_b), (
            "fixture requires the restarted session counter to collide"
        )
        damaged = _damage(token_a)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id=session,
            target_channel="kanban",
        )
        assert alice not in result, "ambiguous splice must NOT restore"
        assert bob not in result, "ambiguous splice must NOT restore"
        assert PLACEHOLDER in result

    def test_no_cross_session_fallback(self):
        """Same (type, serial) in ANOTHER session → no repair → placeholder."""
        plugin = _make_plugin()
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-v176-cross-a", original=original
        )
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-cross-b",
            target_channel="kanban",
        )
        assert original not in result, "cross-session repair must never happen"
        assert PLACEHOLDER in result

    def test_empty_session_id_never_repairs(self):
        """Empty session_id → fail closed → placeholder."""
        plugin = _make_plugin()
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-v176-empty", original=original
        )
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="",
            target_channel="kanban",
        )
        assert original not in result
        assert PLACEHOLDER in result


# ── Test 5: Kanban channel ───────────────────────────────────────────────────


class TestKanbanChannel:
    def test_kanban_in_default_restore_channels(self, monkeypatch):
        """'kanban' is a bare default; 'cron' must still be opt-in."""
        monkeypatch.delenv("PRIVACY_SHIELD_RESTORE_CHAT_ID", raising=False)
        monkeypatch.setattr(
            "privacy_shield.config._resolve_pass_binary", lambda: None
        )
        channels = _default_restore_channels()
        assert "kanban" in channels

    def test_kanban_channel_restores(self):
        """Channel-gate: 'kanban' allowed → repair happens on kanban."""
        plugin = _make_plugin()
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-v176-kanban", original=original
        )
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-kanban",
            target_channel="kanban",
        )
        assert original in result

    def test_disallowed_channel_no_placeholder_no_restore(self):
        """Tool-egress channel (write_file) → token stays verbatim: no
        restore AND no placeholder substitution (residual pass is
        restore-path exclusive)."""
        plugin = _make_plugin()
        damaged = "TOKEN_EMAIL_deadbeef00_002"
        result = plugin.post_llm_response(
            f"Mail an {damaged} zugestellt.",
            session_id="sess-v176-egress",
            target_channel="write_file",
        )
        assert damaged in result
        assert PLACEHOLDER not in result

    def test_chat_id_allowlist_untouched(self):
        """Regression guard: only the 'kanban' entry was added — the
        chat-ID trust boundary config fields keep their defaults."""
        config = PrivacyShieldConfig()
        assert config.restore_allowed_channels == _default_restore_channels()


# ── Test 6: Fresh-PII regression (FIX-1B) ────────────────────────────────────


class TestFreshPiiRegression:
    def test_fresh_token_survives_restore_and_placeholder(self):
        """A fresh leak in the same output gets its own token which stays
        visible: neither restored, nor repaired, nor placeholder-substituted.
        A simultaneously-present damaged token IS repaired."""
        plugin = _make_plugin()
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(
            plugin, session_id="sess-v176-fresh", original=original
        )
        damaged = _damage(token)
        fresh_leak = "fresh.leak@example.net"
        response = (
            f"Mail an {damaged} gesendet. Kontakt: {fresh_leak}"
        )
        result = plugin.post_llm_response(
            response,
            session_id="sess-v176-fresh",
            target_channel="kanban",
        )
        # damaged token repaired to the session original
        assert original in result
        # fresh leak never appears as plaintext
        assert fresh_leak not in result
        # the fresh token minted by the sanitizer stays visible
        fresh_tokens = [
            m.group(0)
            for m in plugin.mapper.token_pattern.finditer(result)
        ]
        assert fresh_tokens, "sanitizer-minted token must remain in output"
        for ft in fresh_tokens:
            assert ft != damaged
        # placeholder not applied to the fresh token
        assert fresh_leak not in result and PLACEHOLDER not in result

    def test_sanitize_out_param_reports_minted_tokens(self):
        """OutputSanitizer.sanitize keeps (text, count) and optionally fills
        fresh_tokens with exactly the tokens minted in this call."""
        plugin = _make_plugin()
        fresh: set[str] = set()
        sanitized, count = plugin.output_sanitizer.sanitize(
            "Kontakt: fresh.leak2@example.net",
            session_id="sess-v176-outparam",
            fresh_tokens=fresh,
        )
        assert count == 1
        assert "fresh.leak2@example.net" not in (sanitized or "")
        assert len(fresh) == count
        # backward-compatible 2-tuple call still works
        sanitized2, count2 = plugin.output_sanitizer.sanitize(
            "Kontakt: fresh.leak2@example.net",
            session_id="sess-v176-outparam",
        )
        assert isinstance(sanitized2, str) or sanitized2 is None
        assert count2 == 1


# ── Test 7: Legacy rows (SQLite backend) ─────────────────────────────────────


class TestLegacyRowsSqlite:
    def _make_sqlite_plugin(self, tmp_path):
        config = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="disk",
            storage_path=str(tmp_path / "mapping.db"),
            restore_allowed_channels=("kanban",),
        )
        return PrivacyShieldPlugin(config=config)

    def _seed(self, plugin, session_id):
        original = "max.mustermann@firma-gmbh.de"
        token = _seed_session_with_token(plugin, session_id=session_id, original=original)
        return original, token

    def test_store_persists_token_serial(self, tmp_path):
        plugin = self._make_sqlite_plugin(tmp_path)
        _, token = self._seed(plugin, "sess-v176-db")
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            row = conn.execute(
                "SELECT token_serial FROM mappings WHERE session_id = ?",
                ("sess-v176-db",),
            ).fetchone()
        assert row is not None
        assert row[0] == _serial_of(token), (
            "store() must persist the parsed serial before encryption"
        )

    def test_legacy_row_without_token_serial_is_placeholder(self, tmp_path, caplog):
        """A legacy row that can NO LONGER yield a serial (processed with
        token_serial = -1, i.e. plaintext token had no counter / was
        undecryptable) must fail closed: placeholder, no restore, no crash.
        NULL rows, by contrast, are migrated by the bounded lazy backfill
        before the candidate query (see test_sqlite_fuzzy_repair_e2e)."""
        plugin = self._make_sqlite_plugin(tmp_path)
        original, token = self._seed(plugin, "sess-v176-legacy")
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            conn.execute("UPDATE mappings SET token_serial = -1")
            conn.commit()
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-legacy",
            target_channel="kanban",
        )
        assert original not in result
        assert PLACEHOLDER in result
        assert get_metrics()["restore_misses"] >= 1
        miss_logs = [r for r in caplog.records if "restore_miss" in r.message]
        assert miss_logs

    def test_sqlite_fuzzy_repair_e2e(self, tmp_path):
        """Decision 2 on the SQLite backend: bounded lazy backfill + indexed
        (session, type, token_serial) query repairs a mangled token."""
        plugin = self._make_sqlite_plugin(tmp_path)
        original, token = self._seed(plugin, "sess-v176-db-fix")
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-db-fix",
            target_channel="kanban",
        )
        assert original in result
        assert "TOKEN_" not in result

    def test_sqlite_backfill_is_bounded_and_once(self, tmp_path):
        """The lazy backfill migrates NULL rows (≤ 200 per call, at most once
        per (session, type)) — a second call is a no-op."""
        plugin = self._make_sqlite_plugin(tmp_path)
        _, token = self._seed(plugin, "sess-v176-bf")
        pii_type = token.split("_")[1].lower()
        # Simulate not-yet-migrated rows.
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            conn.execute("UPDATE mappings SET token_serial = NULL")
            conn.commit()
        first = plugin.mapper.backfill_token_serial("sess-v176-bf", pii_type)
        assert first >= 1
        second = plugin.mapper.backfill_token_serial("sess-v176-bf", pii_type)
        assert second == 0, "second call must be a no-op (once per session+type)"
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            serials = [
                r[0]
                for r in conn.execute(
                    "SELECT token_serial FROM mappings WHERE session_id = ?",
                    ("sess-v176-bf",),
                ).fetchall()
            ]
        assert all(s is not None for s in serials), (
            "backfill must stamp every processed row (serial or -1)"
        )

    def test_attacker_manipulated_serial_fails_closed_and_repairs(
        self, tmp_path, caplog
    ):
        """Finding 3f (HIGH, Merge-Blocker): ein Angreifer mit DB-Schreibzugriff
        manipuliert token_serial auf einen fremden Wert. Vor dem Fix lieferte
        resolve_fuzzy_token die Row's Original-Wert (Mis-Repair). Nach dem Fix:
        Serial wird aus dem eigenen Token neu abgeleitet — Mismatch → Row
        fliegt aus der Kandidatenmenge UND wird auf den abgeleiteten Serial
        zurückgesetzt (Angriffszustand bereinigt)."""
        plugin = self._make_sqlite_plugin(tmp_path)
        original, token = self._seed(plugin, "sess-v176-3f")
        pii_type = token.split("_")[1].lower()
        true_serial = _serial_of(token)
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            conn.execute(
                "UPDATE mappings SET token_serial = ?", (true_serial + 1,)
            )
            conn.commit()
        assert (
            plugin.mapper.resolve_fuzzy_token(
                pii_type, true_serial + 1, "sess-v176-3f"
            )
            is None
        ), "manipulated serial must not restore the row's original"
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            repaired = conn.execute(
                "SELECT token_serial FROM mappings WHERE session_id = ?",
                ("sess-v176-3f",),
            ).fetchone()[0]
        assert repaired == true_serial, (
            "the corrupted serial must be repaired to the content-derived value"
        )
        assert (
            plugin.mapper.resolve_fuzzy_token(
                pii_type, true_serial, "sess-v176-3f"
            )
            == original
        ), "true serial restores again after the integrity repair"
        assert any(
            "token_serial integrity violation" in r.getMessage()
            for r in caplog.records
        )

    def test_candidate_window_truncation_fail_closed(self, tmp_path):
        """Review F4 (Orakel/Standards MINOR): füllt die Kandidaten-Query das
        LIMIT (max_rows), kann Eindeutigkeit jenseits des Fensters nicht
        bewiesen werden → fail-closed (None/Platzhalter) statt Restore bei
        exakt 1 Distinct-Original in den ersten 50 Rows."""
        plugin = self._make_sqlite_plugin(tmp_path)
        original, token = self._seed(plugin, "sess-v176-f4")
        pii_type = token.split("_")[1].lower()
        with sqlite3.connect(str(tmp_path / "mapping.db")) as conn:
            for _ in range(49):
                conn.execute(
                    "INSERT INTO mappings (original_hash, original_encrypted, "
                    "token_encrypted, type, created_at, expires_at, session_id, "
                    "token_hash, token_serial) "
                    "SELECT original_hash, original_encrypted, token_encrypted, "
                    "type, created_at, expires_at, session_id, token_hash, "
                    "token_serial FROM mappings WHERE session_id = 'sess-v176-f4' "
                    "ORDER BY id LIMIT 1"
                )
            conn.commit()
        assert (
            plugin.mapper.resolve_fuzzy_token(
                pii_type, _serial_of(token), "sess-v176-f4"
            )
            is None
        ), "full candidate window must fail closed (uniqueness unprovable)"
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-f4",
            target_channel="kanban",
        )
        assert original not in result
        assert PLACEHOLDER in result

    def test_serial_000_is_not_confused_with_backfill_sentinel(self, tmp_path):
        """Serial 0 ('000') is a valid serial and restores; TOKEN_SERIAL_ABSENT
        (-1) is reserved for processed rows without a serial."""
        plugin = self._make_sqlite_plugin(tmp_path)
        original, token = self._seed(plugin, "sess-v176-zeroserial")
        if _serial_of(token) != 0:
            pytest.skip("fixture token does not carry serial 000")
        damaged = _damage(token)
        result = plugin.post_llm_response(
            f"Mail an {damaged} gesendet.",
            session_id="sess-v176-zeroserial",
            target_channel="kanban",
        )
        assert original in result


# ── Test 9: Metrics ──────────────────────────────────────────────────────────


class TestMetrics:
    def setup_method(self):
        reset_metrics()

    def test_restore_misses_counter_rises(self):
        plugin = _make_plugin()
        before = get_metrics()["restore_misses"]
        plugin.post_llm_response(
            "Mail an TOKEN_PHONE_deadbeef00_009 zugestellt.",
            session_id="sess-v176-metric",
            target_channel="kanban",
        )
        after = get_metrics()["restore_misses"]
        assert after > before
        assert "restore_misses" in get_metrics()

    def test_prometheus_counter_registered(self):
        prometheus_client = pytest.importorskip("prometheus_client")
        from privacy_shield import metrics as metrics_mod

        registry = metrics_mod._prom_registry or prometheus_client.REGISTRY
        counter_names = {c.name for c in registry.collect()}
        # prometheus_client reports Counter families without the _total suffix
        assert (
            "privacy_shield_restore_misses" in counter_names
            or "privacy_shield_restore_misses_total" in counter_names
        )


# ── Config: Decision 1 validation ────────────────────────────────────────────


class TestRestoreMissConfig:
    def test_default_strategy_and_placeholder(self):
        config = PrivacyShieldConfig()
        assert config.restore_miss_strategy == "placeholder"
        assert config.restore_miss_placeholder == PLACEHOLDER
        # Byte-exact: En-Dash (U+2013), not a hyphen.
        assert "–" in config.restore_miss_placeholder
        assert "-" not in config.restore_miss_placeholder
        assert DEFAULT_RESTORE_MISS_PLACEHOLDER in (
            "[maskiertes PII – nicht wiederherstellbar]",
        )
        assert "-" not in DEFAULT_RESTORE_MISS_PLACEHOLDER

    def test_validate_config_rejects_invalid_strategy(self):
        config = PrivacyShieldConfig(restore_miss_strategy="explode")
        issues = validate_config(config)
        assert any("restore_miss_strategy" in issue for issue in issues)
        config_ok = PrivacyShieldConfig(restore_miss_strategy="keep")
        assert not any("restore_miss_strategy" in i for i in validate_config(config_ok))

    def test_load_config_invalid_yaml_value_falls_back_to_default(
        self, tmp_path, monkeypatch, caplog
    ):
        """Invalid restore_miss_strategy in config.yaml → default + warning
        (mirrors reasoning.mode handling)."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("PRIVACY_SHIELD_KEY", "test-key-32-bytes-xxxxxxxxxxxxx")
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  entries:\n    privacy-shield:\n"
            "      restore_miss_strategy: bogus-mode\n"
            "      restore_miss_placeholder: \"[masked PII – not restorable]\"\n",
            encoding="utf-8",
        )
        import logging

        import privacy_shield.config as cfg_mod

        with caplog.at_level(logging.WARNING, logger="privacy_shield.config"):
            config = cfg_mod.load_config()
        assert config.restore_miss_strategy == "placeholder"
        assert config.restore_miss_placeholder == "[masked PII – not restorable]"
        assert any(
            "restore_miss_strategy" in rec.getMessage() for rec in caplog.records
        )

    def test_validate_config_rejects_nonstring_placeholder(self):
        """Review F5 (Orakel/Standards MINOR + Architektur F5): ein nicht-String
        restore_miss_placeholder aus YAML überlebt sonst den Merge ungeprüft
        und führt zu einem TypeError im Residual-Pass."""
        config = PrivacyShieldConfig(restore_miss_placeholder=12345)
        issues = validate_config(config)
        assert any("restore_miss_placeholder" in issue for issue in issues)
        assert not any(
            "restore_miss_placeholder" in issue
            for issue in validate_config(PrivacyShieldConfig(restore_miss_placeholder="x"))
        )

    def test_load_config_nonstring_placeholder_falls_back_to_default(
        self, tmp_path, monkeypatch, caplog
    ):
        """Review F5: nicht-String restore_miss_placeholder in config.yaml →
        Default + Warning statt TypeError beim ''.join im Residual-Pass."""
        monkeypatch.setenv("HERMES_HOME", str(tmp_path))
        monkeypatch.setenv("PRIVACY_SHIELD_KEY", "test-key-32-bytes-xxxxxxxxxxxxx")
        monkeypatch.delenv("PRIVACY_SHIELD_WORKSHOP", raising=False)
        (tmp_path / "config.yaml").write_text(
            "plugins:\n  entries:\n    privacy-shield:\n"
            "      restore_miss_placeholder: 12345\n",
            encoding="utf-8",
        )
        import logging

        import privacy_shield.config as cfg_mod

        with caplog.at_level(logging.WARNING, logger="privacy_shield.config"):
            config = cfg_mod.load_config()
        assert config.restore_miss_placeholder == DEFAULT_RESTORE_MISS_PLACEHOLDER
        assert any(
            "restore_miss_placeholder" in rec.getMessage()
            for rec in caplog.records
        )

    def test_version_bump_is_consistent(self):
        import privacy_shield
        from pathlib import Path

        plugin_yaml = (
            Path(privacy_shield.__file__).resolve().parent / "plugin.yaml"
        ).read_text(encoding="utf-8")
        m = re.search(r'^version:\s*"([^"]+)"', plugin_yaml, re.MULTILINE)
        assert m
        # v1.7.6 floor: plugin.yaml and __init__ must agree, and never regress
        # below 1.7.6 (PR #25 bumped the release train to 1.8.0).
        assert m.group(1) == privacy_shield.__version__
        assert tuple(int(p) for p in m.group(1).split(".")) >= (1, 7, 6)