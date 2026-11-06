"""SQLite Mapping Table with AES-256-GCM encryption and TTL-based auto-expiry.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 5.3

Schema: mappings(id, original_hash, original_encrypted, token_encrypted, token_hash, type, created_at, expires_at, session_id)
- Original values are SHA-256 hashed, NOT stored in plaintext
- original_encrypted: AES-256-GCM encrypted original value (for round-trip demasking)
- Token column is AES-256-GCM encrypted
- token_hash: SHA-256 of the plaintext token for O(log n) reverse lookup (PERF-4)
- expires_at: Unix timestamp when this mapping auto-expires (TTL)
- Key loading: pass wrapper → env → auto-generate

DSGVO Art. 4 Nr. 5: Mapping table is "getrennte Aufbewahrung" (separate storage)
from the pseudonymized data.

Google-Empfehlung (TTL): "Löschfristen für IDs: Setzen Sie eine strikte
Time-to-Live (TTL) für diese Zuordnungen. Nach dem Chat-Ende müssen die IDs
sofort gelöscht werden."
"""

from __future__ import annotations

import gc
import hashlib
import logging
import os
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _compile_token_pattern(
    token_prefix: str,
    hash_length: int,
    counter_digits: int,
) -> "re.Pattern[str]":
    """Build the regex used by MappingTable.restore_text.

    FIX-4A (NEU-001): This used to be hardcoded to ``r'\\bTOKEN_(...)...'`` in
    both ``MappingTable.restore_text`` and ``InMemoryMappingTable.restore_text``.
    When the operator changed the configured ``token_prefix`` (e.g. to ``PS``)
    the Pseudonymizer emitted ``PS_EMAIL_...`` tokens, but the restore regex
    only matched ``TOKEN_EMAIL_...`` — so restoration silently failed and PII
    leaked through tokens into the response.

    The pattern now derives from the configured ``token_prefix``, ``hash_length``
    and ``counter_digits``. The counter suffix is intentionally optional
    (group 3 may be ``None``) so legacy tokens emitted before FIX-3C still
    match.
    """
    if not token_prefix or not token_prefix.isidentifier():
        raise ValueError(
            f"Privacy-Shield: invalid token_prefix {token_prefix!r} "
            "(must be a non-empty Python identifier)"
        )
    if hash_length < 4 or hash_length > 64:
        raise ValueError(
            f"Privacy-Shield: hash_length must be in [4, 64], got {hash_length}"
        )
    if counter_digits < 0 or counter_digits > 6:
        raise ValueError(
            f"Privacy-Shield: counter_digits must be in [0, 6], got {counter_digits}"
        )
    # FIX-RESTORE-BOUNDARY: the old pattern used \b at both ends. That failed
    # when a token was embedded inside a larger compound string, most commonly
    # after an underscore (e.g. FAKE_API_KEY_TOKEN_PHONE_..._001abcdef) or when
    # a detector match left a trailing digit (TOKEN_PHONE_..._0002).
    #
    # PS-MASK-006: The negative lookbehind (?<![A-Za-z0-9]) broke detection when
    # a token was immediately preceded by alphanumerics without a delimiter
    # (e.g. abcTOKEN_PHONE_...). The token prefix (TOKEN_/PS_) is globally
    # unique in the output stream, so we drop the lookbehind entirely and rely
    # on the prefix + TYPE + hash structure to disambiguate. The optional
    # counter group consumes exactly counter_digits digits; the legacy
    # no-counter branch asserts that no counter-like suffix follows.
    counter_group = rf"(?:_([0-9]{{{counter_digits}}}))"
    legacy_tail = rf"(?![0-9_])"
    pattern = (
        rf"{re.escape(token_prefix)}_([A-Z_]+)_"
        rf"([0-9a-f]{{{hash_length}}})"
        rf"(?:{counter_group}|{legacy_tail})"
    )
    return re.compile(pattern)


def _parse_token_serial(token: str, pattern: "re.Pattern[str]") -> int | None:
    """Extract the session serial from a plaintext token string.

    v1.7.6 (Decision 2): tokens have the shape
    ``{PREFIX}_{TYPE}_{HASH}_{SERIAL:03d}`` (e.g. ``TOKEN_BIC_bf0eb3800c_001``).
    ``TYPE`` may contain underscores and the serial is a session-scoped
    counter (000-999) that is NOT globally unique — the counter restarts on
    pseudonymizer LRU eviction, so ``(type, serial)`` collisions inside one
    session are expected (10 colliding pairs observed in a 92-row session).

    Returns the serial as ``int``, or ``None`` when the token does not match
    the pattern or carries the legacy no-counter shape (group 3 absent).
    Legacy tokens never qualify for splice repair (fail-closed).
    """
    if not token:
        return None
    match = pattern.fullmatch(token)
    if match is None:
        return None
    serial = match.group(3)
    if serial is None or not serial.isdigit():
        return None
    return int(serial)


# sentinel persisted into ``token_serial`` for rows that were processed by
# the backfill but whose plaintext token carries no serial (legacy shape).
# NULL still means "not yet processed".
TOKEN_SERIAL_ABSENT = -1


class MappingTable:
    """SQLite-backed mapping table with AES-256-GCM encryption.

    The token column is encrypted at rest. Original values are encrypted
    in original_encrypted for round-trip demasking. This implements
    "getrennte Aufbewahrung" per DSGVO.
    """

    # OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
    PBKDF2_ITERATIONS: int = 600_000
    # AES-256-GCM cryptographic sizes (bytes)
    AES_KEY_LENGTH: int = 32
    SALT_LENGTH: int = 16
    NONCE_LENGTH: int = 12
    AUTH_TAG_LENGTH: int = 16
    # Minimum encrypted payload length: salt + nonce + tag
    MIN_CIPHERTEXT_BYTES: int = SALT_LENGTH + NONCE_LENGTH + AUTH_TAG_LENGTH
    # Default TTL for stored mappings (1 hour)
    TTL_DEFAULT_SECONDS: int = 3600
    # Filesystem permission hardening (BUTLER-PS-6)
    DB_FILE_MODE: int = 0o600
    DB_DIR_MODE: int = 0o700

    def __init__(
        self,
        storage_path: str = "~/.hermes/privacy/mapping.db",
        encryption_key: str = "",
        kdf_iterations: int = PBKDF2_ITERATIONS,
        token_prefix: str = "TOKEN",
        hash_length: int = 10,
        counter_digits: int = 3,
    ):
        if not encryption_key:
            raise ValueError(
                "Privacy-Shield: MappingTable requires a non-empty encryption_key. "
                "Run 'privacy-shield setup' or set PRIVACY_SHIELD_KEY."
            )
        self._storage_path = Path(storage_path).expanduser()
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption_key = encryption_key
        self._lock = threading.Lock()
        self._kdf_iterations = kdf_iterations
        # Pre-derive raw key bytes
        self._raw_key_bytes = encryption_key.encode()
        # FIX-4A (NEU-001): Token-pattern parameters must match the
        # Pseudonymizer's emit format. Keep these in lock-step with
        # Pseudonymizer.HASH_LENGTH / COUNTER_DIGITS. Counter suffix is
        # optional in the regex so legacy tokens (no counter) still match.
        self.token_prefix = token_prefix
        self.hash_length = hash_length
        self.counter_digits = counter_digits
        self.token_pattern = _compile_token_pattern(
            token_prefix=token_prefix,
            hash_length=hash_length,
            counter_digits=counter_digits,
        )
        # v1.7.6 (Decision 2): (session_id, type) pairs whose token_serial
        # backfill already ran — the lazy backfill may run at most ONCE per
        # pair to keep the PBKDF2 cost bounded (600k iterations ≈ 43 ms/row).
        self._serial_backfill_done: set[tuple[str, str]] = set()
        self._init_db()

    def _token_hash(self, token: str) -> str:
        """Deterministic SHA-256 hash of a plaintext token (PERF-4)."""
        return hashlib.sha256(token.encode()).hexdigest()

    def _backfill_token_hash(self) -> int:
        """Backfill empty token_hash values for legacy rows.

        PERF-4: rows created before this migration carry an empty
        token_hash. This helper decrypts each such token once, writes the
        hash back to the column, and returns the number of rows updated.
        It is safe to run concurrently with normal operations because
        the UPDATE is scoped to rows where token_hash is empty and the
        lock serializes writers.
        """
        updated = 0
        with self._lock:
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT id, token_encrypted FROM mappings "
                    "WHERE token_hash = '' OR token_hash IS NULL"
                ).fetchall()
                for row_id, encrypted_token in rows:
                    try:
                        token = self._decrypt(encrypted_token)
                    except Exception:
                        continue
                    conn.execute(
                        "UPDATE mappings SET token_hash = ? WHERE id = ?",
                        (self._token_hash(token), row_id),
                    )
                    updated += 1
                if updated:
                    conn.commit()
                    logger.info("backfill_token_hash: updated %d rows", updated)
            finally:
                conn.close()
        return updated

    # ── Database ────────────────────────────────────────────────────────

    def _open_conn(self) -> sqlite3.Connection:
        """Open the SQLite database and tighten file perms before each call.

        BUTLER-PS-6 / FIX-PS-R5-OPS: chmod 0o600 used to run only at
        initialisation. Backup-restore, manual ``cp`` / ``rsync`` and
        shared-hosting migration can land the file on disk with looser
        permissions; re-asserting the chmod on every open guarantees
        the file converges back to the documented hardening within
        one write — even if a previous run left it world-readable.
        """
        # Tighten the active DB file *before* sqlite opens it so we
        # never even briefly expose a permissive-mode database to a
        # concurrent reader.
        try:
            if self._storage_path.exists():
                os.chmod(str(self._storage_path), self.DB_FILE_MODE)
            if self._storage_path.parent.exists():
                os.chmod(str(self._storage_path.parent), self.DB_DIR_MODE)
        except OSError:
            # Best-effort; on restricted filesystems the chmod may
            # fail and that is non-fatal for the DB itself.
            pass
        return sqlite3.connect(str(self._storage_path))

    def _init_db(self) -> None:
        """Initialize SQLite database and schema.

        PERF-4: migrations are applied idempotently via ``ALTER TABLE ...
        ADD COLUMN`` so existing databases gain the ``token_hash`` index
        column without rebuilding the table. The new column is populated
        lazily on reads for legacy rows that lack it, preserving backward
        compatibility.
        """
        with self._lock:
            conn = self._open_conn()
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS mappings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_hash TEXT NOT NULL,
                        original_encrypted TEXT NOT NULL DEFAULT '',
                        token_encrypted TEXT NOT NULL,
                        type TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL DEFAULT 0,
                        session_id TEXT NOT NULL DEFAULT ''
                    )
                """)
                # Add expires_at column if upgrading from pre-TTL schema
                try:
                    conn.execute("ALTER TABLE mappings ADD COLUMN expires_at REAL NOT NULL DEFAULT 0")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                # Add original_encrypted column if upgrading from pre-demasking schema
                try:
                    conn.execute("ALTER TABLE mappings ADD COLUMN original_encrypted TEXT NOT NULL DEFAULT ''")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                # PERF-4: add token_hash column for O(log n) reverse lookups
                try:
                    conn.execute("ALTER TABLE mappings ADD COLUMN token_hash TEXT NOT NULL DEFAULT ''")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                # v1.7.6 (Decision 2): session-scoped splice repair needs the
                # serial without decrypting. token_serial is NULL for rows not
                # yet processed by the (bounded, lazy) backfill and
                # TOKEN_SERIAL_ABSENT (-1) for processed rows whose plaintext
                # token has no serial (legacy no-counter shape).
                try:
                    conn.execute("ALTER TABLE mappings ADD COLUMN token_serial INTEGER")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mappings_hash
                    ON mappings(original_hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mappings_session
                    ON mappings(session_id)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mappings_expires
                    ON mappings(expires_at)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mappings_token_hash
                    ON mappings(token_hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_mappings_session_type_serial
                    ON mappings(session_id, type, token_serial)
                """)
                conn.commit()
            finally:
                conn.close()

        # Restrict file permissions: DB file 0o600, parent dir 0o700.
        # BUTLER-PS-6: redundant with ``_open_conn`` (which now re-asserts
        # on every open) but kept here so the very first DB file ships
        # with the right mode even before any subsequent open fires.
        try:
            os.chmod(str(self._storage_path), self.DB_FILE_MODE)
            os.chmod(str(self._storage_path.parent), self.DB_DIR_MODE)
        except OSError:
            pass  # Best-effort; non-fatal on restricted filesystems

    # ── Encryption ──────────────────────────────────────────────────────

    def _derive_key(self, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256 key derivation (OWASP 2023: 600k iterations).

        Derives a 32-byte AES-256 key from the raw encryption key + salt.
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.AES_KEY_LENGTH,
            salt=salt,
            iterations=self._kdf_iterations,
        )
        return kdf.derive(self._raw_key_bytes)

    def _encrypt(self, plaintext: str) -> str:
        """AES-256-GCM encrypt a string with PBKDF2 key derivation.

        Format: base64(salt[SALT_LENGTH] + nonce[NONCE_LENGTH] + ciphertext + tag[AUTH_TAG_LENGTH])
        Salt is stored in the ciphertext so decryption can re-derive the key.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64, os as _os

        salt = _os.urandom(self.SALT_LENGTH)
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        nonce = _os.urandom(self.NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        # Prepend salt + nonce to ciphertext for decryption
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode()

    def _decrypt(self, encrypted: str) -> str:
        """AES-256-GCM decrypt a string.

        Expects the PBKDF2 format (salt || nonce || ciphertext) produced by
        ``_encrypt``.  The legacy SHA-256-only fallback has been removed because
        it reused a single key/nonce style and could silently decrypt data
        with a different key.  On failure a clear ValueError is raised.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64

        combined = base64.b64decode(encrypted)

        if len(combined) < self.MIN_CIPHERTEXT_BYTES:
            raise ValueError(f"Encrypted value too short: {len(combined)} bytes")

        salt = combined[:self.SALT_LENGTH]
        nonce = combined[self.SALT_LENGTH:self.SALT_LENGTH + self.NONCE_LENGTH]
        ciphertext = combined[self.SALT_LENGTH + self.NONCE_LENGTH:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()

    # ── Public API ───────────────────────────────────────────────────────

    def store(
        self,
        mappings: list[dict[str, Any]],
        session_id: str = "",
        ttl_seconds: int = TTL_DEFAULT_SECONDS,
    ) -> None:
        """Store PII→token mappings with TTL-based auto-expiry.

        Args:
            mappings: [{"original_hash": sha256, "original_value": "d@x.com",
                        "token": "EMAIL_001", "type": "email"}, ...]
            session_id: Current session identifier
            ttl_seconds: Time-to-live in seconds (default 3600 = 1 hour).
                        0 = already expired (prune_expired will remove immediately).

        PERF-4: stores a SHA-256 hash of the plaintext token in
        ``token_hash`` so reverse lookups can use the SQLite index instead
        of decrypting every row.
        """
        if not mappings:
            return

        now = time.time()
        expires_at = now + ttl_seconds if ttl_seconds > 0 else now
        with self._lock:
            conn = self._open_conn()
            try:
                for m in mappings:
                    token = m["token"]
                    encrypted_token = self._encrypt(token)
                    encrypted_original = self._encrypt(m.get("original_value", ""))
                    token_hash = self._token_hash(token)
                    # v1.7.6 (Decision 2): persist the serial BEFORE encryption
                    # so the splice-repair candidate query never has to decrypt
                    # the token column.
                    token_serial = _parse_token_serial(token, self.token_pattern)
                    conn.execute(
                        """INSERT INTO mappings
                           (original_hash, original_encrypted, token_encrypted, token_hash, type,
                            created_at, expires_at, session_id, token_serial)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            m["original_hash"],
                            encrypted_original,
                            encrypted_token,
                            token_hash,
                            m["type"],
                            now,
                            expires_at,
                            session_id,
                            token_serial,
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def lookup_by_hash(self, original_hash: str) -> str | None:
        """Look up token by original value hash.

        Returns decrypted token or None.
        """
        with self._lock:
            conn = self._open_conn()
            try:
                row = conn.execute(
                    "SELECT token_encrypted FROM mappings WHERE original_hash = ? "
                    "ORDER BY id DESC LIMIT 1",
                    (original_hash,),
                ).fetchone()
                if row:
                    return self._decrypt(row[0])
                return None
            finally:
                conn.close()

    def lookup_by_token(self, token: str) -> str | None:
        """Look up original hash by token (reverse lookup).

        Returns original_hash or None.

        PERF-4: uses the indexed ``token_hash`` column instead of a full
        table scan. Legacy rows with an empty token_hash are still matched
        by decrypting candidate tokens as a fallback.
        """
        if not token:
            return None
        with self._lock:
            conn = self._open_conn()
            try:
                # Fast path: exact hash match via the new index.
                row = conn.execute(
                    "SELECT original_hash, token_encrypted FROM mappings "
                    "WHERE token_hash = ? ORDER BY id DESC LIMIT 1",
                    (self._token_hash(token),),
                ).fetchone()
                if row:
                    original_hash, encrypted_token = row
                    try:
                        decrypted = self._decrypt(encrypted_token)
                        if decrypted == token:
                            return str(original_hash)
                    except Exception:
                        pass

                # Fallback: legacy rows without token_hash still need
                # verification in Python because the token column is encrypted.
                rows = conn.execute(
                    "SELECT original_hash, token_encrypted FROM mappings "
                    "WHERE token_hash = '' OR token_hash IS NULL"
                ).fetchall()
                for original_hash, encrypted_token in rows:
                    try:
                        decrypted = self._decrypt(encrypted_token)
                        if decrypted == token:
                            return str(original_hash)
                    except Exception:
                        continue
                return None
            finally:
                conn.close()

    def lookup_original_by_token(
        self, token: str, session_id: str = ""
    ) -> str | None:
        """Look up original PII value by token (for round-trip demasking).

        Args:
            token: The TOKEN_TYPE_NNN token to resolve.
            session_id: If non-empty, restrict the lookup to mappings stored
                under this session. This prevents the cross-session collision
                where two concurrent sessions map the same token string (e.g.
                ``TOKEN_EMAIL_001``) to *different* originals and the restore
                would return the wrong person's PII. The most recent matching
                row wins (``ORDER BY id DESC``). Empty ``session_id`` (default)
                scans all rows for backward compatibility and returns the most
                recent match.

        Returns decrypted original value or None.

        PERF-4: when ``token_hash`` is populated we use the SQLite index to
        narrow candidates to O(log n). For legacy rows the index is bypassed
        and matching is performed in Python after decrypting only the
        un-migrated candidate rows.
        """
        if not token:
            return None
        token_hash = self._token_hash(token)
        with self._lock:
            conn = self._open_conn()
            try:
                if session_id:
                    # Prefer indexed hash lookup within the session. If the
                    # column has not been backfilled, fall through to the
                    # legacy fallback.
                    row = conn.execute(
                        "SELECT token_encrypted, original_encrypted FROM mappings "
                        "WHERE session_id = ? AND token_hash = ? "
                        "ORDER BY id DESC LIMIT 1",
                        (session_id, token_hash),
                    ).fetchone()
                    if row:
                        encrypted_token, encrypted_original = row
                        try:
                            decrypted_token = self._decrypt(encrypted_token)
                            if decrypted_token == token and encrypted_original is not None:
                                return self._decrypt(encrypted_original)
                        except Exception:
                            pass
                    rows = conn.execute(
                        "SELECT token_encrypted, original_encrypted FROM mappings "
                        "WHERE session_id = ? AND (token_hash = '' OR token_hash IS NULL) "
                        "ORDER BY id DESC",
                        (session_id,),
                    ).fetchall()
                else:
                    row = conn.execute(
                        "SELECT token_encrypted, original_encrypted FROM mappings "
                        "WHERE token_hash = ? ORDER BY id DESC LIMIT 1",
                        (token_hash,),
                    ).fetchone()
                    if row:
                        encrypted_token, encrypted_original = row
                        try:
                            decrypted_token = self._decrypt(encrypted_token)
                            if decrypted_token == token and encrypted_original is not None:
                                return self._decrypt(encrypted_original)
                        except Exception:
                            pass
                    rows = conn.execute(
                        "SELECT token_encrypted, original_encrypted FROM mappings "
                        "WHERE token_hash = '' OR token_hash IS NULL "
                        "ORDER BY id DESC"
                    ).fetchall()
                for encrypted_token, encrypted_original in rows:
                    try:
                        decrypted_token = self._decrypt(encrypted_token)
                        if decrypted_token == token:
                            if encrypted_original is not None:
                                return self._decrypt(encrypted_original)
                            return None
                    except Exception:
                        continue
                return None
            finally:
                conn.close()

    def known_original_values(self, session_id: str = "") -> set[str]:
        """Return the set of plaintext original PII values for a session.

        Used by the output-side scanner to distinguish "fresh" PII (LLM
        hallucinated a value we never mapped) from "already-mapped" PII
        (the original value is expected to round-trip through restoration).

        TTL filtering: rows whose ``expires_at`` is in the past are skipped
        so a stale mapping never shadows a fresh match in the response.

        Session filtering: when ``session_id`` is non-empty, only rows for
        that session are returned; an empty ``session_id`` returns the
        empty set so callers must always thread the session through.

        Originals are decrypted on demand; they are NEVER cached on the
        instance to keep the side-channel small.
        """
        if not session_id:
            return set()
        now = time.time()
        results: set[str] = set()
        with self._lock:
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT original_encrypted, expires_at FROM mappings "
                    "WHERE session_id = ?",
                    (session_id,),
                ).fetchall()
            finally:
                conn.close()
        for encrypted_original, expires_at in rows:
            if expires_at and expires_at > 0 and expires_at < now:
                continue
            if not encrypted_original:
                continue
            try:
                plaintext = self._decrypt(encrypted_original)
            except Exception:
                # Skip undecryptable rows rather than blowing up the caller.
                continue
            if plaintext:
                results.add(plaintext)
        return results

    def backfill_token_serial(
        self,
        session_id: str,
        pii_type: str,
        max_rows: int = 200,
    ) -> int:
        """Bounded lazy backfill of ``token_serial`` for one (session, type).

        v1.7.6 (Decision 2): rows written before this migration carry
        ``token_serial IS NULL``. This helper decrypts at most ``max_rows``
        (hard cap 200) such rows for the given (session_id, type) combination,
        re-derives the serial from the decrypted plaintext token, and
        persists it — all under the existing instance lock. It runs at most
        once per (session, type) for the lifetime of this instance so a hot
        restore path cannot repeatedly pay the PBKDF2 cost (~43 ms/row at
        600k iterations). NEVER decrypts the whole table: a 61k-row
        full-table scan would take ~45 min.

        Rows whose plaintext token has no serial (legacy no-counter shape)
        are stamped ``TOKEN_SERIAL_ABSENT`` (-1) so later calls skip them;
        they will never qualify for splice repair (fail-closed).

        Returns the number of rows updated.
        """
        if not session_id or not pii_type:
            return 0
        max_rows = min(max_rows, 200)
        key = (session_id, pii_type)
        with self._lock:
            if key in self._serial_backfill_done or max_rows <= 0:
                return 0
            updated = 0
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT id, token_encrypted FROM mappings "
                    "WHERE session_id = ? AND type = ? AND token_serial IS NULL "
                    "ORDER BY id LIMIT ?",
                    (session_id, pii_type, max_rows),
                ).fetchall()
                for row_id, encrypted_token in rows:
                    try:
                        token = self._decrypt(encrypted_token)
                    except Exception:
                        # Undecryptable row: mark processed, no repair.
                        conn.execute(
                            "UPDATE mappings SET token_serial = ? WHERE id = ?",
                            (TOKEN_SERIAL_ABSENT, row_id),
                        )
                        updated += 1
                        continue
                    serial = _parse_token_serial(token, self.token_pattern)
                    conn.execute(
                        "UPDATE mappings SET token_serial = ? WHERE id = ?",
                        (serial if serial is not None else TOKEN_SERIAL_ABSENT, row_id),
                    )
                    updated += 1
                if updated:
                    conn.commit()
                    logger.info(
                        "backfill_token_serial: %d rows updated (session=<%d chars>, type=%s)",
                        updated, len(session_id), pii_type,
                    )
            finally:
                conn.close()
            # Mark done even when rows remain NULL (row cap) or none existed —
            # the promise is "at most once per (session, type)".
            self._serial_backfill_done.add(key)
        return updated

    def backfill_token_serial_chunk(self, max_rows: int = 200) -> int:
        """One resumable global backfill chunk (operator CLI helper).

        Processes up to ``max_rows`` rows with ``token_serial IS NULL``
        across ALL sessions/types in a single transaction, regardless of
        the per-(session, type) lazy marker — the CLI owns its resumability
        by looping until this returns 0. Returns rows processed.
        """
        max_rows = min(max_rows, 1000)
        if max_rows <= 0:
            return 0
        with self._lock:
            processed = 0
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT id, token_encrypted FROM mappings "
                    "WHERE token_serial IS NULL ORDER BY id LIMIT ?",
                    (max_rows,),
                ).fetchall()
                for row_id, encrypted_token in rows:
                    try:
                        token = self._decrypt(encrypted_token)
                    except Exception:
                        conn.execute(
                            "UPDATE mappings SET token_serial = ? WHERE id = ?",
                            (TOKEN_SERIAL_ABSENT, row_id),
                        )
                        processed += 1
                        continue
                    serial = _parse_token_serial(token, self.token_pattern)
                    conn.execute(
                        "UPDATE mappings SET token_serial = ? WHERE id = ?",
                        (serial if serial is not None else TOKEN_SERIAL_ABSENT, row_id),
                    )
                    processed += 1
                if processed:
                    conn.commit()
            finally:
                conn.close()
        return processed

    def resolve_fuzzy_token(
        self,
        pii_type: str,
        serial: int,
        session_id: str,
        max_rows: int = 50,
    ) -> str | None:
        """Session-scoped splice repair: resolve ``(type, serial)`` → original.

        v1.7.6 (Decision 2): a model-mangled token (correct serial, broken
        hash/prefix) is repaired from same-session candidates keyed by
        ``(session_id, type, token_serial)`` via the SQLite index.

        Uniqueness contract: exactly ONE distinct original value among the
        candidates → restore; 0 or ≥ 2 distinct originals → ``None`` (the
        caller substitutes the restore-miss placeholder). Row count is
        irrelevant — 4 rows with 2 distinct originals are ambiguous.

        Security: candidates restricted to the exact ``session_id`` (no
        cross-session fallback, never resolves with empty ``session_id``);
        ``pii_type`` is compared lowercased against the lowercase DB column.
        Integrity (v1.7.6 security fix, Finding 3f): ``token_serial`` is NOT
        trusted as authoritative — each candidate row's serial is re-derived
        from its own decrypted ``token_encrypted`` and must match the stored
        column value; mismatched rows are excluded from the candidate set AND
        repaired back to the content-derived serial (an attacker with DB write
        access can otherwise point one row's serial at a foreign original —
        repairing the row also cleans the attack state). This costs one extra
        decryption per candidate row on the already-slow fuzzy-repair path.
        Fail-closed truncation (v1.7.6 security fix, Review F4): when the
        candidate query hits ``max_rows`` the set may be truncated beyond
        uniqueness, so the result is inconclusive → ``None`` (placeholder).
        Performance: at most one bounded lazy backfill (≤ 200 rows, once per
        (session, type)) plus bounded decryptions of ``original_encrypted``
        and ``token_encrypted`` per call — the PII plaintext original is only
        decrypted after a row passed serial verification.
        """
        if not session_id or not pii_type:
            return None
        if not isinstance(serial, int) or serial < 0:
            return None
        normalized_type = pii_type.lower()
        self.backfill_token_serial(session_id, normalized_type)
        now = time.time()
        with self._lock:
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT id, token_encrypted, token_serial, original_encrypted, expires_at "
                    "FROM mappings "
                    "WHERE session_id = ? AND type = ? AND token_serial = ? "
                    "ORDER BY id LIMIT ?",
                    (session_id, normalized_type, serial, max_rows),
                ).fetchall()
            finally:
                conn.close()
        # F4 fail-closed: a full candidate window means the true candidate set
        # may extend beyond the LIMIT — uniqueness cannot be established.
        if len(rows) >= max_rows:
            logger.debug(
                "resolve_fuzzy_token: candidate window exhausted (limit=%d, session=<%d chars>, "
                "type=%s) — fail-closed",
                max_rows, len(session_id), normalized_type,
            )
            return None
        originals: set[str] = set()
        repairs: list[tuple[int, int]] = []
        for row_id, encrypted_token, stored_serial, encrypted_original, expires_at in rows:
            if expires_at and expires_at > 0 and expires_at < now:
                continue
            if not encrypted_original:
                continue
            # Finding 3f: re-derive the serial from the row's own token.
            content_serial: int | None = None
            if encrypted_token:
                try:
                    content_serial = _parse_token_serial(
                        self._decrypt(encrypted_token), self.token_pattern
                    )
                except Exception:
                    content_serial = None
            if content_serial != stored_serial:
                if content_serial is not None:
                    # SQL parameter order: SET token_serial = ?, WHERE id = ?
                    repairs.append((content_serial, row_id))
                    logger.warning(
                        "Privacy-Shield: token_serial integrity violation "
                        "(row=%d, stored_serial=%d, derived_serial=%d) — repaired, row excluded",
                        row_id, stored_serial if stored_serial is not None else -1, content_serial,
                    )
                continue
            try:
                plaintext = self._decrypt(encrypted_original)
            except Exception:
                continue
            if plaintext:
                originals.add(plaintext)
        if repairs:
            with self._lock:
                conn = self._open_conn()
                try:
                    conn.executemany(
                        "UPDATE mappings SET token_serial = ? WHERE id = ?", repairs
                    )
                    conn.commit()
                finally:
                    conn.close()
        if len(originals) == 1:
            return next(iter(originals))
        return None

    def restore_text(self, text: str, session_id: str = "") -> str:
        """Restore tokens in text back to original PII values.

        Scans for ``{PREFIX}_{TYPE}_{HASH}_{COUNTER}`` patterns
        (e.g. ``TOKEN_EMAIL_a1b2c3d4e5_001``) and replaces each with
        the original PII value from the mapping table. Tokens that
        cannot be resolved are left as-is (fallback — LLM may have
        lost them).

        SMELL-4 (Morpheus R5): the docstring previously advertised
        ``TOKEN_TYPE_NNN`` (Phase-1 style) even though the regex and
        rest of the code use the Phase-4 hash+counter shape introduced
        by FIX-4A.  Documentation now matches the implementation.

        Args:
            text: Text containing tokens like TOKEN_EMAIL_a1b2c3d4e5_001
            session_id: Restrict restoration to this session's mappings
                (prevents cross-session token collisions — see
                ``lookup_original_by_token``). Empty = scan all (backward
                compatible with the no-session CLI path).

        Returns:
            Text with tokens replaced by original PII values where possible.
        """
        if not text:
            return text

        # FIX-4A (NEU-001): Use the pre-compiled configurable token_pattern
        # (built from token_prefix/hash_length/counter_digits in __init__)
        # instead of a hardcoded TOKEN_ regex. Counter suffix is optional
        # in the pattern, so legacy tokens without a counter still match.
        def _replace(match: re.Match[str]) -> str:
            full_token = match.group(0)
            original = self.lookup_original_by_token(
                full_token, session_id=session_id
            )
            if original is not None:
                return str(original)
            # Fallback: leave token as-is (LLM may have lost it)
            return full_token

        return self.token_pattern.sub(_replace, text)

    def count(self) -> int:
        """Return total number of stored mappings."""
        with self._lock:
            conn = self._open_conn()
            try:
                row = conn.execute("SELECT COUNT(*) FROM mappings").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def list_all(self) -> list[dict[str, Any]]:
        """Return all stored mappings with decrypted tokens.

        Returns list of dicts: {original_hash, token, type, created_at, session_id}
        """
        with self._lock:
            conn = self._open_conn()
            try:
                rows = conn.execute(
                    "SELECT original_hash, token_encrypted, type, created_at, session_id "
                    "FROM mappings ORDER BY id"
                ).fetchall()
                results: list[dict[str, Any]] = []
                for original_hash, encrypted_token, pii_type, created_at, session_id in rows:
                    try:
                        token = self._decrypt(encrypted_token)
                    except Exception:
                        token = "<decrypt-failed>"
                    results.append({
                        "original_hash": original_hash,
                        "token": token,
                        "type": pii_type,
                        "created_at": created_at,
                        "session_id": session_id,
                    })
                return results
            finally:
                conn.close()

    def prune_expired(self) -> int:
        """Delete all mappings where expires_at < now.

        Returns count of deleted rows.
        """
        now = time.time()
        with self._lock:
            conn = self._open_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM mappings WHERE expires_at > 0 AND expires_at < ?",
                    (now,),
                )
                conn.commit()
                deleted = cursor.rowcount
                if deleted:
                    logger.info("prune_expired: removed %d expired mappings", deleted)
                return deleted
            finally:
                conn.close()

    def purge_session(self, session_id: str) -> int:
        """Delete all mappings bound to a session (purpose-limitation purge).

        Implements "retention = session lifetime": when a session ends its
        mappings are deleted with it (DSGVO Art. 5(1)(e)). Canonical name
        for the session-end hook; ``close_session`` delegates here.

        The WHERE clause is load-bearing, a bare DELETE would wipe every
        other live session's mappings.
        """
        if not session_id:
            return 0
        with self._lock:
            conn = self._open_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM mappings WHERE session_id = ?",
                    (session_id,),
                )
                conn.commit()
                deleted = cursor.rowcount
                if deleted:
                    logger.info(
                        "purge_session: removed %d mappings for session %s",
                        deleted, session_id,
                    )
                return deleted
            finally:
                conn.close()

    def close_session(self, session_id: str) -> int:
        """Delete all mappings for a given session_id.

        Implements Google-Empfehlung: "Nach dem Chat-Ende müssen die IDs
        sofort gelöscht werden."

        Returns count of deleted rows.
        """
        return self.purge_session(session_id)

    def expired_count(self) -> int:
        """Return count of expired (but not yet pruned) mappings."""
        now = time.time()
        with self._lock:
            conn = self._open_conn()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM mappings WHERE expires_at > 0 AND expires_at < ?",
                    (now,),
                ).fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def close(self) -> None:
        """Explicit close (no-op for SQLite, but good practice)."""
        pass


# ── In-Memory Session-Scoped Mapping Table ────────────────────────────────

class InMemoryMappingTable:
    """Session-scoped mapping table that never touches disk.

    Implements the Phase-4 cache-leak mitigation: there is no file on disk
    that an attacker could read, and the mapping lives only as long as the
    Hermes session.  On ``close_session`` the dictionary entry is deleted.

    Trade-off: mapping table is lost on process restart, so tokens that were
    sent to the provider can no longer be restored.  That is acceptable because
    the provider already saw the pseudonymized content; the goal is to avoid
    leaking the original PII from local storage.
    """

    def __init__(
        self,
        token_prefix: str = "TOKEN",
        hash_length: int = 10,
        counter_digits: int = 3,
        **_kwargs: Any,
    ):
        self._store: dict[str, dict[str, tuple[str, float]]] = {}
        self._lock = threading.Lock()
        # FIX-4A (NEU-001): configurable token-pattern parameters, matching
        # the Pseudonymizer emit format. Counter suffix is optional in the
        # regex so legacy tokens without a counter still match.
        self.token_prefix = token_prefix
        self.hash_length = hash_length
        self.counter_digits = counter_digits
        self.token_pattern = _compile_token_pattern(
            token_prefix=token_prefix,
            hash_length=hash_length,
            counter_digits=counter_digits,
        )

    def store(
        self,
        mappings: list[dict[str, Any]],
        session_id: str = "",
        ttl_seconds: int = MappingTable.TTL_DEFAULT_SECONDS,
    ) -> None:
        """Store PII→token mappings in memory with TTL-based expiry."""
        if not mappings:
            return
        now = time.time()
        expires_at = now + ttl_seconds if ttl_seconds > 0 else now
        with self._lock:
            session_store = self._store.setdefault(session_id, {})
            for m in mappings:
                token = m["token"]
                original = m.get("original_value", "")
                session_store[token] = (original, expires_at)

    def restore_text(self, text: str, session_id: str = "") -> str:
        """Restore tokens in text back to original PII values."""
        if not text:
            return text
        now = time.time()
        with self._lock:
            session_store = self._store.get(session_id, {})

        def _replace(match: re.Match[str]) -> str:
            full_token = match.group(0)
            entry = session_store.get(full_token)
            if entry is None:
                return full_token
            original, expires_at = entry
            if now > expires_at:
                return full_token
            if original is None:
                return full_token
            return str(original)

        # FIX-4A (NEU-001): use the pre-compiled configurable pattern.
        return self.token_pattern.sub(_replace, text)

    def known_original_values(self, session_id: str = "") -> set[str]:
        """Return the set of plaintext original PII values for a session.

        Same semantics as ``MappingTable.known_original_values`` — TTL
        filtering, session filtering, empty ``session_id`` returns empty.
        """
        if not session_id:
            return set()
        now = time.time()
        results: set[str] = set()
        with self._lock:
            session_store = self._store.get(session_id, {})
        for original, expires_at in session_store.values():
            if expires_at and expires_at > 0 and expires_at < now:
                continue
            if original:
                results.add(original)
        return results

    def lookup_original_by_token(self, token: str, session_id: str = "") -> str | None:
        """Look up the original value for a token in a session."""
        with self._lock:
            session_store = self._store.get(session_id, {})
        entry = session_store.get(token)
        if entry is None:
            return None
        original, expires_at = entry
        if time.time() > expires_at:
            return None
        return original

    def resolve_fuzzy_token(
        self,
        pii_type: str,
        serial: int,
        session_id: str = "",
        max_rows: int = 50,
    ) -> str | None:
        """Session-scoped splice repair for the in-memory backend.

        v1.7.6 (Decision 2): tokens are stored in plaintext keyed by token
        string, so the serial is parsed directly via ``token_pattern`` — no
        backfill and no decryption needed. Same uniqueness contract as
        ``MappingTable.resolve_fuzzy_token``: exactly one distinct original
        among the TTL-live ``(type, serial)`` candidates, never across
        sessions, fail-closed on empty ``session_id`` or non-numeric serial.
        """
        if not session_id or not pii_type:
            return None
        if not isinstance(serial, int) or serial < 0:
            return None
        normalized_type = pii_type.lower()
        now = time.time()
        # Snapshot the session entries under the lock (Review F7): iterating
        # the live dict outside the lock raced with concurrent store() and
        # silently degraded repair to a miss.
        with self._lock:
            session_items = list(self._store.get(session_id, {}).items())
        originals: set[str] = set()
        for token, (original, expires_at) in session_items:
            if expires_at and expires_at > 0 and expires_at < now:
                continue
            if not original:
                continue
            match = self.token_pattern.fullmatch(token)
            if match is None:
                continue
            if match.group(1).lower() != normalized_type:
                continue
            token_serial = match.group(3)
            if token_serial is None or not token_serial.isdigit():
                continue
            if int(token_serial) != serial:
                continue
            originals.add(str(original))
            if len(originals) > 1 or len(originals) >= max_rows:
                break
        if len(originals) == 1:
            return next(iter(originals))
        return None

    def count(self) -> int:
        with self._lock:
            return sum(len(s) for s in self._store.values())

    def list_all(self) -> list[dict[str, Any]]:
        """Return all stored mappings with SHA-256 hashes, never plaintext."""
        results: list[dict[str, Any]] = []
        with self._lock:
            for session_id, session_store in self._store.items():
                for token, (original, _) in session_store.items():
                    results.append({
                        "original_hash": hashlib.sha256(original.encode()).hexdigest(),
                        "token": token,
                        "type": token.split("_")[1] if "_" in token else "unknown",
                        "created_at": 0.0,
                        "session_id": session_id,
                    })
        return results

    def prune_expired(self) -> int:
        now = time.time()
        deleted = 0
        with self._lock:
            for session_store in self._store.values():
                expired = [t for t, (_, exp) in session_store.items() if exp > 0 and exp < now]
                for t in expired:
                    del session_store[t]
                    deleted += 1
        return deleted

    def close_session(self, session_id: str) -> int:
        """Crypto-shred: remove all mappings for the given session.

        Returns the number of mappings that were removed.
        """
        if not session_id:
            return 0
        with self._lock:
            session_store = self._store.pop(session_id, {})
            count = len(session_store)
            # Best-effort overwrite before GC
            for token in list(session_store):
                session_store[token] = ("", 0.0)
            del session_store
            gc.collect()
            return count

    def purge_session(self, session_id: str) -> int:
        """Remove all mappings for the session (session-end purge path)."""
        return self.close_session(session_id)

    def expired_count(self) -> int:
        now = time.time()
        count = 0
        with self._lock:
            for session_store in self._store.values():
                for _, exp in session_store.values():
                    if exp > 0 and exp < now:
                        count += 1
        return count

    def close(self) -> None:
        with self._lock:
            for session_store in self._store.values():
                for token in list(session_store):
                    session_store[token] = ("", 0.0)
            self._store.clear()
            gc.collect()


# Backward-compatible alias used by older code/tests
SessionMappingTable = InMemoryMappingTable
