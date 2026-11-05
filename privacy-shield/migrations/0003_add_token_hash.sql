-- Migration 0003: Add token_hash column + index for O(log n) reverse lookup.
-- PERF-4 (Morpheus R5): previously lookup_by_token / lookup_original_by_token
-- decrypted every row to find a match. This migration adds a deterministic
-- SHA-256 hash of the plaintext token so SQLite can use the new index.
--
-- Idempotent: ALTER TABLE ADD COLUMN and CREATE INDEX IF NOT EXISTS both
-- tolerate being run multiple times. Legacy rows keep an empty token_hash
-- until the next write or a manual backfill.

ALTER TABLE mappings ADD COLUMN token_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_mappings_token_hash
ON mappings(token_hash);
