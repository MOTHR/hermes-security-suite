#!/usr/bin/env python3
"""Resumable one-shot backfill of ``token_serial`` in the mapping table.

v1.7.6 (Decision 2, Performance contract): rows written before the
token_serial migration carry ``NULL`` in that column and can therefore
never qualify for the session-scoped splice repair (fail-closed). The
plugin ships a *bounded lazy backfill* (≤ 200 rows, at most once per
(session, type)) on the restore path; this script is the operator tool
that converges the whole table offline, in chunks, with resume.

Resume model: a row is "done" as soon as ``token_serial`` is non-NULL —
either the parsed serial (0-999) or ``-1`` (= processed, token has no
serial). Simply re-run the script after an interruption; only rows with
``token_serial IS NULL`` are touched. No full-table re-decrypt of
already-migrated rows.

Performance: PBKDF2-HMAC-SHA256 with 600_000 iterations costs roughly
40–120 ms per decryption depending on host and crypto backend, so the
default chunk of 200 rows takes ~10–25 s.
Size the chunk with ``--chunk``; ``--max`` optionally stops the whole
run after N processed rows (0 = unlimited). The in-flight chunk always
finishes before the limit is checked, so one final chunk may exceed
``--max`` slightly.

Usage:
    python scripts/backfill_token_serial.py [--db PATH] [--chunk 200] [--max 0] [--dry-run]
    python scripts/backfill_token_serial.py --status [--db PATH]

The encryption key is resolved exactly like the plugin does (pass store →
PRIVACY_SHIELD_KEY env → PRIVACY_SHIELD_KEY_FILE). The script never
prints decrypted content — only counts and progress.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from privacy_shield.config import load_config  # noqa: E402
from privacy_shield.mapping_table import MappingTable  # noqa: E402


def _default_db_path() -> str:
    return str(load_config().storage_path)


def _build_table(db_path: str) -> MappingTable | None:
    config = load_config()
    key = config.encryption_key
    if not key:
        print(
            "ERROR: no encryption key resolved (pass store / PRIVACY_SHIELD_KEY). "
            "Aborting without touching the database.",
            file=sys.stderr,
        )
        return None
    return MappingTable(
        storage_path=db_path,
        encryption_key=key,
        kdf_iterations=600_000,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill token_serial column (resumable, chunked)."
    )
    parser.add_argument(
        "--db",
        default=None,
        help="Mapping DB path (default: configured storage_path)",
    )
    parser.add_argument(
        "--chunk",
        type=int,
        default=200,
        help="Rows per chunk (default 200; each row ≈ 43 ms PBKDF2)",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0,
        help="Stop after N processed rows (0 = unlimited)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Only print counts, do not modify anything.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many rows would be processed, then exit.",
    )
    args = parser.parse_args()

    db_path = args.db or _default_db_path()

    table = _build_table(db_path)
    if table is None:
        return 2

    if args.status or args.dry_run:
        import sqlite3

        with sqlite3.connect(db_path) as conn:
            # read-only report; counts only, no decryption
            rows = conn.execute(
                "SELECT COUNT(*), SUM(token_serial IS NULL) FROM mappings"
            ).fetchone()
        total, pending = (rows[0] or 0, rows[1] or 0)
        print(f"total_rows={total} pending_backfill={pending}")
        return 0

    processed_total = 0
    limit = args.max if args.max and args.max > 0 else float("inf")
    chunk = max(1, min(args.chunk, 1000))
    while processed_total < limit:
        count = table.backfill_token_serial_chunk(max_rows=chunk)
        if count == 0:
            break
        processed_total += count
        print(f"processed={processed_total}", flush=True)
    print(f"done processed={processed_total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())