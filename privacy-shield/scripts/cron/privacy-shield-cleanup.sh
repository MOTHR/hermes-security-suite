#!/usr/bin/env bash
# Privacy-Shield Daily Cleanup (BUTLER-PS-8 / FIX-PS-R5-OPS)
#
# Source-of-truth lives in ~/.hermes/scripts/privacy-shield-cleanup.sh.
# This in-repo copy ships with the plugin so the Operator can pull
# privacy-shield into a fresh Hermes without the global scripts dir.
#
# Exit codes:
#   0 = cleanup succeeded (or nothing to clean up)
#   1 = privacy-shield binary missing
#   2 = cleanup command failed (mapping DB may be locked / corrupt)

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PRIVACY_DIR="$HERMES_HOME/privacy"
LOG="$PRIVACY_DIR/cleanup.log"
LAST_OK_FILE="$PRIVACY_DIR/last_cleanup_ok"

mkdir -p "$PRIVACY_DIR"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG" >&2
}

# --- Pre-Check 1: privacy-shield binary available --------------------------------
if ! command -v privacy-shield >/dev/null 2>&1; then
    log "FAIL: privacy-shield not on PATH"
    exit 1
fi

# --- Run map --cleanup-expired (DSGVO Art. 17) ---------------------------------
START_TS=$(date +%s)
if ! OUTPUT=$(privacy-shield map --cleanup-expired 2>&1); then
    RC=$?
    log "FAIL: map --cleanup-expired exited with rc=$RC"
    echo "$OUTPUT" >> "$LOG"
    if [ -x "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" ]; then
        "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" \
            "Privacy-Shield Cleanup FAILED" \
            "map --cleanup-expired exit $RC at $(date -u +%Y-%m-%dT%H:%M:%SZ)
Last output:
$OUTPUT
Action: inspect ~/.hermes/privacy/mapping.db (may be locked; stop conflicting privacy-shield processes and rerun)" \
            >/dev/null 2>&1 || log "WARN: telegram-alert.sh failed"
    fi
    exit 2
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))

REMOVED=$(echo "$OUTPUT" | grep -oE '(Deleted: |Removed )[0-9]+' | head -1 | grep -oE '[0-9]+' || true)
REMOVED=${REMOVED:-0}

echo "$OUTPUT" >> "$LOG"
date -u +%Y-%m-%dT%H:%M:%SZ > "$LAST_OK_FILE"
log "OK: cleanup complete in ${DURATION}s — removed ${REMOVED} expired mappings"
exit 0
