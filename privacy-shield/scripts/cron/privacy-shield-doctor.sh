#!/usr/bin/env bash
# Privacy-Shield Daily Doctor Health-Check (BUTLER-PS-3 / FIX-PS-R5-OPS)
#
# Source-of-truth script lives in ~/.hermes/scripts/privacy-shield-doctor.sh
# (the cron entry point used by hermes cron). This in-repo copy exists so the
# plugin ships its own operations assets, identical in behaviour, for the
# Operator who pulls privacy-shield into a fresh Hermes without the global
# scripts directory.
#
# Exit codes:
#   0 = healthy (all stages pass)
#   1 = doctor subprocess returned non-zero
#   2 = privacy-shield binary missing
#   3 = critical structural issue (e.g. plugin.yaml unreadable)

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PRIVACY_DIR="$HERMES_HOME/privacy"
LOG="$PRIVACY_DIR/doctor.log"
DOCTOR_LOG="$PRIVACY_DIR/doctor-history.log"
LAST_OK_FILE="$PRIVACY_DIR/last_doctor_ok"

mkdir -p "$PRIVACY_DIR"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG" >&2
}

# --- Pre-Check 1: privacy-shield binary available --------------------------------
if ! command -v privacy-shield >/dev/null 2>&1; then
    log "FAIL: privacy-shield not on PATH"
    exit 2
fi

# --- Pre-Check 2: plugin source readable -----------------------------------------
PLUGIN_ROOT="$HERMES_HOME/plugins/privacy-shield"
if [ ! -d "$PLUGIN_ROOT" ]; then
    log "FAIL: plugin source missing at $PLUGIN_ROOT"
    exit 3
fi

# --- Run doctor --quick (Stages 1+2; skips pytest) -------------------------------
START_TS=$(date +%s)
if ! OUTPUT=$(privacy-shield doctor --quick 2>&1); then
    RC=$?
    log "FAIL: doctor --quick exited with rc=$RC"
    echo "$OUTPUT" >> "$DOCTOR_LOG"
    ALERT_SCRIPT="${PRIVACY_SHIELD_ALERT_SCRIPT:-$HERMES_HOME/scripts/telegram-alert.sh}"
    if [ -x "$ALERT_SCRIPT" ]; then
        "$ALERT_SCRIPT" \
            "Privacy-Shield Doctor FAILED" \
            "doctor --quick exit $RC at $(date -u +%Y-%m-%dT%H:%M:%SZ)
Last output:
$OUTPUT" \
            >/dev/null 2>&1 || log "WARN: telegram-alert.sh failed"
    fi
    exit 1
fi

END_TS=$(date +%s)
DURATION=$((END_TS - START_TS))
echo "$OUTPUT" >> "$DOCTOR_LOG"
date -u +%Y-%m-%dT%H:%M:%SZ > "$LAST_OK_FILE"
log "OK: doctor --quick passed in ${DURATION}s"
exit 0
