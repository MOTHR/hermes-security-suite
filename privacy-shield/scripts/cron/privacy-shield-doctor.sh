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
#   4 = encryption key unresolvable (privacy-shield 1.9.x contract fix)

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

# --- Pre-Check 3: key available (privacy-shield 1.9.x) ---------------------------
# Without an encryption key the plugin is disabled and `doctor --quick` was a
# silent false-pass (1.9.x stage greps pass a keyless run). The doctor CLI now
# asserts the key itself (Pre-Stage 0, exit 2); this wrapper still provisions
# the key itself from the pass entry the pre-1.9 CLI used, so a missing key
# fails HERE with a dedicated exit code instead of as a doctor stage failure.
# Value is never printed.
pass_bin="$(command -v pass 2>/dev/null || true)"
resolved_key=""
for pcand in ${pass_bin:+"$pass_bin"} "$HOME/.local/bin/pass" "/opt/homebrew/bin/pass"; do
    [ -x "$pcand" ] || continue
    # ~/.local/bin/pass + MacGPG2 gpg is the known-good launchd combination
    # augment with the known-good launchd gpg set: MacGPG2 2.2.41 matches the
    # running gpg-agent; newer /opt/homebrew gpg (2.5.24) fails against it
    resolved_key="$(PATH="$HOME/.local/bin:/usr/local/bin:/usr/local/MacGPG2/bin:$PATH" "$pcand" show hermes/privacy-shield-key 2>/dev/null || true)"
    [ -n "$resolved_key" ] && break
done
if [ -n "${PRIVACY_SHIELD_KEY:-}" ]; then
    : # key already provided by the caller
elif [ -n "$resolved_key" ]; then
    export PRIVACY_SHIELD_KEY="$resolved_key"
else
    log "FAIL: no encryption key resolvable (env PRIVACY_SHIELD_KEY or pass show hermes/privacy-shield-key)"
    if [ -x "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" ]; then
        "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" \
            "Privacy-Shield Doctor FAILED" \
            "doctor wrapper: encryption key unresolvable (exit 4) at $(date -u +%Y-%m-%dT%H:%M:%SZ)
Plugin would run DISABLED; no keyless doctor pass written." \
            >/dev/null 2>&1 || log "WARN: telegram-alert.sh failed"
    fi
    exit 4
fi

# --- Run doctor --quick (Stages 1+2; skips pytest) -------------------------------
START_TS=$(date +%s)
# Capture the sub-command's real rc: `if ! cmd` would leave $? as the
# negation's status (0) inside the branch, masking the actual failure code.
RC=0
OUTPUT=$(privacy-shield doctor --quick 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then
    log "FAIL: doctor --quick exited with rc=$RC"
    echo "$OUTPUT" >> "$DOCTOR_LOG"

    # Telegram-Alert bei Fail (best-effort)
    if [ -x "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" ]; then
        "$HERMES_HOME/profiles/sysadmin/scripts/telegram-alert.sh" \
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
