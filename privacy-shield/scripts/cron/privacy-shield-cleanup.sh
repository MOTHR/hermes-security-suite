#!/usr/bin/env bash
# Privacy-Shield Daily Cleanup (BUTLER-PS-8 / FIX-PS-R5-OPS)
#
# Runs `privacy-shield map --cleanup-expired` once per day to enforce
# DSGVO Art. 17 (Recht auf Löschung) — expired mappings must be removed
# from the persistent mapping table on a regular cadence, not only
# when a user manually invokes the command.
#
# Exit codes:
#   0 = cleanup succeeded (or nothing to clean up)
#   1 = prerequisite missing (privacy-shield binary or encryption key)
#   2 = cleanup command failed (mapping DB may be locked / corrupt)
#
# Designed to be wired into Hermes cron via:
#   hermes cron create "Privacy-Shield Daily Cleanup" --schedule "30 3 * * *" \
#       --script $HOME/.hermes/scripts/privacy-shield-cleanup.sh --no-agent
#
# Memory-Lesson q: silent on PASS, stderr on FAIL. No progress chatter.

set -euo pipefail

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
PRIVACY_DIR="$HERMES_HOME/privacy"
LOG="$PRIVACY_DIR/cleanup.log"
STATE_DIR="$PRIVACY_DIR"
LAST_OK_FILE="$STATE_DIR/last_cleanup_ok"

mkdir -p "$PRIVACY_DIR"

log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG" >&2
}

# --- Pre-Check 1: privacy-shield binary available --------------------------------
if ! command -v privacy-shield >/dev/null 2>&1; then
    log "FAIL: privacy-shield not on PATH"
    exit 1
fi

# --- Pre-Check 2: key available (privacy-shield 1.9.x) --------------------------
# privacy-shield 1.9.x removed the standalone pass fallback from load_config
# (pure upstream plugin contract): the CLI resolves the key only via the
# Hermes secret scope (which reads os.environ outside multiplexing). A cron
# subprocess has no Hermes runtime, so the script provisions the key itself
# from the same pass entry the pre-1.9 CLI used. Value is never printed.
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
    log "FAIL: pass store has no resolvable hermes/privacy-shield-key entry"
    exit 1
fi

# --- Run map --cleanup-expired (DSGVO Art. 17) ---------------------------------
START_TS=$(date +%s)
# Capture the sub-command's real rc: `if ! cmd` would leave $? as the
# negation's status (0) inside the branch, masking the actual failure code.
RC=0
OUTPUT=$(privacy-shield map --cleanup-expired 2>&1) || RC=$?
if [ "$RC" -ne 0 ]; then
    log "FAIL: map --cleanup-expired exited with rc=$RC"
    echo "$OUTPUT" >> "$LOG"

    # Telegram-Alert bei Fail (best-effort)
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

# Detect removed rows from OUTPUT. The CLI emits two equivalent lines:
#   "Deleted: N"
#   (older versions) "Removed N expired mappings"
# We accept both. grep returns 1 on no match; with `pipefail` that
# would abort the script, so we capture via `|| true`.
REMOVED=$(echo "$OUTPUT" | grep -oE '(Deleted: |Removed )[0-9]+' | head -1 | grep -oE '[0-9]+' || true)
REMOVED=${REMOVED:-0}

echo "$OUTPUT" >> "$LOG"
date -u +%Y-%m-%dT%H:%M:%SZ > "$LAST_OK_FILE"
log "OK: cleanup complete in ${DURATION}s — removed ${REMOVED} expired mappings"
exit 0
