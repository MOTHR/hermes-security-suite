#!/usr/bin/env bash
#
# Privacy-Shield One-Liner Installer
# Modi: --dry-run, --apply, --uninstall
#
# Idempotent: Mehrfach-Ausfuehrung ist harmlos.

set -euo pipefail

# -------------------------------------------------
# Pfade (fest eingestellt)
# -------------------------------------------------
PLUGIN_DIR="${HOME}/.hermes/plugins/privacy-shield"
CONFIG_FILE="${HOME}/.hermes/config.yaml"
HERMES_PLUGINS_DIR="${HOME}/.hermes/plugins"
CRON_SCRIPT="${PLUGIN_DIR}/scripts/auto_apply_hook.py"
CRON_ENTRY="0 */6 * * * python3 ${CRON_SCRIPT} --apply >> ~/.hermes/privacy/auto-apply.log 2>&1"

# -------------------------------------------------
# Hilfsfunktionen
# -------------------------------------------------
log_info()  { echo "[INFO]  $1"; }
log_warn()  { echo "[WARN]  $1" >&2; }
log_error() { echo "[ERROR] $1" >&2; }

die() { log_error "$1"; exit 1; }

dry_run() {
    log_info "DRY-RUN: $1"
}

check_hermes_cli() {
    if ! command -v hermes &>/dev/null; then
        log_warn "Hermes CLI nicht im PATH gefunden. Pruefe ~/.hermes/hermes-agent/venv/bin/"
    fi
}

is_plugin_installed() {
    [[ -d "$PLUGIN_DIR" ]] && [[ -f "$PLUGIN_DIR/plugin.yaml" ]]
}

is_cron_installed() {
    crontab -l 2>/dev/null | grep -F "$CRON_SCRIPT" | grep -q -- --apply
}

is_config_enabled() {
    [[ -f "$CONFIG_FILE" ]] && grep -q "privacy_shield" "$CONFIG_FILE" 2>/dev/null
}

# -------------------------------------------------
# Aktionen
# -------------------------------------------------

do_install_plugin() {
    if is_plugin_installed; then
        log_info "Plugin-Verzeichnis existiert bereits: $PLUGIN_DIR"
        return 0
    fi

    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "Erstelle Plugin-Verzeichnis: $PLUGIN_DIR"
        return 0
    fi

    # Im echten Modus: Kopiere Plugin-Code (idempotent)
    if [[ -d "$PLUGIN_DIR" ]]; then
        log_info "Plugin-Verzeichnis existiert bereits."
    else
        log_info "Erstelle Plugin-Verzeichnis: $PLUGIN_DIR"
        mkdir -p "$PLUGIN_DIR"
    fi
    log_info "Hinweis: Plugin-Code muss per 'hermes plugin install' oder manuell kopiert werden."
}

do_enable_config() {
    if is_config_enabled; then
        log_info "privacy_shield ist bereits in config.yaml aktiviert."
        return 0
    fi

    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "Aktiviere privacy_shield in $CONFIG_FILE"
        return 0
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        die "config.yaml nicht gefunden: $CONFIG_FILE"
    fi

    log_info "Aktiviere privacy_shield in config.yaml..."
    # Fuege am Ende der Datei ein (idempotent)
    if ! grep -q "privacy_shield:" "$CONFIG_FILE"; then
        echo "" >> "$CONFIG_FILE"
        echo "privacy_shield:" >> "$CONFIG_FILE"
        echo "  enabled: true" >> "$CONFIG_FILE"
        echo "  mode: limited" >> "$CONFIG_FILE"
        echo "  detection_engine: regex" >> "$CONFIG_FILE"
        echo "  token_style: deterministic" >> "$CONFIG_FILE"
        echo "  fallback_on_timeout: block" >> "$CONFIG_FILE"
        echo "  max_latency_ms: 80" >> "$CONFIG_FILE"
    fi
    log_info "privacy_shield aktiviert."
}

do_register_cron() {
    if is_cron_installed; then
        log_info "Cron-Job ist bereits registriert."
        return 0
    fi

    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "Registriere Cron-Job: $CRON_ENTRY"
        return 0
    fi

    log_info "Registriere Cron-Job..."
    # Pruefe, ob Cron-Script existiert
    if [[ ! -f "$CRON_SCRIPT" ]]; then
        log_warn "Cron-Script nicht gefunden: $CRON_SCRIPT"
        log_warn "Cron-Registrierung wird uebersprungen."
        return 1
    fi

    # Erstelle Backup des aktuellen Crontabs
    crontab -l > /tmp/crontab.bak.$(date +%s) 2>/dev/null || true

    # Fuege Eintrag hinzu
    (crontab -l 2>/dev/null; echo "$CRON_ENTRY") | crontab -
    log_info "Cron-Job registriert."
}

do_healthcheck() {
    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "Pruefe Plugin-Gesundheit (hermes plugins list)"
        return 0
    fi

    log_info "Pruefe Plugin-Gesundheit..."
    if is_plugin_installed; then
        log_info "Plugin-Verzeichnis OK: $PLUGIN_DIR"
    else
        log_warn "Plugin-Verzeichnis NICHT gefunden: $PLUGIN_DIR"
    fi

    if is_config_enabled; then
        log_info "Config OK: privacy_shield aktiviert"
    else
        log_warn "Config: privacy_shield NICHT in config.yaml gefunden"
    fi

    if is_cron_installed; then
        log_info "Cron OK: Auto-Apply-Cron ist aktiv"
    else
        log_warn "Cron: Auto-Apply-Cron NICHT registriert"
    fi

    # Pruefe, ob auto_apply_hook.py existiert
    if [[ -f "$CRON_SCRIPT" ]]; then
        log_info "Auto-Apply-Script OK: $CRON_SCRIPT"
    else
        log_warn "Auto-Apply-Script NICHT gefunden: $CRON_SCRIPT"
    fi
}

do_uninstall() {
    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "Deaktiviere privacy_shield in config.yaml"
        dry_run "Entferne Cron-Job"
        dry_run "Plugin-Verzeichnis BLEIBT erhalten (manuelles Loeschen)"
        return 0
    fi

    log_info "Deinstalliere Privacy-Shield..."

    # Deaktiviere in config.yaml
    if [[ -f "$CONFIG_FILE" ]] && grep -q "privacy_shield:" "$CONFIG_FILE"; then
        # Entferne privacy_shield Block (einfache Methode: sed)
        sed -i '' '/^privacy_shield:/,/^[^ ]/d' "$CONFIG_FILE" 2>/dev/null || \
            sed -i '/^privacy_shield:/,/^[^ ]/d' "$CONFIG_FILE"
        log_info "privacy_shield aus config.yaml entfernt."
    fi

    # Entferne Cron-Job
    if is_cron_installed; then
        crontab -l | grep -vF "$CRON_SCRIPT" | crontab -
        log_info "Cron-Job entfernt."
    fi

    log_warn "Plugin-Verzeichnis wird NICHT automatisch geloescht."
    log_warn "Manuell loeschen: rm -rf $PLUGIN_DIR"

    log_info "Deinstallation abgeschlossen."
}

# -------------------------------------------------
# Hauptprogramm
# -------------------------------------------------

main() {
    local mode="apply"

    if [[ $# -gt 0 ]]; then
        case "$1" in
            --dry-run)
                mode="dry-run"
                MODE="dry-run"
                shift
                ;;
            --apply)
                mode="apply"
                shift
                ;;
            --uninstall)
                mode="uninstall"
                shift
                ;;
            *)
                echo "Usage: $0 [--dry-run | --apply | --uninstall]"
                exit 1
                ;;
        esac
    fi

    log_info "Privacy-Shield Installer — Modus: $mode"
    log_info "========================================="

    check_hermes_cli

    if [[ "$mode" == "uninstall" ]]; then
        do_uninstall
        log_info "FERTIG. Privacy-Shield ist deinstalliert."
        exit 0
    fi

    # 1. Plugin-Code (idempotent)
    do_install_plugin

    # 2. Config aktivieren (idempotent)
    do_enable_config

    # 3. Cron-Job registrieren (idempotent)
    do_register_cron || log_warn "Cron-Registrierung fehlgeschlagen."

    # 4. Health-Check
    do_healthcheck

    log_info "========================================="
    log_info "FERTIG. Privacy-Shield ist installiert."

    if [[ "$mode" == "dry-run" ]]; then
        log_info "Das war nur ein Probelauf (--dry-run)."
        log_info "Fuehre '$0 --apply' aus, um wirklich zu installieren."
    fi

    exit 0
}

main "$@"
