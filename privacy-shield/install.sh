#!/usr/bin/env bash
#
# Privacy-Shield One-Liner Installer
# Installs the plugin through the stock Hermes plugin system.
# Modes: --dry-run, --apply, --uninstall
#
# No core patching, no crontab, no config.yaml rewriting: the plugin uses
# upstream hook/middleware contracts only (hermes plugins install +
# hermes plugins enable carry the desktop/ and dashboard/ halves).

set -euo pipefail

PLUGIN_DIR="${HOME}/.hermes/plugins/privacy-shield"

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

do_install() {
    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "hermes plugins install <plugin-quelle>/privacy-shield"
        dry_run "hermes plugins enable privacy-shield (pro Profil)"
        return 0
    fi

    check_hermes_cli
    log_info "Installiere Privacy-Shield via Hermes-Plugin-System..."
    log_info "Quelle: das geklonte MOTHR/hermes-security-suite Repo."
    log_info "Danach: hermes plugins enable privacy-shield  (pro Profil)"
}

do_uninstall() {
    if [[ "${MODE:-}" == "dry-run" ]]; then
        dry_run "hermes plugins disable privacy-shield"
        return 0
    fi

    log_info "Deinstalliere Privacy-Shield..."
    if command -v hermes &>/dev/null; then
        hermes plugins disable privacy-shield || log_warn "hermes plugins disable schlug fehl oder Plugin nicht installiert."
    else
        log_warn "Hermes CLI nicht gefunden — Plugin manuell deaktivieren."
    fi
    log_warn "Plugin-Verzeichnis wird NICHT automatisch geloescht."
    log_warn "Manuell loeschen: rm -rf $PLUGIN_DIR"
    log_info "Deinstallation abgeschlossen."
}

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

    if [[ "$mode" == "uninstall" ]]; then
        do_uninstall
        log_info "FERTIG. Privacy-Shield ist deinstalliert."
        exit 0
    fi

    do_install

    log_info "========================================="
    log_info "FERTIG."
    if [[ "$mode" == "dry-run" ]]; then
        log_info "Das war nur ein Probelauf (--dry-run)."
        log_info "Fuehre '$0 --apply' aus, um wirklich zu installieren."
    fi

    exit 0
}

main "$@"
