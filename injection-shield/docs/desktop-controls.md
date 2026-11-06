# Injection-Shield Desktop Controls

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# Injection-Shield Desktop Controls

Die Desktop-Controls-Funktion (v0.5.0) bietet Workshop-Teilnehmern und
Endusern einen grafischen Bereich in der Hermes-Desktop-App, um Injection-Shield
anzupassen, ohne YAML zu bearbeiten.

### Was kann geändert werden

| Einstellung | Typ | Beschreibung |
|------------|-----|-------------|
| `enabled` | bool | Plugin ein-/ausschalten |
| `mode` | Auswahl | `audit` (nur loggen) / `enforcement` (blockieren) |
| `allowed_domains` | String-Liste | Domains, die als vertrauenswürdiger Egress behandelt werden |
| `risky_tools` | String-Liste | Tools, die zusätzliche Prüfung auslösen |
| `tool_call_categories` | String-Liste | Aktivierte Tool-Call-Exfil-Detektoren |
| `telegram.enabled` | bool | Telegram-Benachrichtigungen (Opt-in) |
| `telegram.chat_id` | int/null | Ziel-Telegram-Chat-ID |
| `telegram.min_severity` | Auswahl | `low` / `medium` / `high` / `critical` |
| `audit_log_path` | String | Pfad für rotierendes Audit-Log |
| `audit_log_max_bytes` | int | Rotationsschwelle |
| `audit_log_backup_count` | int | Anzahl der Backups |
| `audit_log_retention_days` | int | Auto-Prune-Schwelle in Tagen |

### Architektur

- **Backend**: `dashboard/plugin_api.py` exportiert einen `fastapi.APIRouter`.
  Hermes mounted ihn unter `/api/plugins/injection-shield/`.
- **Frontend**: `desktop/plugin.js` ist eine einzelne ESM-Datei, geladen
  von der Hermes-Desktop-App. Es nutzt `ctx.rest()` für die Kommunikation mit dem Backend.
- **Persistenz**: `POST /config` schreibt Overrides nach
  `~/.hermes/config.yaml` unter `plugins.entries.injection-shield`.
  `config.load_config()` merge diese Overrides beim Plugin-Start.
- **Bundling**: `setup.py` kopiert `desktop/` nach
  `~/.hermes/desktop-plugins/injection-shield-controls/` während
  `pip install` / `pip install -e .`.

### Endpoints

| Methode | Pfad | Zweck |
|--------|------|-------|
| GET | `/api/plugins/injection-shield/config` | Schema + effektive Werte |
| POST | `/api/plugins/injection-shield/config` | Overrides validieren und speichern |
| GET | `/api/plugins/injection-shield/status` | Version, enabled, Modus, letzte Audit |
| POST | `/api/plugins/injection-shield/detector-test` | Synthetischer Detektor-Scan |

### Verifikation

```bash
cd injection-shield-desktop
python3 -m pytest tests/test_dashboard_api.py -v
```

### Hinweise für Workshop-Betreiber

- Das gebundelte UI ist deaktiviert, bis das Paket installiert ist; kein manuelles Kopieren nötig.
- Änderungen werden nach dem nächsten Hermes-Plugin-Reload (oder Neustart) wirksam.
- Telegram-Benachrichtigungen bleiben Opt-in; das UI aktiviert sie nur, wenn eine gültige `chat_id` gesetzt ist.
- Jede Config-Änderung über das UI wird nach `~/.hermes/config.yaml` unter `plugins.entries.injection-shield` geschrieben
  und kann in der regulären Hermes-Config oder im Edit-Audit-Log des Dashboard-Backends eingesehen werden.
- v0.5.0 unterstützt benutzerdefinierte `HERMES_HOME`-Pfade: `~/.hermes` in jedem Config-Pfad
  wird gegen die aktive `HERMES_HOME`-Umgebungsvariable aufgelöst.
  Der CI-Workflow setzt `HERMES_HOME=/tmp/hermes-ci-home`, um dies deterministisch zu halten.

---

## English

# Injection-Shield Desktop Controls

The Desktop-Controls feature (v0.5.0) gives workshop participants and
end-users a graphical pane inside the Hermes Desktop app to tune
Injection-Shield without editing YAML.

## What can be changed

| Setting | Type | Description |
|---------|------|-------------|
| `enabled` | bool | Turn the plugin on/off |
| `mode` | choice | `audit` (log only) / `enforcement` (block) |
| `allowed_domains` | string list | Domains treated as trusted egress |
| `risky_tools` | string list | Tools that trigger extra scrutiny |
| `tool_call_categories` | string list | Enabled tool-call exfil detectors |
| `telegram.enabled` | bool | Telegram alerting opt-in |
| `telegram.chat_id` | int/null | Target Telegram chat id |
| `telegram.min_severity` | choice | `low` / `medium` / `high` / `critical` |
| `audit_log_path` | string | Rotating audit log path |
| `audit_log_max_bytes` | int | Rotation threshold |
| `audit_log_backup_count` | int | Number of backups to keep |
| `audit_log_retention_days` | int | Auto-prune threshold in days |

## Architecture

- **Backend**: `dashboard/plugin_api.py` exports a `fastapi.APIRouter`.
  Hermes mounts it under `/api/plugins/injection-shield/`.
- **Frontend**: `desktop/plugin.js` is a single-file ESM loaded by
  the Hermes Desktop app. It uses `ctx.rest()` to talk to the backend.
- **Persistence**: `POST /config` writes overrides to
  `~/.hermes/config.yaml` under `plugins.entries.injection-shield`.
  `config.load_config()` merges those overrides on plugin startup.
- **Bundling**: `setup.py` copies `desktop/` into
  `~/.hermes/desktop-plugins/injection-shield-controls/` during
  `pip install` / `pip install -e .`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/plugins/injection-shield/config` | Schema + effective values |
| POST | `/api/plugins/injection-shield/config` | Validate and save overrides |
| GET | `/api/plugins/injection-shield/status` | Version, enabled, mode, last audit |
| POST | `/api/plugins/injection-shield/detector-test` | Synthetic detector scan |

## Verification

```bash
cd injection-shield-desktop
python3 -m pytest tests/test_dashboard_api.py -v
```

## Notes for Workshop Operators

- The bundled UI is off until the package is installed; no manual copying
  is required.
- Changes take effect after the next Hermes plugin reload (or restart).
- Telegram alerting remains opt-in; the UI only enables it when a valid
  `chat_id` is set.
- Every config edit performed through the UI is written to
  `~/.hermes/config.yaml` under `plugins.entries.injection-shield` and can be
  reviewed in the regular Hermes config or via the Edit-Audit-Log of the
  dashboard backend.
- v0.5.0 supports custom `HERMES_HOME` paths: `~/.hermes` in any config
  path is resolved against the active `HERMES_HOME` environment variable.
  The CI workflow sets `HERMES_HOME=/tmp/hermes-ci-home` to keep this
  deterministic.
