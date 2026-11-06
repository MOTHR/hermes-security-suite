# Privacy-Shield Desktop Controls

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield Desktop Controls

Die Desktop-Controls-Funktion (v1.5.0) gibt Workshop-Teilnehmern und
Endanwendern eine grafische Oberfläche in der Hermes Desktop App,
mit der sich Privacy-Shield anpassen lässt, ohne YAML zu bearbeiten.

## Was kann geändert werden

| Setting | Typ | Beschreibung |
|---------|------|-------------|
| `enabled` | bool | Plugin ein-/ausschalten |
| `mode` | choice | `off` / `audit` / `limited` / `strict` / `paranoid` |
| `detection_engine` | choice | `regex` / `ner` / `hybrid` |
| `confidence_threshold` | float 0..1 | Mindest-Konfidenz für Auto-Masking |
| `restore_allowed_channels` | string list | Kanäle, in denen Tokens zurückgespielt werden (z. B. `telegram:123`) |
| `token_style` | choice | `deterministic` / `random` |
| `token_prefix` | string | Token-Präfix des Pseudonymizers |
| `storage_mode` | choice | `memory` / `disk` |
| `cache_bypass` | bool | Shielding für vault-lokalen Tool-Output überspringen |
| `pdf_enabled` | bool | PDF-Preprocessing aktivieren |
| `image_enabled` | bool | Bild-OCR aktivieren |
| `ocr_lang` | string | Tesseract-Sprachpakete |
| `audit_log_path` | string | Pfad des rotierenden Operator-Logs |
| `audit_log_retention_days` | int | Auto-Prune-Schwelle in Tagen |

## Architektur

- **Backend**: `dashboard/plugin_api.py` exportiert einen `fastapi.APIRouter`.
  Hermes bindet ihn unter `/api/plugins/privacy-shield/` ein.
- **Frontend**: `desktop/plugin.js` ist ein Single-File-ESM, das die
  Hermes Desktop App lädt. Es kommuniziert über `ctx.rest()` mit dem Backend.
- **Persistenz**: `POST /config` schreibt Overrides in
  `~/.hermes/config.yaml` unter `plugins.entries.privacy-shield`.
  `config.load_config()` merged diese Overrides beim Plugin-Start.
- **Bundling**: `setup.py` kopiert `desktop/` während
  `pip install` / `pip install -e .` nach
  `~/.hermes/desktop-plugins/privacy-shield-controls/`.

## Endpunkte

| Methode | Pfad | Zweck |
|--------|------|---------|
| GET | `/api/plugins/privacy-shield/config` | Schema + effektive Werte |
| POST | `/api/plugins/privacy-shield/config` | Overrides validieren und speichern |
| GET | `/api/plugins/privacy-shield/status` | Version, enabled, mode, letzter Audit |
| POST | `/api/plugins/privacy-shield/restore-test` | Synthetischer PII-Round-Trip-Test |

---

## English

# Privacy-Shield Desktop Controls

The Desktop-Controls feature (v1.5.0) gives workshop participants and
end-users a graphical pane inside the Hermes Desktop app to tune
Privacy-Shield without editing YAML.

## What can be changed

| Setting | Type | Description |
|---------|------|-------------|
| `enabled` | bool | Turn the plugin on/off |
| `mode` | choice | `off` / `audit` / `limited` / `strict` / `paranoid` |
| `detection_engine` | choice | `regex` / `ner` / `hybrid` |
| `confidence_threshold` | float 0..1 | Minimum confidence for auto-masking |
| `restore_allowed_channels` | string list | Channels where tokens are restored (e.g. `telegram:123`) |
| `token_style` | choice | `deterministic` / `random` |
| `token_prefix` | string | Token prefix used by the pseudonymizer |
| `storage_mode` | choice | `memory` / `disk` |
| `cache_bypass` | bool | Skip shielding for vault-local tool outputs |
| `pdf_enabled` | bool | Enable PDF preprocessing |
| `image_enabled` | bool | Enable image OCR |
| `ocr_lang` | string | Tesseract language packs |
| `audit_log_path` | string | Operator rotating log path |
| `audit_log_retention_days` | int | Auto-prune threshold in days |

## Architecture

- **Backend**: `dashboard/plugin_api.py` exports a `fastapi.APIRouter`.
  Hermes mounts it under `/api/plugins/privacy-shield/`.
- **Frontend**: `desktop/plugin.js` is a single-file ESM loaded by
  the Hermes Desktop app. It uses `ctx.rest()` to talk to the backend.
- **Persistence**: `POST /config` writes overrides to
  `~/.hermes/config.yaml` under `plugins.entries.privacy-shield`.
  `config.load_config()` merges those overrides on plugin startup.
- **Bundling**: `setup.py` copies `desktop/` into
  `~/.hermes/desktop-plugins/privacy-shield-controls/` during
  `pip install` / `pip install -e .`.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/plugins/privacy-shield/config` | Schema + effective values |
| POST | `/api/plugins/privacy-shield/config` | Validate and save overrides |
| GET | `/api/plugins/privacy-shield/status` | Version, enabled, mode, last audit |
| POST | `/api/plugins/privacy-shield/restore-test` | Synthetic PII round-trip test |

## Verification

```bash
cd privacy-shield-desktop
python3 -m pytest tests/test_dashboard_api.py -v
```

## Notes for Workshop Operators

- The bundled UI is off until the package is installed; no manual copying
  is required.
- Changes take effect after the next Hermes plugin reload (or restart).
- No real PII is used in the restore smoke test; the sample text contains
  synthetic data only.
