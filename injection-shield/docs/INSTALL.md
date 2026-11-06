# Installation

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# Installation

## Voraussetzungen

- **Python 3.10+** (verwendet PEP-604 Union-Syntax `X | None`)
- **Hermes Agent** (`~/.hermes/`) — installiert und mindestens ein Profil vorhanden
- **Optional**: `pyyaml` (bereits von Hermes Core benötigt, daher meist vorhanden)
- **Optional** für Telegram-Benachrichtigungen:
  - ein Telegram-Bot-Token (setze `TELEGRAM_BOT_TOKEN` in der Profil-`.env`)
  - `INJECTION_SHIELD_TELEGRAM_CHAT_ID` Env-Var mit der Ziel-Chat-ID

## Installation

### Variante 1 — Manuelle Installation (empfohlen für Workshop-Setups)

```bash
git clone https://github.com/MOTHR/hermes-injection-shield.git ~/.hermes/plugins/injection-shield
cd ~/.hermes/plugins/injection-shield
pip install -e .
```

`pip install -e .` macht das Paket im Hermes-Python-Path importierbar
(`from injection_shield import InjectionShieldPlugin`) **und kopiert das
Desktop-Plugin nach `~/.hermes/desktop-plugins/injection-shield-controls/`**,
damit die Hermes Desktop App die grafischen Controls anzeigt.

### Variante 2 — Git-URL direkt

```bash
pip install git+https://github.com/MOTHR/hermes-injection-shield.git@v0.5.3
```

Anschließend muss das Plugin-Verzeichnis trotzdem unter
`~/.hermes/plugins/injection-shield/` liegen, weil Hermes es über das
Filesystem lädt — nicht nur über den Python-Import. Nach der
`pip install`-Variante also:

```bash
mkdir -p ~/.hermes/plugins
ln -s $(python -c "import injection_shield, os; print(os.path.dirname(injection_shield.__file__))") \
      ~/.hermes/plugins/injection-shield
```

> **HERMES_HOME-Support (v0.5.0):** Alle Pfade in der Config können
> `~/.hermes` als Alias für den aktuellen `HERMES_HOME`-Pfad verwenden.
> Der Operator-Hermes-Home-Support ist in v0.5.0 eingebaut und wird im
> CI-Workflow mit `HERMES_HOME=/tmp/hermes-ci-home` getestet.

### Variante 3 — Dev-Worktree

Für aktive Entwicklung am Plugin selbst (im selben Repo wie Hermes):

```bash
cd ~/.hermes/plugins/injection-shield
pip install -e .[dev]
```

## Hermes-Integration

### 1. Plugin in `config.yaml` aktivieren

Trage das Plugin in `~/.hermes/config.yaml` (oder einer
Profile-`config.yaml`) unter `plugins.enabled` ein:

```yaml
plugins:
  enabled:
    - injection-shield
  entries:
    injection-shield:
      enabled: true
      mode: audit              # erst audit, später ggf. enforcement
      allowed_domains:
        - api.openai.com
        - api.anthropic.com
        - api.x.ai
        - ollama.com
        - hermes-agent.nousresearch.com
        - api.telegram.org
      risky_tools:
        - terminal
        - write_file
      telegram:
        enabled: false         # FIX-1D: default off — opt-in per Env-Var
        chat_id: null
        min_severity: medium
      audit_log_path: ~/.hermes/profiles/{profile}/workspace/logs/prompt-injection-attempts.log
      audit_log_max_bytes: 10485760   # 10 MiB
      audit_log_backup_count: 5
      audit_log_retention_days: 90
```

### 2. Optional: Plugin in mehrere Profile symlinken

```bash
for profile in <profile1> <profile2>; do  # list your profiles
  mkdir -p ~/.hermes/profiles/$profile/plugins/
  ln -sf ~/.hermes/plugins/injection-shield ~/.hermes/profiles/$profile/plugins/injection-shield
done
```

### 3. Telegram-Alerts aktivieren (nur wenn gewünscht — DSGVO Art. 25)

```bash
# ~/.hermes/profiles/<profile>/.env
export TELEGRAM_BOT_TOKEN=...                  # dein Bot-Token
export INJECTION_SHIELD_TELEGRAM_CHAT_ID=...   # Ziel-Chat-ID
```

Lieber in `~/.zshrc` oder einem systemd-EnvironmentFile setzen — niemals ins
Repo committen.

## Verifikation

### Plugin-Sichtbarkeit prüfen

```bash
hermes plugins list | grep injection
```

Erwartete Ausgabe: `injection-shield (enabled)` (oder `(installed)` falls
nicht aktiviert).

### Import-Test

```bash
~/.hermes/hermes-agent/venv/bin/python -c \
  "from injection_shield import InjectionShieldPlugin; print(InjectionShieldPlugin)"
```

### Test-Suite

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q
```

Erwartet: ~410 passed, 0 failed (Stand v0.5.3).

### Live-Hook-Test

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python live_tests.py
```

Das Skript sendet synthetische Tool-Args an die Hooks und prüft, ob das
Audit-Log korrekt beschrieben wird.

## Update

```bash
cd ~/.hermes/plugins/injection-shield
git pull
pip install -e .
```

Kein Restart von Hermes nötig — die Hooks werden pro Turn geladen.

## Deinstallation

```bash
# 1. Plugin entfernen (entfernt auch den config.yaml-Eintrag + Enabled-Status)
hermes plugins remove injection-shield

# 2. Profil-Symlinks entfernen
for profile in <profile1> <profile2>; do  # list your profiles
  rm -f ~/.hermes/profiles/$profile/plugins/injection-shield
done

# 3. Audit-Log entfernen (optional)
rm ~/.hermes/profiles/*/workspace/logs/prompt-injection-attempts.log*
```

## Nächste Schritte

- `OPERATIONS.md` für den Alltagsbetrieb (Modi, Daily-Checks, Alerts)
- `TROUBLESHOOTING.md` für typische Probleme
- `DSGVO-KONZEPT.md` für die datenschutzrechtliche Bewertung

---

## English

# Installation

## Prerequisites

- **Python 3.10+** (uses PEP-604 union syntax `X | None`)
- **Hermes Agent** (`~/.hermes/`) — installed and at least one profile exists
- **Optional**: `pyyaml` (already required by Hermes core, so usually present)
- **Optional** for Telegram alerts:
  - a Telegram bot token (set `TELEGRAM_BOT_TOKEN` in the profile `.env`)
  - `INJECTION_SHIELD_TELEGRAM_CHAT_ID` env var with the destination chat id

## Installation

### Variant 1 — Manual Installation (recommended for workshop setups)

```bash
git clone https://github.com/MOTHR/hermes-injection-shield.git ~/.hermes/plugins/injection-shield
cd ~/.hermes/plugins/injection-shield
pip install -e .
```

`pip install -e .` makes the package importable in Hermes's Python path
(`from injection_shield import InjectionShieldPlugin`) **and copies the
desktop plugin to `~/.hermes/desktop-plugins/injection-shield-controls/`**,
so that the Hermes Desktop app displays the graphical controls.

### Variant 2 — Direct Git URL

```bash
pip install git+https://github.com/MOTHR/hermes-injection-shield.git@v0.5.3
```

Afterward, the plugin directory must still be located under
`~/.hermes/plugins/injection-shield/` because Hermes loads it from the
filesystem — not just via the Python import. So after the `pip install`
variant:

```bash
mkdir -p ~/.hermes/plugins
ln -s $(python -c "import injection_shield, os; print(os.path.dirname(injection_shield.__file__))") \
      ~/.hermes/plugins/injection-shield
```

> **HERMES_HOME support (v0.5.0):** All paths in the config can use
> `~/.hermes` as an alias for the current `HERMES_HOME` path.
> Operator Hermes home support is built into v0.5.0 and is tested in the
> CI workflow with `HERMES_HOME=/tmp/hermes-ci-home` to keep it deterministic.

### Variant 3 — Dev Worktree

For active development on the plugin itself (in the same repo as Hermes):

```bash
cd ~/.hermes/plugins/injection-shield
pip install -e .[dev]
```

## Hermes Integration

### 1. Enable the plugin in `config.yaml`

Add the plugin to `~/.hermes/config.yaml` (or a profile `config.yaml`) under
`plugins.enabled`:

```yaml
plugins:
  enabled:
    - injection-shield
  entries:
    injection-shield:
      enabled: true
      mode: audit              # start with audit, switch to enforcement later
      allowed_domains:
        - api.openai.com
        - api.anthropic.com
        - api.x.ai
        - ollama.com
        - hermes-agent.nousresearch.com
        - api.telegram.org
      risky_tools:
        - terminal
        - write_file
      telegram:
        enabled: false         # FIX-1D: default off — opt-in via env var
        chat_id: null
        min_severity: medium
      audit_log_path: ~/.hermes/profiles/{profile}/workspace/logs/prompt-injection-attempts.log
      audit_log_max_bytes: 10485760   # 10 MiB
      audit_log_backup_count: 5
      audit_log_retention_days: 90
```

### 2. Optional: Symlink plugin into multiple profiles

```bash
for profile in <profile1> <profile2>; do  # list your profiles
  mkdir -p ~/.hermes/profiles/$profile/plugins/
  ln -sf ~/.hermes/plugins/injection-shield ~/.hermes/profiles/$profile/plugins/injection-shield
done
```

### 3. Activate Telegram Alerts (only if desired — GDPR Art. 25)

```bash
# ~/.hermes/profiles/<profile>/.env
export TELEGRAM_BOT_TOKEN=...                  # your bot token
export INJECTION_SHIELD_TELEGRAM_CHAT_ID=...   # destination chat ID
```

Better to set this in `~/.zshrc` or a systemd EnvironmentFile — never
commit to the repo.

## Verification

### Check plugin visibility

```bash
hermes plugins list | grep injection
```

Expected output: `injection-shield (enabled)` (or `(installed)` if
not enabled).

### Import test

```bash
~/.hermes/hermes-agent/venv/bin/python -c \
  "from injection_shield import InjectionShieldPlugin; print(InjectionShieldPlugin)"
```

### Test suite

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q
```

Expected: ~410 passed, 0 failed (as of v0.5.3).

### Live hook test

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python live_tests.py
```

The script sends synthetic tool args to the hooks and verifies the audit log
is written correctly.

## Update

```bash
cd ~/.hermes/plugins/injection-shield
git pull
pip install -e .
```

No Hermes restart needed — hooks are loaded per turn.

## Uninstallation

```bash
# 1. Remove the plugin (also removes the config.yaml entry + enabled state)
hermes plugins remove injection-shield

# 2. Remove profile symlinks
for profile in <profile1> <profile2>; do  # list your profiles
  rm -f ~/.hermes/profiles/$profile/plugins/injection-shield
done

# 3. Remove the audit log (optional)
rm ~/.hermes/profiles/*/workspace/logs/prompt-injection-attempts.log*
```

## Next Steps

- `OPERATIONS.md` for day-to-day operations (modes, daily checks, alerts)
- `TROUBLESHOOTING.md` for common problems
- `DSGVO-KONZEPT.md` for the data protection assessment
