# injection-shield

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# injection-shield

Prompt-Injection-Abwehr mit Defense-in-Depth für Hermes Agent.

**Version:** 0.8.2 (2026-11-11) — 7 Detektor-Schichten · 480+ Tests · Desktop-Controls-Pane · Telegram-Benachrichtigungen mit Severity-Filter + Rate-Limiting · Sync-Hook-Vertrag (Hermes v0.20.5+)

## Was es tut

`injection-shield` fügt vier Verteidigungsschichten zu jeder Hermes-Runde hinzu:

1. **Schicht 1 — Content Tagging** (`post_tool_call`): Umhüllt Ausgaben von
   `web_extract`, `web_search` und allen `mcp__*`-Tools in
   `<untrusted_tool_result>`-Tags, sodass das LLM sie als Daten behandelt, nicht als Anweisungen.
2. **Schicht 2 — Anti-Injection-Firewall** (`pre_llm_call`): Injiziert eine
   System-Prompt-Firewall, die das Modell daran erinnert, injizierte Direktiven zu ignorieren.
3. **Schicht 3 — Ausgabevalidierung** (`post_llm_call`): Scannt die LLM-Antwort
   auf Credential-Leaks und User-Action-Direktiven; blockiert die Antwort in
   `enforcement`-Modus und sendet Alerts.
4. **Schicht 4 — Risky-Tool-Audit** (`pre_tool_call`): Auditiert/blockiert Aufrufe von
   riskanten Tools (`terminal`, `write_file`), wenn deren Argumente Injection-Patterns enthalten.

## Hooks

- `pre_tool_call`
- `post_tool_call`
- `pre_llm_call`
- `post_llm_call`

## Desktop Controls (v0.5.0)

Injection-Shield liefert ein offizielles Desktop-Plugin, mit dem du Einstellungen
in der Hermes-Desktop-App ändern kannst, statt YAML zu bearbeiten:

- Plugin ein-/ausschalten
- Betriebsmodus wechseln (`audit` / `enforcement`)
- Erlaubte Domains, riskante Tools und Tool-Call-Detektor-Kategorien verwalten
- Telegram-Benachrichtigungen konfigurieren (enabled, Chat-ID, Mindest-Schweregrad)
- Audit-Log-Rotation und -Aufbewahrung anpassen
- Synthetischen Injection-Detektor-Smoke-Test ausführen

Das Desktop-Plugin ist in `desktop/` gebündelt und wird vom Hermes-Plugin-System
selbst installiert (`hermes plugins install` / `hermes plugins enable`) — **kein
Kopieren nach `~/.hermes/desktop-plugins/`**. Das Backend lebt in
`dashboard/plugin_api.py` und wird vom Hermes-Dashboard-Plugin-System unter
`/api/plugins/injection-shield/` gemountet.

Um es zu nutzen, öffne die Hermes-Desktop-App, suche den Bereich **Injection-Shield**
(üblicherweise rechts), und passe die Einstellungen an. Änderungen werden nach
`~/.hermes/config.yaml` unter `plugins.entries.injection-shield` geschrieben
und werden beim nächsten Plugin-Reload wirksam.

## Konfiguration

Füge zu `~/.hermes/config.yaml` (oder einer Profil-config) unter
`plugins.entries.injection-shield` hinzu:

```yaml
plugins:
  enabled:
    - injection-shield
  entries:
    injection-shield:
      enabled: true
      mode: audit              # audit = nur loggen; enforcement = blockieren
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
        enabled: true
        chat_id: YOUR_CHAT_ID_HERE   # Ersetze durch deine Telegram chat_id.
                                       # Niemals eine echte chat_id in die
                                       # committed config schreiben — see
                                       # docs/DSGVO-KONZEPT.md und die
                                       # INJECTION_SHIELD_TELEGRAM_CHAT_ID
                                       # Env-Var.
        min_severity: medium
      audit_log_path: ~/.hermes/profiles/{profile}/workspace/logs/prompt-injection-attempts.log
```

Alle Felder sind optional — das Plugin fällt auf sichere Defaults zurück.

### Modi

- `audit` (Standard): Loggt Verstöße, blockiert nie. Nutze dies für die ersten
  24 Stunden, um False Positives zu finden.
- `enforcement`: Blockiert riskante Tool-Calls und ersetzt verstößende LLM-Ausgaben.

### Erlaubte Domains

Terminal-Ausgaben, die URLs außerhalb der erlaubten Liste enthalten, werden
geloggt und alarmiert. Füge Domains zu `allowed_domains` hinzu, um diese
Alerts zu unterdrücken.

### Telegram-Benachrichtigungen

Setze `TELEGRAM_BOT_TOKEN` im Profil `.env` oder in der Umgebung. Wenn das
Token fehlt, werden Alerts still übergangen — das Plugin stürzt nie ab.

## Installation

### Von GitHub (jede Maschine mit Python ≥3.10)

```bash
pip install git+https://github.com/MOTHR/hermes-injection-shield.git
injection-shield --version
```

### Bearbeitbare Installation für lokale Entwicklung

```bash
git clone https://github.com/MOTHR/hermes-injection-shield.git
cd hermes-injection-shield
pip install -e .
```

## Cross-Plugin-Vertrag

Injection-Shield und [hermes-privacy-shield](https://github.com/MOTHR/hermes-privacy-shield) sind jetzt unabhängige Repositories, teilen aber ein Token-Format-Vertrag.

- Privacy-Shield emittiert Pseudonym-Tokens als `TOKEN_<TYPE>_<10-hex>_<3-digit>`.
- Injection-Shield akzeptiert dieses Format über `_TOKEN_PATTERN` in
  `detectors/injection_patterns.py`.
- Beide Repositories müssen dieses Format gemeinsam upgraden. Die kanonische
  Quelle ist `privacy_shield.TOKEN_FORMAT_PATTERN`.

## Testing

```bash
cd hermes-injection-shield
pytest tests/ -v
```

## False Positives

Wenn legitimer Inhalt markiert wird:

1. Prüfe das Audit-Log auf den exakten Pattern-Match.
2. Füge die Domain oder das Tool zur relevanten Whitelist hinzu.
3. Erwäge, ein bestimmtes riskantes Tool auf audit-only zu setzen,
   indem du `mode: audit` konfigurierst.

## Dokumentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Defense-in-Depth-Schichten, Hooks, Datenfluss, Modullayout
- [`docs/INSTALL.md`](docs/INSTALL.md) — Drei Install-Varianten, Hermes-Config, Telegram-Opt-in, Verifikation
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — Modi, Audit-Log, Daily-Checks, Telegram-Alerts, Performance-Budget
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — False Positives, Bypass-Entdeckung, Plugin-Crash, Log-Wachstum
- [`docs/DSGVO-KONZEPT.md`](docs/DSGVO-KONZEPT.md) — DSGVO Art. 5/25/32-Bewertung, TOMs, AVV, Art. 15/17

## Lizenz

MIT

---

## English

# injection-shield

Prompt-injection defense-in-depth plugin for Hermes Agent.

**Version:** 0.8.2 (2026-11-11) — 7 detector layers · 480+ tests · Desktop-Controls pane · Telegram alerting with severity gate + rate limiting · sync hook contract (Hermes v0.20.5+)

## What it does

`injection-shield` adds four defense layers to every Hermes turn:

1. **Layer 1 — Content tagging** (`post_tool_call`): wraps outputs from
   `web_extract`, `web_search`, and any `mcp__*` tool in
   `<untrusted_tool_result>` tags so the LLM treats them as data, not
   instructions.
2. **Layer 2 — Anti-injection firewall** (`pre_llm_call`): injects a
   system-prompt firewall that reminds the model to ignore injected
   directives.
3. **Layer 3 — Output validation** (`post_llm_call`): scans the LLM response
   for credential leaks and user-action directives; blocks the response in
   `enforcement` mode and alerts.
4. **Layer 4 — Risky-tool audit** (`pre_tool_call`): audits/blockscalls to
   risky tools (`terminal`, `write_file`) when their arguments contain
   injection patterns.

## Hooks

- `pre_tool_call`
- `post_tool_call`
- `pre_llm_call`
- `post_llm_call`

## Desktop Controls (v0.5.0)

Injection-Shield ships an official desktop plugin so you can tune settings in
the Hermes Desktop app instead of editing YAML:

- Enable/disable the plugin
- Switch operating mode (`audit` / `enforcement`)
- Manage allowed domains, risky tools, and tool-call detector categories
- Configure Telegram alerting (enabled, chat id, minimum severity)
- Adjust audit log rotation and retention
- Run a synthetic injection-detector smoke test

The desktop plugin is bundled in `desktop/` and installed by the Hermes plugin
system itself (`hermes plugins install` / `hermes plugins enable`) — **no
copying to `~/.hermes/desktop-plugins/` happens or is needed.** The backend lives in
`dashboard/plugin_api.py` and is mounted by the Hermes dashboard plugin system
at `/api/plugins/injection-shield/`.

To use it, open the Hermes Desktop app, look for the **Injection-Shield** pane
(usually on the right), and adjust the controls. Changes are written to
`~/.hermes/config.yaml` under `plugins.entries.injection-shield` and take effect
on the next plugin reload.

## Configuration

Add to `~/.hermes/config.yaml` (or any profile config) under
`plugins.entries.injection-shield`:

```yaml
plugins:
  enabled:
    - injection-shield
  entries:
    injection-shield:
      enabled: true
      mode: audit              # audit = log only; enforcement = block
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
        enabled: true
        chat_id: YOUR_CHAT_ID_HERE   # Replace with your Telegram chat_id.
                                       # NEVER use a real chat_id in the
                                       # committed config — see
                                       # docs/DSGVO-KONZEPT.md and the
                                       # INJECTION_SHIELD_TELEGRAM_CHAT_ID
                                       # env-var.
        min_severity: medium
      audit_log_path: ~/.hermes/profiles/{profile}/workspace/logs/prompt-injection-attempts.log
```

All fields are optional — the plugin falls back to safe defaults.

### Modes

- `audit` (default): logs violations, never blocks. Use this for the first
  24 hours to find false positives.
- `enforcement`: blocks risky tool calls and replaces violating LLM outputs.

### Allowed domains

Terminal outputs that contain URLs outside the allowed list are logged and
alerted. Add domains to `allowed_domains` to suppress these alerts.

### Telegram alerts

Set `TELEGRAM_BOT_TOKEN` in the profile `.env` or environment. If the token is
missing, alerts are silently skipped — the plugin never crashes.

## Installation

### From GitHub (any machine with Python ≥3.10)

```bash
pip install git+https://github.com/MOTHR/hermes-injection-shield.git
injection-shield --version
```

### Editable install for local development

```bash
git clone https://github.com/MOTHR/hermes-injection-shield.git
cd hermes-injection-shield
pip install -e .
```

## Cross-Plugin Contract

Injection-Shield and [hermes-privacy-shield](https://github.com/MOTHR/hermes-privacy-shield) are now independent repositories, but they share a token-format contract.

- Privacy-Shield emits pseudonym tokens as `TOKEN_<TYPE>_<10-hex>_<3-digit>`.
- Injection-Shield accepts this format via `_TOKEN_PATTERN` in
  `detectors/injection_patterns.py`.
- Both repositories must upgrade this format together. The canonical
  source-of-truth is `privacy_shield.TOKEN_FORMAT_PATTERN`.

## Testing

```bash
cd hermes-injection-shield
pytest tests/ -v
```

## False positives

If legitimate content is flagged:

1. Check the audit log for the exact pattern match.
2. Add the domain or tool to the relevant whitelist.
3. Consider switching a specific risky tool to audit-only by setting
   `mode: audit`.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Defense-in-depth layers, hooks, data flow, module layout
- [`docs/INSTALL.md`](docs/INSTALL.md) — Three install variants, Hermes config, Telegram opt-in, verification
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — Modes, audit-log, daily checks, Telegram alerts, performance budget
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — False positives, bypass discovery, plugin crash, log growth
- [`docs/DSGVO-KONZEPT.md`](docs/DSGVO-KONZEPT.md) — GDPR Art. 5/25/32 evaluation, TOMs, AVV, Art. 15/17
- [`TOKEN_BIC_aadf003511_004.md`](TOKEN_BIC_aadf003511_004.md) — Security policy: what the plugin does/reads/writes, network egress, credentials

## License

MIT (see [LICENSE](LICENSE))
