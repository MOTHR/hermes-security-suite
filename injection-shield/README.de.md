🌐 [Deutsch](README.de.md) | English

# injection-shield

Prompt-Injection-Abwehr mit Defense-in-Depth für Hermes Agent.

**Version:** 0.6.0 (2026-09-21) — 7 Detektor-Schichten · 410+ Tests · Desktop-Controls-Pane · Telegram-Benachrichtigungen mit Severity-Filter + Rate-Limiting · Sync-Hook-Vertrag (Hermes v0.20.5+)

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

Das Desktop-Plugin ist in `desktop/` gebündelt und wird automatisch nach
`~/.hermes/desktop-plugins/injection-shield-controls/` kopiert, wenn das Paket
installiert wird (`pip install` oder `pip install -e .  # in der Monorepo-Paketwurzel ausgefuehrt`). Das Backend lebt in
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
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
injection-shield --version
```

### Bearbeitbare Installation für lokale Entwicklung

```bash
git clone https://github.com/MOTHR/hermes-security-suite.git
cd hermes-security-suite/injection-shield
pip install -e .  # in der Monorepo-Paketwurzel ausgefuehrt
```

## Cross-Plugin-Vertrag

Injection-Shield und [privacy-shield (Suite-Monorepo)](https://github.com/MOTHR/hermes-security-suite) sind jetzt unabhängige Repositories, teilen aber ein Token-Format-Vertrag.

- Privacy-Shield emittiert Pseudonym-Tokens als `TOKEN_<TYPE>_<10-hex>_<3-digit>`.
- Injection-Shield akzeptiert dieses Format über `_TOKEN_PATTERN` in
  `detectors/injection_patterns.py`.
- Beide Repositories müssen dieses Format gemeinsam upgraden. Die kanonische
  Quelle ist `privacy_shield.TOKEN_FORMAT_PATTERN`.

## Testing

```bash
cd hermes-security-suite/injection-shield
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
