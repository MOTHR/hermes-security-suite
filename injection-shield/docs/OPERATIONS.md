# Operations

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# Betrieb

## Modi

`injection-shield` läuft in drei Modi, gesteuert über
`plugins.entries.injection-shield.mode` in `config.yaml`:

| Mode         | Verhalten                                                          | Use-Case                                |
|--------------|--------------------------------------------------------------------|-----------------------------------------|
| `audit`      | Alle Hooks laufen, jede Erkennung wird geloggt — nichts blockiert  | Erste 24h nach Aktivierung, Tests       |
| `enforcement`| Risky-Tool-Calls mit Pattern-Match werden geblockt; LLM-Output mit Pattern-Match wird ersetzt | Production nach Tuning-Phase |
| `off`        | Plugin komplett deaktiviert (kein Hook-Overhead)                   | Debugging, Performance-Probleme         |

**Default ist `audit`** — das Plugin ist also "sicher bei Erstinstallation".
Wir empfehlen mindestens 24h `audit`-Phase, bevor auf `enforcement`
umgeschaltet wird. So lassen sich False-Positives sammeln, ohne dass echte
Workflows blockiert werden.

### Modus wechseln

```bash
# temporär (eine Hermes-Session)
hermes config set plugins.entries.injection-shield.mode enforcement

# dauerhaft in config.yaml
plugins:
  entries:
    injection-shield:
      mode: enforcement
```

## Audit-Log

Pfad (siehe `config.py::DEFAULT_CONFIG`):

```
~/.hermes/profiles/<profile>/workspace/logs/prompt-injection-attempts.log
```

Eintrag-Format (JSONL — eine Zeile pro Event):

```json
{"ts": "2026-08-22T01:23:45Z", "hook": "pre_tool_call", "tool": "terminal",
 "type": "instruction_override", "severity": "high",
 "match_len": 38, "session_hash": "sha256:9a1b…", "redacted": true}
```

- `match_len` — Länge des erkannten Patterns in Zeichen (kein Klartext — DSGVO Art. 5(1)(c) Datenminimierung)
- `session_hash` — salted SHA-256 des Session-Keys; nicht rückführbar
- `redacted: true` — der Match-Text wurde vor dem Loggen ersetzt

### Rotation & Retention

Konfiguriert in `config.py`:

| Setting                       | Default  | Zweck                                |
|-------------------------------|----------|--------------------------------------|
| `audit_log_max_bytes`         | 10 MiB   | Rotations-Schwelle pro Datei         |
| `audit_log_backup_count`      | 5        | Wie viele `.log.1`–`.log.5` behalten |
| `audit_log_retention_days`    | 90       | Auto-Prune älterer Einträge (DSGVO)  |

Implementiert via `logging.handlers.RotatingFileHandler` + Atomic-Prune
(`tempfile.mkstemp` + `os.replace`, siehe `FIX-2C`).

Worst-case Plattenverbrauch: 60 MiB pro Profil (10 MiB × (1 + 5 Backups)).

## Daily-Checks

Empfohlen als Cron-Job oder in einem Watchdog-Script:

```bash
#!/usr/bin/env bash
# ~/.hermes/scripts/injection-shield-daily.sh

PROFILE="${1:-default}"
LOG_DIR="$HOME/.hermes/profiles/$PROFILE/workspace/logs"

# 1. Log-Größe prüfen
du -sh "$LOG_DIR/prompt-injection-attempts.log"* 2>/dev/null

# 2. Anzahl Violations letzte 24h
SINCE="$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
tail -1000 "$LOG_DIR/prompt-injection-attempts.log" \
  | grep -c "\"ts\":\"$SINCE" \
  || true

# 3. Severity-Verteilung
tail -5000 "$LOG_DIR/prompt-injection-attempts.log" \
  | python3 -c "import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try: c[json.loads(line).get('severity', '?')] += 1
    except Exception: pass
for sev, n in sorted(c.items()): print(f'{sev}: {n}')"
```

## Telegram-Alerts (optional, opt-in)

Default **deaktiviert** (FIX-1D / DSGVO Art. 25 "Privacy by Default").

### Aktivieren via Env-Var

```bash
# in ~/.zshrc oder systemd EnvironmentFile
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF…"
export INJECTION_SHIELD_TELEGRAM_CHAT_ID="YOUR_CHAT_ID"
```

### Aktivieren via config.yaml

```yaml
plugins:
  entries:
    injection-shield:
      telegram:
        enabled: true
        chat_id: YOUR_CHAT_ID
        min_severity: medium   # low | medium | high | critical
```

**Hierarchie**: Env-Var > `config.yaml` > Default (off).
Wenn weder Env-Var noch chat_id gesetzt sind → `enabled` wird intern auf
`false` gezwungen, egal was in der YAML steht. So kann ein versehentlich
gecheckter `enabled: true` keinen versehentlichen Alert auslösen.

### Alert-Format

```
🚨 injection-shield: high severity
Hook: post_llm_call
Type: credential_leak
Severity: high
Time: 2026-08-22T01:23:45Z
Profile: default
```

Kein Klartext-Match, kein Session-Key — nur Metadaten.

## Risky-Tools

Default-Liste (`config.py::DEFAULT_CONFIG`):

```python
"risky_tools": ["terminal", "write_file"]
```

Diese Tools werden in `pre_tool_call` auditiert. Du kannst die Liste erweitern
(`browser_exec`, `execute_code` etc.), aber **sei konservativ** — je mehr
Tools auditiert werden, desto höher der Hook-Overhead pro Turn.

## Performance-Budget

| Hook              | Typische Latenz | Worst-Case |
|-------------------|-----------------|------------|
| `pre_tool_call`   | <1 ms           | 50 ms (Regex-Backtrack auf adversarial input) |
| `post_tool_call`  | <1 ms           | 10 ms |
| `pre_llm_call`    | <2 ms           | 20 ms (Zero-Width-Scan auf langem Input) |
| `post_llm_call`   | 1–5 ms          | 50 ms |

Insgesamt also <15 ms zusätzlich pro Turn im Normalbetrieb — vernachlässigbar
gegenüber der LLM-Latenz.

## Incident-Response

Bei Verdacht auf einen Bypass siehe `TROUBLESHOOTING.md` → "Bypass entdeckt".

Bei einem Plugin-Crash (kein Response vom LLM):
1. Modus auf `off` setzen
2. Tail der letzten Audit-Log-Einträge lesen
3. Issue im Tracker mit Hook-Name + letztem Event anlegen

---

## English

# Operations

## Modes

`injection-shield` runs in three modes, controlled via
`plugins.entries.injection-shield.mode` in `config.yaml`:

| Mode         | Behavior                                                          | Use Case                                |
|--------------|--------------------------------------------------------------------|-----------------------------------------|
| `audit`      | All hooks run, every detection is logged — nothing blocked          | First 24h after activation, tests       |
| `enforcement`| Risky tool calls with pattern match are blocked; LLM output with pattern match is replaced | Production after tuning phase |
| `off`        | Plugin completely disabled (no hook overhead)                      | Debugging, performance issues           |

**Default is `audit`** — the plugin is "safe on first install".
We recommend at least 24h in `audit` mode before switching to `enforcement`
to collect false positives without blocking real workflows.

### Switching modes

```bash
# temporarily (one Hermes session)
hermes config set plugins.entries.injection-shield.mode enforcement

# permanently in config.yaml
plugins:
  entries:
    injection-shield:
      mode: enforcement
```

## Audit Log

Path (see `config.py::DEFAULT_CONFIG`):

```
~/.hermes/profiles/<profile>/workspace/logs/prompt-injection-attempts.log
```

Entry format (JSONL — one line per event):

```json
{"ts": "2026-08-22T01:23:45Z", "hook": "pre_tool_call", "tool": "terminal",
 "type": "instruction_override", "severity": "high",
 "match_len": 38, "session_hash": "sha256:9a1b…", "redacted": true}
```

- `match_len` — length of the detected pattern in characters (no cleartext — GDPR Art. 5(1)(c) data minimization)
- `session_hash` — salted SHA-256 of the session key; not traceable
- `redacted: true` — the match text was replaced before logging

### Rotation & Retention

Configured in `config.py`:

| Setting                       | Default  | Purpose                                 |
|-------------------------------|----------|------------------------------------------|
| `audit_log_max_bytes`         | 10 MiB   | Rotation threshold per file             |
| `audit_log_backup_count`      | 5        | How many `.log.1`–`.log.5` to keep     |
| `audit_log_retention_days`    | 90       | Auto-prune of older entries (GDPR)       |

Implemented via `logging.handlers.RotatingFileHandler` + atomic prune
(`tempfile.mkstemp` + `os.replace`, see `FIX-2C`).

Worst-case disk usage: 60 MiB per profile (10 MiB × (1 + 5 backups)).

## Daily Checks

Recommended as a cron job or in a watchdog script:

```bash
#!/usr/bin/env bash
# ~/.hermes/scripts/injection-shield-daily.sh

PROFILE="${1:-default}"
LOG_DIR="$HOME/.hermes/profiles/$PROFILE/workspace/logs"

# 1. Check log size
du -sh "$LOG_DIR/prompt-injection-attempts.log"* 2>/dev/null

# 2. Number of violations last 24h
SINCE="$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
tail -1000 "$LOG_DIR/prompt-injection-attempts.log" \
  | grep -c "\"ts\":\"$SINCE" \
  || true

# 3. Severity distribution
tail -5000 "$LOG_DIR/prompt-injection-attempts.log" \
  | python3 -c "import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try: c[json.loads(line).get('severity', '?')] += 1
    except Exception: pass
for sev, n in sorted(c.items()): print(f'{sev}: {n}')"
```

## Telegram Alerts (optional, opt-in)

Default **disabled** (FIX-1D / GDPR Art. 25 "Privacy by Default").

### Enable via env var

```bash
# in ~/.zshrc or systemd EnvironmentFile
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF…"
export INJECTION_SHIELD_TELEGRAM_CHAT_ID="YOUR_CHAT_ID"
```

### Enable via config.yaml

```yaml
plugins:
  entries:
    injection-shield:
      telegram:
        enabled: true
        chat_id: YOUR_CHAT_ID
        min_severity: medium   # low | medium | high | critical
```

**Hierarchy**: env var > `config.yaml` > default (off).
If neither env var nor chat_id is set → `enabled` is internally forced to
`false`, regardless of what the YAML says. This way, an accidentally checked
`enabled: true` cannot trigger an accidental alert.

### Alert Format

```
🚨 injection-shield: high severity
Hook: post_llm_call
Type: credential_leak
Severity: high
Time: 2026-08-22T01:23:45Z
Profile: default
```

No cleartext match, no session key — metadata only.

## Risky Tools

Default list (`config.py::DEFAULT_CONFIG`):

```python
"risky_tools": ["terminal", "write_file"]
```

These tools are audited in `pre_tool_call`. You can extend the list
(`browser_exec`, `execute_code` etc.), but **be conservative** — the more
tools audited, the higher the hook overhead per turn.

## Performance Budget

| Hook              | Typical Latency | Worst Case |
|-------------------|-----------------|------------|
| `pre_tool_call`   | <1 ms           | 50 ms (regex backtrack on adversarial input) |
| `post_tool_call`  | <1 ms           | 10 ms |
| `pre_llm_call`    | <2 ms           | 20 ms (zero-width scan on long input) |
| `post_llm_call`   | 1–5 ms          | 50 ms |

So in total <15 ms added per turn in normal operation — negligible
compared to LLM latency.

## Incident Response

If you suspect a bypass, see `TROUBLESHOOTING.md` → "Bypass discovered".

If the plugin crashes (no response from LLM):
1. Set mode to `off`
2. Read the tail of the last audit log entries
3. Open an issue in the tracker with hook name + last event
