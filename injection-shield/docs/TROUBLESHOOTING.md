# Troubleshooting

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# Fehlerbehebung

## False-Positive-Welle

**Symptom:** Viele legitime Tool-Calls oder LLM-Antworten werden als
Injection geflaggt; Audit-Log füllt sich rapide.

**Diagnose:**

```bash
# Verteilung der Pattern-Typen
tail -500 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log \
  | python3 -c "import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try: c[json.loads(line).get('type', '?')] += 1
    except Exception: pass
for t, n in sorted(c.items(), key=lambda x: -x[1]): print(f'{t}: {n}')"
```

**Lösung:**

1. **Sofort:** Modus auf `audit` setzen — `enforcement` würde Tool-Calls jetzt
   blockieren:
   ```bash
   hermes config set plugins.entries.injection-shield.mode audit
   ```
2. **Mittelfristig:** Welcher Pattern-Typ dominiert?
   - `instruction_override` → see `firewall_text` in `config.py` —
     Patterns ggf. enger fassen.
   - `credential_leak` → in `plugins.entries.injection-shield.credential_allowlist`
     legitime Werte whitelisten.
   - `zero_width` → betrifft oft kopierter Text aus PDFs/Web — Hinweis an
     User, dass das Verhalten korrekt ist.
3. **Langfristig:** Modus nach Tuning auf `enforcement` zurücksetzen.

## Bypass entdeckt

**Symptom:** Im Output des LLM tauchen klar verdächtige Konstrukte auf:
klassische Override-Formulierungen, Base64-URL-Payloads, Variation-Selector-Stego —
obwohl das Plugin aktiv ist.

**Sofort-Maßnahmen:**

1. **Modus auf `audit` setzen** — verhindert weitere Schäden, ohne den
   normalen Workflow zu unterbrechen:
   ```bash
   hermes config set plugins.entries.injection-shield.mode audit
   ```
2. **Audit-Log sichern** (Forensik, vor Auto-Prune):
   ```bash
   cp ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log* \
      ~/Desktop/injection-shield-evidence-$(date +%Y%m%d).log
   ```
3. **Plugin-Version notieren** (für Issue-Tracker):
   ```bash
   pip show injection-shield | grep -E '^(Name|Version|Location):'
   ```
4. **Issue anlegen** im Tracker mit:
   - Exaktem Bypass-Payload (in Code-Block, **nicht ausführen**)
   - Audit-Log-Auszug
   - Repro-Steps (welches Tool, welcher Hook)
5. **Workaround**: Bypass-Pattern in `firewall_text` (siehe
   `detectors/injection_patterns.py`) manuell ergänzen, bis ein offizielles
   Release den Fix bringt.

## Plugin-Crash

**Symptom:** LLM-Calls brechen ab oder das Plugin wirft Tracebacks in den
Hermes-Logs (`~/.hermes/profiles/<profile>/workspace/logs/hermes.log`).

**Diagnose:**

```bash
# 1. Letzte Audit-Events auf Fehler prüfen
tail -200 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log \
  | grep -iE '(error|traceback|exception)' || echo "OK — keine Fehler im Audit-Log"

# 2. Hermes-Log
tail -200 ~/.hermes/profiles/default/workspace/logs/hermes.log \
  | grep -iE '(injection.shield|detector)' | tail -20

# 3. Plugin-Status
hermes plugins info injection-shield
```

**Lösung:**

1. **Update** auf neueste Version:
   ```bash
   cd ~/.hermes/plugins/injection-shield
   git pull
   pip install -e .
   ```
2. **Workaround** bis Update: Plugin deaktivieren:
   ```bash
   hermes plugins disable injection-shield
   ```
   Oder Modus auf `off` setzen (kein Hook-Overhead, aber Plugin bleibt geladen).
3. **Detector-Isolation**: Die `DetectorChain` wrappt jeden Detector in einen
   try/except — einzelne Layer können ausfallen, ohne dass das gesamte
   Shield crasht. Prüfe, ob nur ein spezifischer Hook betroffen ist.

## Log-Datei wächst unkontrolliert

**Symptom:** `prompt-injection-attempts.log` > 100 MiB.

**Diagnose:**

```bash
ls -lh ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log*
```

**Lösung:**

1. **Prüfe Rotation**: Sind die Backups da?
   ```bash
   ls -1 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log* \
     | wc -l
   ```
   Bei `audit_log_backup_count: 5` sollten max. 6 Dateien da sein.
2. **Retention prüfen**: Steht `audit_log_retention_days: 90` korrekt?
   ```bash
   grep -A2 audit_log_retention_days ~/.hermes/config.yaml
   ```
3. **Manueller Cleanup** (Notfall):
   ```bash
   find ~/.hermes/profiles/*/workspace/logs/ \
     -name "prompt-injection-attempts.log.*" -mtime +90 -delete
   ```
4. **Prüfe Pattern-Tuning**: Wenn das Volumen konstant hoch ist → Modus auf
   `audit` lassen und Patterns enger fassen, statt in `enforcement` zu gehen.

## Telegram-Alerts funktionieren nicht

**Symptom:** Trotz Konfiguration kommen keine Alerts an.

**Diagnose-Checkliste:**

1. **Token gesetzt?**
   ```bash
   echo "Token-Länge: ${#TELEGRAM_BOT_TOKEN}"
   echo "Chat-ID: $INJECTION_SHIELD_TELEGRAM_CHAT_ID"
   ```
2. **Plugin sieht die Env-Vars?**
   ```bash
   ~/.hermes/hermes-agent/venv/bin/python -c "
   import os
   from injection_shield.config import load_config
   cfg = load_config('default')
   print('telegram:', cfg['telegram'])
   "
   ```
3. **Bot ist Admin im Channel?** (für Channel-Posts erforderlich)
4. **`min_severity` zu hoch?** Versuche temporär `low`:
   ```yaml
   telegram:
     enabled: true
     min_severity: low
   ```

## Hook feuert nicht

**Symptom:** Audit-Log bleibt leer, obwohl ein offensichtlicher
Injection-Versuch stattgefunden hat.

**Diagnose:**

1. **Plugin enabled?**
   ```bash
   hermes plugins list | grep injection
   ```
2. **Modus korrekt?** `off` deaktiviert alle Hooks.
3. **Im richtigen Profil?** Hermes kann pro Profil ein separates
   `audit_log_path` haben.
4. **Pattern-Match überprüfen** mit dem Live-Test:
   ```bash
   cd ~/.hermes/plugins/injection-shield
   ~/.hermes/hermes-agent/venv/bin/python live_tests.py
   ```

## Test-Failures nach Update

**Symptom:** Nach `pip install -e .` oder `git pull` brechen Tests.

**Lösung:**

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python -m pip install -e .[dev]
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -v
```

Falls einzelne Tests fehlschlagen: erst die anderen laufen lassen
(`pytest tests/ --deselect tests/test_<failing>.py`) und die fehlschlagenden
Tests als Issue melden — niemals `xfail`-Marker hinzufügen, ohne den
Maintainer zu fragen.

## Hilfe-Resources

- Incident-Report: `[[../../03-Projects/Merovinger/Incident-20260821-KriPo-Berlin/00-Incident-Report]]`
- DSGVO-Bewertung: `docs/DSGVO-KONZEPT.md`

---

## English

# Troubleshooting

## False Positive Wave

**Symptom:** Many legitimate tool calls or LLM responses are flagged as
injection; audit log fills up rapidly.

**Diagnosis:**

```bash
# Distribution of pattern types
tail -500 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log \
  | python3 -c "import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try: c[json.loads(line).get('type', '?')] += 1
    except Exception: pass
for t, n in sorted(c.items(), key=lambda x: -x[1]): print(f'{t}: {n}')"
```

**Solution:**

1. **Immediately:** Set mode to `audit` — `enforcement` would now block tool calls:
   ```bash
   hermes config set plugins.entries.injection-shield.mode audit
   ```
2. **Medium term:** Which pattern type dominates?
   - `instruction_override` → see `firewall_text` in `config.py` —
     tighten patterns if needed.
   - `credential_leak` → whitelist legitimate values in
     `plugins.entries.injection-shield.credential_allowlist`.
   - `zero_width` → often affects text copied from PDFs/web — inform users
     that the behavior is correct.
3. **Long term:** Switch back to `enforcement` after tuning.

## Bypass Discovered

**Symptom:** Clearly suspicious constructs appear in the LLM output:
classic override-style phrases, base64 URL payloads, variation selector stego —
even though the plugin is active.

**Immediate actions:**

1. **Set mode to `audit`** — prevents further damage without interrupting the
   normal workflow:
   ```bash
   hermes config set plugins.entries.injection-shield.mode audit
   ```
2. **Back up the audit log** (forensics, before auto-prune):
   ```bash
   cp ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log* \
      ~/Desktop/injection-shield-evidence-$(date +%Y%m%d).log
   ```
3. **Note the plugin version** (for the issue tracker):
   ```bash
   pip show injection-shield | grep -E '^(Name|Version|Location):'
   ```
4. **Open an issue** in the tracker with:
   - Exact bypass payload (in code block, **do not execute**)
   - Audit log excerpt
   - Repro steps (which tool, which hook)
5. **Workaround**: Manually add bypass pattern to `firewall_text` (see
   `detectors/injection_patterns.py`) until an official release brings the fix.

## Plugin Crash

**Symptom:** LLM calls abort or the plugin throws tracebacks in the
Hermes logs (`~/.hermes/profiles/<profile>/workspace/logs/hermes.log`).

**Diagnosis:**

```bash
# 1. Check last audit events for errors
tail -200 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log \
  | grep -iE '(error|traceback|exception)' || echo "OK — no errors in audit log"

# 2. Hermes log
tail -200 ~/.hermes/profiles/default/workspace/logs/hermes.log \
  | grep -iE '(injection.shield|detector)' | tail -20

# 3. Plugin status
hermes plugins info injection-shield
```

**Solution:**

1. **Update** to the latest version:
   ```bash
   cd ~/.hermes/plugins/injection-shield
   git pull
   pip install -e .
   ```
2. **Workaround** until update: disable the plugin:
   ```bash
   hermes plugins disable injection-shield
   ```
   Or set mode to `off` (no hook overhead, but plugin stays loaded).
3. **Detector isolation**: The `DetectorChain` wraps each detector in
   try/except — individual layers can fail without the entire shield
   crashing. Check whether only a specific hook is affected.

## Log File Growing Uncontrollably

**Symptom:** `prompt-injection-attempts.log` > 100 MiB.

**Diagnosis:**

```bash
ls -lh ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log*
```

**Solution:**

1. **Check rotation**: Are the backups there?
   ```bash
   ls -1 ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log* \
     | wc -l
   ```
   With `audit_log_backup_count: 5`, there should be at most 6 files.
2. **Check retention**: Is `audit_log_retention_days: 90` set correctly?
   ```bash
   grep -A2 audit_log_retention_days ~/.hermes/config.yaml
   ```
3. **Manual cleanup** (emergency):
   ```bash
   find ~/.hermes/profiles/*/workspace/logs/ \
     -name "prompt-injection-attempts.log.*" -mtime +90 -delete
   ```
4. **Check pattern tuning**: If volume is constantly high → keep in `audit`
   mode and tighten patterns rather than going to `enforcement`.

## Telegram Alerts Not Working

**Symptom:** Despite configuration, no alerts arrive.

**Diagnostic checklist:**

1. **Token set?**
   ```bash
   echo "Token length: ${#TELEGRAM_BOT_TOKEN}"
   echo "Chat ID: $INJECTION_SHIELD_TELEGRAM_CHAT_ID"
   ```
2. **Can the plugin see the env vars?**
   ```bash
   ~/.hermes/hermes-agent/venv/bin/python -c "
   import os
   from injection_shield.config import load_config
   cfg = load_config('default')
   print('telegram:', cfg['telegram'])
   "
   ```
3. **Is the bot admin in the channel?** (required for channel posts)
4. **`min_severity` too high?** Try temporarily `low`:
   ```yaml
   telegram:
     enabled: true
     min_severity: low
   ```

## Hook Not Firing

**Symptom:** Audit log stays empty despite an obvious injection attempt having occurred.

**Diagnosis:**

1. **Plugin enabled?**
   ```bash
   hermes plugins list | grep injection
   ```
2. **Mode correct?** `off` disables all hooks.
3. **Correct profile?** Hermes can have a separate `audit_log_path` per profile.
4. **Verify pattern match** with the live test:
   ```bash
   cd ~/.hermes/plugins/injection-shield
   ~/.hermes/hermes-agent/venv/bin/python live_tests.py
   ```

## Test Failures After Update

**Symptom:** After `pip install -e .` or `git pull`, tests break.

**Solution:**

```bash
cd ~/.hermes/plugins/injection-shield
~/.hermes/hermes-agent/venv/bin/python -m pip install -e .[dev]
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -v
```

If individual tests fail: let the others run first
(`pytest tests/ --deselect tests/test_<failing>.py`) and report the failing
tests as an issue — never add `xfail` markers without asking the maintainer.

## Help Resources

- Incident report: `[[../../03-Projects/Merovinger/Incident-20260821-KriPo-Berlin/00-Incident-Report]]`
- GDPR assessment: `docs/DSGVO-KONZEPT.md`
