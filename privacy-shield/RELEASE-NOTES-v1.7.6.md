# Privacy-Shield v1.7.6 — Restore-Miss-Platzhalter, Session-Splice-Repair, Kanban-Channel

Löst die drei Dirk-Entscheidungen vom 29.10.2026 (Kanban-Karte
t_f11a29b7). Zwei Karten-Annahmen wurden an den realen Code korrigiert:

- **Token-Grammatik** (Karte: „8hex" ist veraltet): real
  `TOKEN_{TYPE}_{10hex}_{serial:03d}`; `TYPE` darf `_` enthalten
  (`CRYPTO_BTC`, `FUEHRENSCHEIN_DE`); der Session-Counter (000-999)
  ist **nicht** global eindeutig — er startet bei LRU-Eviction der
  Session neu. Empirisch (Session `20261021_113823_b28763b0`, 92 Rows):
  **10 Kollisionen** von `(type, serial)`, z. B.
  `('ip_address','002')` = 4 Rows / 2 verschiedene Token-Hashes.
- **Eindeutigkeitsprüfung** zählt deshalb **unterschiedliche Originale**
  (distinct original_hash/value), nicht die Row-Anzahl: 4 Rows mit
  2 verschiedenen Originalen = mehrdeutig → Platzhalter.

## What's in it

### Entscheidung 1 — `restore_miss_strategy` (Default `placeholder`)

- Neue Option `restore_miss_strategy: "placeholder" | "keep"`
  (Default `placeholder`), validiert wie `reasoning.mode` — ungültiger
  Wert → Default + WARNING.
- Platzhaltertext als Modul-Konstante (`DEFAULT_RESTORE_MISS_PLACEHOLDER`,
  En-Dash U+2013, wörtlich `[maskiertes PII – nicht wiederherstellbar]`)
  plus Config-Override `restore_miss_placeholder` für EN-Deployments
  (bilingual: DE default, EN override).
- Residual-Pass in `plugin.post_llm_response` (nur hinter dem
  Channel-Gate): Scan mit `mapper.token_pattern`; Sanitizer-Fresh-Tokens
  werden ausgelassen (FIX-1B); jeder echte Restversuch → Fuzzy-Repair
  (Entscheidung 2); kein eindeutiger Kandidat → Platzhalter (`placeholder`)
  bzw. Token bleibt (`keep`). Miss → WARNING-Log
  (`restore_miss (session=<gekürzt>, type=<TYPE>, serial=<n>)`, ohne PII/
  Klartext/vollen Token) + Metric `restore_misses` +
  Prometheus-Counter `privacy_shield_restore_misses_total`
  (Muster wie `privacy_shield_masking_volume_total`; bestehende Counter
  unverändert).
- Platzhalter ersetzt **nur den Token-Span** — geklebte Suffixe
  (`TOKEN_CRYPTO_BTC_22d5465887_002dem` → Platzhalter + `dem`) bleiben
  erhalten.
- Auf nicht erlaubten Channels (write_file, terminal, MCP) bleibt alles
  unverändert stehen: kein Restore, **kein** Platzhalter-Eingriff.

### Entscheidung 2 — Session-gebundener Splice-Repair (an)

Ziel: ein vom Modell gesplictes Token (Serial korrekt, Hash/Rest kaputt)
wird über `(type_lower, serial)` **innerhalb derselben Session**
zurückgeholt.

Regeln (in `MappingTable.resolve_fuzzy_token` und
`InMemoryMappingTable.resolve_fuzzy_token`, beide Backends):

- Nur Kandidaten mit **exakt gleicher** `session_id`; kein
  Cross-Session-Fallback; leerer `session_id` → kein Repair (fail-closed).
- Typ: `group(1)` aus `mapper.token_pattern` → `lower()` (DB-Spalte `type`
  ist lowercase, z. B. `crypto_btc`).
- Serial: `group(3)` muss vorhanden und numerisch sein — Legacy-Tokens
  ohne Serial → kein Repair → Platzhalter.
- **Eindeutig** = genau **ein** unterschiedliches Original unter den
  Kandidaten → Originalwert einsetzen; 0 oder ≥ 2 → Platzhalter.
- Typvergleich case-insensitiv via `lower()`; DB-Spalte lowercase.

Performance (hartes Limit — PBKDF2-HMAC-SHA256 mit 600.000 Iterationen
≈ 40–120 ms/Row, host- und backendabhängig; gemessen ~86 ms mit hashlib,
~117 ms mit dem cryptography-Backend; ungefiltertes Entschlüsseln der
Tabelle ist verboten, 61k Rows ≈ 1,5–2 h):

- SQLite (`MappingTable`): neue Nullable-Spalte `token_serial` in
  `mappings` + Index `(session_id, type, token_serial)`; Migration
  idempotent via `ALTER TABLE`/`CREATE INDEX` (Muster wie `token_hash`).
  Semantik: `NULL` = noch nicht verarbeitet, `-1` (`TOKEN_SERIAL_ABSENT`)
  = verarbeitet aber Token ohne Serial. `store()` parst den Serial aus
  dem Klartext-Token **vor** der Verschlüsselung.
- **Bounded Lazy-Backfill**: für eine (session_id, type)-Kombination bis
  200 Rows entschlüsseln + persistieren, unter dem bestehenden Lock,
  höchstens einmal pro (session, type) (Marker). Kein Full-Table-Scan.
- **Operator-Backfill**: `scripts/backfill_token_serial.py` — resumable,
  chunked (`--chunk`), mit Fortschritt (`processed=N`), `--status`/
  `--dry-run` ohne Schreibzugriff; Schlüssel aus pass/env wie das Plugin.
- In-Memory (`InMemoryMappingTable`): Klartext-Keys → Serial direkt aus
  dem Token-String geparst, Lookup ohne Entschlüsselung.
- Kandidaten-Query entschlüsselt pro Aufruf nur wenige Rows
  (`original_encrypted` — die Token-Spalte wird im Repair-Pfad **nie**
  entschlüsselt); vermerkt in Code + Doku.

### Entscheidung 3 — Kanban-Channel (Variante a)

- `config.py::_default_restore_channels()`: `kanban` in die Bare-Liste
  (`telegram`, `desktop`, `cli`, `kanban`). `cron` bleibt Opt-in
  (PS-CHANNEL-007 unverändert).
- **Chat-ID-Allowlist bleibt die Vertrauensgrenze**: `allowed_chats` /
  `allowed_chat_ids` / telegram-send nicht verändert, nicht erweitert,
  nicht entfernt. Es kommt nur der eine Channel-Eintrag `kanban` hinzu.
- `ALLOWED_RESTORE_CHANNELS` in `plugin.py` bleibt leer (kein globales
  Hardcoding). Channel-Matching bleibt prefix-aware/fail-closed
  (`_channel_allowed`); exakter Match `kanban` genügt.
- Tool-Egress unberührt: keine Tool-Argumente/Results werden durch die
  Kanban-Erweiterung restore-fähig.

### FIX-1B — Fresh-PII/Output-Sanitizer-Verhalten bleibt erhalten

- Frisch geleakte Werte werden vom Sanitizer mit eigenen Tokens versehen
  und **bewusst nicht** in der Mapping-Tabelle gespeichert — sie sind
  nicht auflösbar und müssen sichtbar bleiben (User sieht Token, nie den
  Leak).
- `OutputSanitizer.sanitize(...)` behält die 2-Tuple-Rückgabe
  `(text, count)`; die erzeugten Tokens gehen über den optionalen
  Out-Parameter `fresh_tokens: set[str] | None = None` an den Aufrufer.
  Bestehende Tests/Caller bleiben gültig.
- Reihenfolge unverändert: Fresh-PII-Sanitize **vor** Restore → exakter
  Restore → Residual-Pass.

## Config (bilingual)

```yaml
plugins:
  entries:
    privacy-shield:
      # Restore-Miss handling (v1.7.6)
      restore_miss_strategy: placeholder   # placeholder | keep
      # DE default; EN deployments may override:
      # restore_miss_placeholder: "[masked PII – cannot be restored]"
      # Restore channels (chat-ID allowlist stays the trust boundary!)
      restore_allowed_channels: ["telegram", "desktop", "cli", "kanban"]
```

DE: `[maskiertes PII – nicht wiederherstellbar]` (Default) —
EN-Override: `restore_miss_placeholder` nach Bedarf setzen.

**Achtung:** Ein explizites `restore_allowed_channels` ersetzt die komplette
Default-Liste (`_merge_user_config` überschreibt das ganze Tupel, kein
Auto-Merge) — ein expliziter Eintrag ohne `kanban` deaktiviert die
Kanban-Wiederherstellung stillschweigend.

## Tests

- Neue `tests/test_restore_miss_v176.py` (30 Tests): Splice-Miss →
  exakter Platzhalter; Fuzzy-Treffer → Original; Fuzzy-Multi-Match →
  Platzhalter; kein Cross-Session-Fallback; Kanban-Channel
  (erlaubt/nicht erlaubt); Fresh-PII-Regression; Legacy-Row ohne Serial
  (fail-closed, kein Crash); geklebter Suffix; Metrics
  (`restore_misses`, Prometheus); Config-Validierung; SQLite-Backend
  mit `token_serial`-Persistenz + bounded Backfill (once per session+type);
  Security-Regressionen (Review-Feedback, 2026-11-06): manipulierter
  `token_serial` → fail-closed + Reparatur (Finding 3f), Kandidaten-Fenster
  am LIMIT → fail-closed (F4), nicht-String-Platzhalter → Fallback (F5),
  Log-Level-Verträge (Finding 7g/7d).
- Suite: 1073 gesammelt — **1066 passed, 7 skipped, 0 failed**
  (Repo-.venv-Python; Baseline `origin/main`@22ddadf: 1043 gesammelt —
  1036 passed, 7 skipped; Delta +25 v1.7.6-Tests + 5 Security-Regressionen).

## Risiken / offene Punkte

- **Versionskollision mit PR #25 (v1.8.0, `local/dashboard-selfload-parked`)**:
  beide Branchen bumpen die Version; Mergereihenfolge entscheidet, welche
  Changelog-/RELEASE-NOTES-Konflikt-Hunks nachgearbeitet werden müssen.
  PR #25 bleibt offen und unangetastet (Basis dieser Karte: `origin/main`).
- Legacy-Deployment-DBs starten mit `NULL` in `token_serial`; erste Repair-
  Anfragen zahlen einmalig den Lazy-Backfill (≤ 200 Rows / (session,type));
  Operator kann jederzeit vorweg backfillen (`scripts/backfill_token_serial.py`).
- Live-Config-Rollout (`~/.hermes/config.yaml` + Profile) erfolgt in der
  Folgekarte — nicht in dieser.
- **Residual-Risiko Finding 3f:** Die Serial-Verifikation schützt den
  Restore-Pfad vor Mis-Repair und repariert korrupte Rows. Ein Angreifer mit
  fortgesetztem direktem Schreibzugriff auf die DB-Datei kann Serials weiter
  manipulieren (z. B. auch `original_hash`/`token_hash` korrumpieren);
  Restoring insgesamt wird dadurch **nicht** blockiert, aber ein **falsches**
  Original wird nie mehr geliefert (fail-closed). Ein DB-Trigger
  (Review-Option B) wäre zusätzlich abwählbar (`DROP TRIGGER`) und wurde
  daher bewusst nicht gesetzt.