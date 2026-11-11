# Privacy-Shield v1.9.2 — Doctor-Key-Assertion, History-Masking Release

Erster Release-Tag nach v1.9.1. Enthält die Doctor-Key-Assertion (Fix für
die Silent-False-Pass-Regression ohne Encryption-Key) und das als
Fix-Delta `fba3d4f..191bf70` geprüfte R-1 History-Masking (Option b). Beides
ist auf `main` schon seit a9d1031 bzw. 2bef5e0 (Reviews: orakel + seraph,
beide PASS) enthalten; dieser Bump macht die Version sichtbar synchron zu
Code-Verhalten und CHANGELOG.

## Doctor-Key-Assertion (kein Key = FAIL, exit 2)

- **Was war kaputt?** Unter 1.9.x lief `privacy-shield doctor --quick`
  ohne Encryption-Key mit „2/2 OK" und exit 0 durch. Grund: Stage 1 (Scan)
  ist key-free by Design, Stage 2 gibt ein ephemeres, nicht persistiertes
  Testtoken auf stdout aus — die üblichen stdout-Greps auf „OK" greifen
  damit auch bei deaktiviertem Plugin. Betroffen war vor allem ein
  ungepatchter hermes-managed CLI-Snapshot (installs-venv plugin-sources),
  da Cron-Wrapper ihren Key selbst provisionieren.
- **Fix**: Pre-Stage 0 in `cli.py`. `_check_key()` assertiert vor Stage 1,
  ob `load_config().encryption_key` auflösbar ist. Ohne Key:
  „FAIL — encryption key missing", exit 2. Exit 1 nur für failed automated
  stages (manuelle Stages 4/5 zählen nicht).
- **Wrapper** (`privacy-shield-doctor.sh`): Key-Pre-Check exit 4 („no
  encryption key resolvable") plus Key-Provisionierung via `pass` vor dem
  CLI-Call. `last_doctor_ok` entsteht nur bei cli exit 0. Key-Wert wird
  nie ausgegeben.
- **Regressionstests**: keyless (leere Umgebung, scratch-HOME) → exit 2;
  mit Key → exit 0, „2/2 OK". `tests/test_doctor.py` prüft Verhalten,
  keine Output-Snapshots.

## R-1: History-Masking (Option b)

- `apply_shield_to_request` maskiert alle User-Messages des Requests
  (Live-Prompt + History, str und Multimodal-Text-Parts) — auch ohne
  Staged-Slot (PII-freier Live-Prompt, Turn-ID-Mismatch): schließt P2.
- `mask_sidecar_suffix` (Default on): Bytes hinter dem Live-Prompt
  (Memory-Prefetch, Plugin-Kontext) werden gescannt statt byte-exakt
  erhalten; unbekannte Wire-Shapes bleiben fail-safe (Full-Mask): schließt P3.
- Turn-scoped Per-Message-Memo (Key `session_id + SHA-256(content)`,
  Hard-Cap 256): Detektor-Kette einmal pro Turn pro Message statt pro
  API-Attempt; frische Mapping-Zeilen pro Turn erhalten den Restore-Vertrag.
- Config: `mask_history` (Default **on**; Ollama-Exemption unverändert),
  `mask_history: false` reproduziert exakt die v1.9.1-Semantik.
- P4 (Summary-/Aux-Calls bypassen die `llm_request`-Middleware) bleibt
  dokumentiert offen bis zum Upstream-Core-PR (Option c).
- Reviews: orakel (PASS, t_eb5a2461) und seraph (PASS, t_9c75defc) über das
  Fix-Delta; Smith-Contract bleibt intakt (leerer turn_id = kein
  Cross-Turn-Staged-Read).

## Upgrade-Notizen

- Keine Konfig-Migration nötig: neue Flags sind Default-on und decken das
  intendierte Verhalten ab; Rückweg zur v1.9.1-Semantik ist
  `mask_history: false` (+ optional `mask_sidecar_suffix: false`).
- Nach Deployment einmal per Wrapper prüfen: keyless CLI-Lauf muss jetzt
  mit exit 2 und „encryption key missing" enden; der Wrapper liefert bei
  fehlendem Key exit 4. Ist das nicht der Fall, läuft noch ein Snapshot
  vor diesem Release.
