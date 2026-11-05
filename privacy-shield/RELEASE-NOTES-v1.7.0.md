## Privacy-Shield v1.7.0

**Pre-Intake Reasoning Tokenization** — closes the state.db persistence gap (GB-009) identified in the Stolen-Thoughts threat analysis (arXiv:2608.09867, University of Tübingen 2026).

### What's New

- **`post_api_request` pre-intake hook** (official Core API hook — no core patch): mutates `reasoning`, `reasoning_content`, and `reasoning_details` **in place on the live assistant_message**, BEFORE `_persist_session` writes to `state.db`. The database now only ever stores tokenized reasoning text. (**GB-009 CLOSED** — previously documented as an accepted design limitation in v1.6.1.)
- **Two-layer defense-in-depth**: pre-intake (v1.7.0) + the v1.6.1 `post_llm_call` in-memory pass for late consumers of the conversation history.
- Tools, exporters, audit trail, and output stages see only tokenized reasoning blocks.
- Configurable via `reasoning_mode: off | audit | restore` (default `restore`), `reasoning_confidence_threshold`.
- Audit-log entries carry `source=reasoning_block_pre_intake`; the log never contains plaintext PII.

### Residual Architecture Limitation (must read)

**The provider sees the reasoning before Privacy-Shield does.** With cloud reasoning models (OpenAI / Anthropic / Google), reasoning content is transmitted in plaintext over the network and may appear in provider logs/telemetry. This is outside the plugin's control. Mitigations:

- For sensitive data: disable reasoning (`reasoning.effort = none`) or run a local model (e.g. Ollama).
- For cloud providers: review the provider's DPA/BAA (GDPR compliance).

### Validation

- Chain tests (`tests/test_reasoning_pre_intake.py`): live object → `build_assistant_message` → `_db_flush_row` — persistence only ever receives tokenized text.
- Full test suite: 820 tests green.
- Follows the three-phase red team (Seal Team / Green Berets / Re-Red-Team) that gated v1.6.1; the two release blockers from that process are now resolved: GB-010 (last_reasoning leak, fixed in v1.6.1) and GB-009 (state.db, closed in v1.7.0).

### Breaking Changes

None — v1.7.0 is backward-compatible with v1.6.x config.

### Full Changelog

[CHANGELOG.md](CHANGELOG.md)

---

## Privacy-Shield v1.7.0 — Deutsche Version

**Pre-Intake-Reasoning-Tokenisierung** — schließt die state.db-Persistenzlücke (GB-009) aus der Stolen-Thoughts-Bedrohungsanalyse (arXiv:2608.09867, Universität Tübingen 2026).

### Was ist neu

- **`post_api_request`-Pre-Intake-Hook** (offizieller Core-API-Hook, kein Core-Patch): mutiert `reasoning`/`reasoning_content`/`reasoning_details` **in-place auf dem Live-Objekt**, BEVOR `_persist_session` nach `state.db` schreibt. Die Datenbank erhält ausschließlich tokenisierte Reasoning-Texte. (**GB-009 GESCHLOSSEN**)
- **Zwei-Ebenen-Defense-in-Depth:** Pre-Intake (v1.7.0) + In-Memory-Pass über `post_llm_call` (v1.6.1) für späte Konsumenten der Conversation-History.
- Tools, Exporter, Audit-Trail und Output-Stages sehen nur tokenisierte Reasoning-Blöcke.
- Konfiguration via `reasoning_mode: off | audit | restore` (Default `restore`).

### Verbleibende Architektur-Limitation (bitte lesen)

**Der Provider sieht das Reasoning vor Privacy-Shield.** Bei Cloud-Reasoning-Modellen (OpenAI / Anthropic / Google) wird Reasoning-Inhalt im Klartext übertragen und kann in Provider-Logs/Telemetrie landen — außerhalb der Plugin-Kontrolle. Mitigation: bei sensiblen Daten Reasoning deaktivieren oder lokal betreiben (Ollama); bei Cloud-Providern DPA/BAA prüfen (DSGVO).

### Validierung

- Kettentests (`tests/test_reasoning_pre_intake.py`): Live-Objekt → `build_assistant_message` → `_db_flush_row`
- 820 Tests grün
- Drei-Phasen-Red-Team (v1.6.1-Gate): beide Release-Blocker inzwischen geschlossen — GB-010 (v1.6.1), GB-009 (v1.7.0)

### Breaking Changes

Keine — rückwärtskompatibel mit v1.6.x-Config.
