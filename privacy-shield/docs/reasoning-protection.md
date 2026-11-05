# Reasoning-Block-Schutz

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Reasoning-Block-Schutz

Privacy-Shield v1.7.1 liefert **Pre-Intake-Redaktion** für Reasoning-/
Thinking-Blöcke — ohne einen Hermes-Core-Patch zu benötigen.

> ✅ **STATUS v1.7.1 (2026-09-21): Drei-Quellen-Fallback.**
> Der `post_api_request`-Hook feuert direkt nach dem Response-Intake,
> **vor** `_persist_session`. Reasoning-Felder werden am Live-Objekt
> tokenisiert — `state.db` erhält nur noch tokenisierte Reasoning-Texte
> (GB-009 BEHOBEN).
>
> **Neu in v1.7.1 — Read-only-Property-Lücke geschlossen:**
> `NormalizedResponse.reasoning_content`/`reasoning_details` sind
> read-only Properties über `provider_data`. v1.7.0 scheiterte dort am
> `setattr` (fail-open, Token verworfen — GB-009 teilweise re-opened).
> v1.7.1 nutzt eine Drei-Quellen-Fallback-Kette:
>
> 1. **setattr** — Dataclass-Felder (z. B. `reasoning`)
> 2. **provider_data** — In-Place-Mutation des Dicts hinter der Property
>    (bei `None` wird `{}` initialisiert)
> 3. **model_extra** — SDK-Varianten, die Reasoning nur dort ablegen
>
> Jeder genutzte Fallback erzeugt ein Audit-Event
> (`reasoning_redaction_fallback`), jeder vollständige Bypass ein
> `reasoning_redaction_bypass`-Event — Silent-Failure endet hier.
>
> **Verbleibende Architektur-Limitation (Provider-Ebene):**
> 1. **Provider (OpenAI/Anthropic/Google) sieht Reasoning vor Privacy-Shield** — die Daten werden bereits über das Netzwerk übertragen und sind in Provider-Logs/Telemetrie im Klartext. Außerhalb unserer Kontrolle.
> 2. **`result["last_reasoning"]` enthält nach dem Hook den tokenisierten Wert** — das ist GB-010-Fix, see below.
>
> **Was Du tun solltest:**
> - Bei sensiblen Daten: Reasoning-Modelle deaktivieren (`reasoning.effort = none`) oder lokal betreiben (Ollama).
> - Bei Cloud-Providern: Provider-DPA/BAA prüfen (GDPR-Compliance).

## Funktionsweise (v1.7.0: zwei Ebenen)

- **Ebene 1 — Pre-Intake (v1.7.0):** Privacy-Shield registriert den
  `post_api_request`-Hook. Er mutiert Reasoning-Felder (`reasoning`,
  `reasoning_content`, `reasoning_details`) **in-place auf dem Live-
  `assistant_message`-Objekt**, bevor `build_assistant_message` sie
  liest und `_persist_session` sie in `state.db` schreibt.
- **Ebene 2 — In-Memory (v1.6.1, Defense-in-Depth):** Der
  `post_llm_call`-Hook iteriert zusätzlich über `conversation_history`
  und tokenisiert Reasoning-Felder in Assistant-Nachrichten in-place.
  Deckt späte Konsumenten ab, die die History nach dem Intake-Stadium
  lesen.
- Tools, Exporter, Audit-Trail und Output-Stages sehen nur noch
  tokenisierte Reasoning-Blöcke.

## Modus

| Modus   | Verhalten |
|---------|-----------|
| `off`   | Reasoning-Blöcke werden unverändert durchgereicht. |
| `audit` | PII wird erkannt und audit-geloggt, der Text bleibt aber unverändert. |
| `restore` | PII wird tokenisiert; Mapping-Table speichert die Rückübersetzung. |

Default ist `restore`.

## Konfiguration

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore
      reasoning_confidence_threshold: 0.85
```

Oder über Umgebungsvariablen:

```bash
export PRIVACY_SHIELD_REASONING_MODE=restore
export PRIVACY_SHIELD_REASONING_CONFIDENCE=0.85
```

## Audit-Log

Reasoning-Events tragen das Extra-Feld `source`:

- `reasoning_block_pre_intake` (v1.7.0): Pre-Intake-Redaktion via `post_api_request`.
- `reasoning_block` (v1.6.1): In-Memory-Redaktion via `post_llm_call`.

```jsonl
{"ts": 1787481000.0, "event": "reasoning_redaction_applied",
 "session_id_hash": "a1b2...", "mode": "restore",
 "masked_count_bucket": "1-1", "pii_types": ["email"],
 "source": "reasoning_block_pre_intake",
 "note": "Pre-Intake-Redaktion via post_api_request: state.db erhaelt nur tokenisierte Reasoning-Texte (GB-009 geschlossen)."}
```

Es werden niemals Klartext-PII-Werte in die Audit-Datei geschrieben.

## Persistenz-Limitation

**STATUS-UPDATE 2026-09-09 (v1.7.0): BEHOBEN.** Der Core-Hook
`post_api_request` (feuert in `agent/turn_response_intake.py` direkt
nach Response-Intake, VOR `_persist_session`) ermöglicht die
**Pre-Intake-Redaktion** auf dem Live-`assistant_message`-Objekt.
`state.db` erhält nur noch tokenisierte Reasoning-Texte — GB-009 ist
geschlossen. Verifiziert durch die Kettentests in
`tests/test_reasoning_pre_intake.py` (Live-Objekt ->
`build_assistant_message` -> `_db_flush_row`).

Historischer Befund (v1.6.1): Spike-001 (`t_c33c4baf`) Verdict:
**PARTIAL**. In-Place-Mutation wirkt auf das Original-`messages`-Array
durch, aber `_persist_session` lief **vor** dem `post_llm_call`-Hook.
Deshalb landete Reasoning-PII kurzzeitig in `state.db`.

### Was v1.7.0 abdeckt

- Reasoning-Inhalt im laufenden Hermes-Memory: tokenisiert (pre-intake).
- Reasoning-Inhalt in `state.db`: tokenisiert (GB-009 geschlossen).
- Reasoning-Inhalt in Export-Trails (Audit-Log, Session-Exporter,
  Telemetrie): tokenisiert, weil diese Stages die `messages`-Liste aus
  dem Memory lesen.
- `post_llm_call`-In-Memory-Redaktion bleibt als Defense-in-Depth aktiv.

### Restriktionen

- `content`-Stream wird nicht angefasst: inline `<think>`-Blöcke im
  Content sind vom Pre-Intake-Pfad nicht abgedeckt (der Core strippt
  Think-Blocks am Storage-Boundary selbst); die Detections werden im
  Audit-Log geführt.
- SDK-Varianten, die Reasoning in `model_extra` verstecken: covered
  durch den Core-Lese-Pfad, aber nicht direkt setattr-bar — Fail-open
  mit Warning.

### Bekanntes Restrisiko: codex_reasoning_items (v1.7.2-Kandidat)

`codex_reasoning_items` steht default in `skip_fields`: die Items sind
provider-native, teils signierte Blöcke, die nicht textuell tokenisiert
werden können, ohne Signaturen zu invalidieren. Konsequenz: PII in
codex_reasoning_items wird **nicht** automatisch tokenisiert (Raw-Text
in `state.db`). Geplante Minderung in v1.7.2: Leaf-Text-Tokenisierung
der text/content-Unterfelder oder ein Audit-Event bei non-empty Items
mit PII-Treffern.

### Mitigation

- Reasoning-Restore-Channel ist aktiv (Default `restore`).
- Audit-Log-Einträge zeigen Token-Werte, nie Klartext.

## Upstream-Status

Ein Hermes-SDK-Patch für einen dedizierten `transform_llm_reasoning`-Hook
war geplant. Auf Betreiber-Vorgabe wurde der Core-Patch zurückgerollt
(Memory-Lesson 2026-08-23: kein Editieren von `~/.hermes/hermes-agent/`).
Privacy-Shield v1.7.0 nutzt stattdessen den offiziellen
`post_api_request`-Hook der Core-API (dokumentiert in
`website/docs/developer-guide/plugins/index.md`) — kein Core-Patch
erforderlich.

## Verwandte Dokumente

- Vault-Zettel:
  `~/Second-Brain/02-Knowledge/operations/security/privacy-shield/build/reasoning-block-v1.6.1.md`
- Spike-001 README: `~/Second-Brain/02-Knowledge/operations/security/privacy-shield/build/reasoning-block-v1.6.0.md`

---

## English

# Reasoning Block Protection

Privacy-Shield v1.7.1 provides **pre-intake redaction** for reasoning/
thinking blocks — without requiring a Hermes core patch.

> ✅ **STATUS v1.7.1 (2026-09-21): Three-source fallback.**
> The `post_api_request` hook fires directly after response intake,
> **before** `_persist_session`. Reasoning fields are tokenized on the
> live object — `state.db` receives only tokenized reasoning texts
> (GB-009 FIXED).
>
> **New in v1.7.1 — Read-only property gap closed:**
> `NormalizedResponse.reasoning_content`/`reasoning_details` are
> read-only properties over `provider_data`. v1.7.0 failed there with
> `setattr` (fail-open, token discarded — GB-009 partially re-opened).
> v1.7.1 uses a three-source fallback chain:
>
> 1. **setattr** — Dataclass fields (e.g. `reasoning`)
> 2. **provider_data** — In-place mutation of the dict behind the property
>    (initializes `{}` if `None`)
> 3. **model_extra** — SDK variants that store reasoning only there
>
> Every used fallback creates an audit event
> (`reasoning_redaction_fallback`), every complete bypass a
> `reasoning_redaction_bypass` event — silent failure ends here.
>
> **Remaining architecture limitation (provider level):**
> 1. **Provider (OpenAI/Anthropic/Google) sees reasoning before Privacy-Shield** — data is already transmitted over the network and appears in provider logs/telemetry in plaintext. Outside our control.
> 2. **`result["last_reasoning"]` contains the tokenized value after the hook** — that is the GB-010 fix, see below.
>
> **What you should do:**
> - For sensitive data: Disable reasoning models (`reasoning.effort = none`) or run locally (Ollama).
> - For cloud providers: Check provider DPA/BAA (GDPR compliance).

## How It Works (v1.7.0: two layers)

- **Layer 1 — Pre-Intake (v1.7.0):** Privacy-Shield registers the
  `post_api_request` hook. It mutates reasoning fields (`reasoning`,
  `reasoning_content`, `reasoning_details`) **in-place on the live
  `assistant_message` object**, before `build_assistant_message` reads
  them and `_persist_session` writes them to `state.db`.
- **Layer 2 — In-Memory (v1.6.1, defense-in-depth):** The
  `post_llm_call` hook additionally iterates over `conversation_history`
  and tokenizes reasoning fields in assistant messages in-place.
  Covers late consumers that read history after the intake stage.
- Tools, exporters, audit trail, and output stages see only
  tokenized reasoning blocks.

## Modes

| Mode   | Behavior |
|--------|----------|
| `off`   | Reasoning blocks are passed through unchanged. |
| `audit` | PII is detected and audit-logged, but the text remains unchanged. |
| `restore` | PII is tokenized; mapping table stores the reverse translation. |

Default is `restore`.

## Configuration

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore
      reasoning_confidence_threshold: 0.85
```

Or via environment variables:

```bash
export PRIVACY_SHIELD_REASONING_MODE=restore
export PRIVACY_SHIELD_REASONING_CONFIDENCE=0.85
```

## Audit Log

Reasoning events carry the extra field `source`:

- `reasoning_block_pre_intake` (v1.7.0): Pre-intake redaction via `post_api_request`.
- `reasoning_block` (v1.6.1): In-memory redaction via `post_llm_call`.

```jsonl
{"ts": 1787481000.0, "event": "reasoning_redaction_applied",
 "session_id_hash": "a1b2...", "mode": "restore",
 "masked_count_bucket": "1-1", "pii_types": ["email"],
 "source": "reasoning_block_pre_intake",
 "note": "Pre-intake redaction via post_api_request: state.db receives only tokenized reasoning texts (GB-009 closed)."}
```

Plaintext PII values are never written to the audit file.

## Persistence Limitation

**STATUS UPDATE 2026-09-09 (v1.7.0): FIXED.** The core hook
`post_api_request` (fires in `agent/turn_response_intake.py` directly
after response intake, BEFORE `_persist_session`) enables
**pre-intake redaction** on the live `assistant_message` object.
`state.db` receives only tokenized reasoning texts — GB-009 is
closed. Verified by the chain tests in
`tests/test_reasoning_pre_intake.py` (live object ->
`build_assistant_message` -> `_db_flush_row`).

Historical finding (v1.6.1): Spike-001 (`t_c33c4baf`) verdict:
**PARTIAL**. In-place mutation propagates through the original `messages`
array, but `_persist_session` ran **before** the `post_llm_call` hook.
Therefore reasoning PII briefly landed in `state.db`.

### What v1.7.0 Covers

- Reasoning content in live Hermes memory: tokenized (pre-intake).
- Reasoning content in `state.db`: tokenized (GB-009 closed).
- Reasoning content in export trails (audit log, session exporter,
  telemetry): tokenized, because these stages read the `messages` list
  from memory.
- `post_llm_call` in-memory redaction remains active as defense-in-depth.

### Restrictions

- `content` stream is not touched: inline `<think>` blocks in
  content are not covered by the pre-intake path (the core strips
  think blocks at the storage boundary itself); detections are
  recorded in the audit log.
- SDK variants that hide reasoning in `model_extra`: covered
  by the core read path, but not directly settable — fail-open
  with warning.

### Known Residual Risk: codex_reasoning_items (v1.7.2 candidate)

`codex_reasoning_items` is by default in `skip_fields`: the items are
provider-native, partly signed blocks that cannot be textually tokenized
without invalidating signatures. Consequence: PII in
codex_reasoning_items is **not** automatically tokenized (raw text
in `state.db`). Planned mitigation in v1.7.2: leaf text tokenization
of the text/content subfields or an audit event for non-empty items
with PII hits.

### Mitigation

- Reasoning restore channel is active (default `restore`).
- Audit log entries show token values, never plaintext.

## Upstream Status

A Hermes SDK patch for a dedicated `transform_llm_reasoning` hook
was planned. At operator direction, the core patch was rolled back
(memory lesson 2026-08-23: no editing of `~/.hermes/hermes-agent/`).
Privacy-Shield v1.7.0 instead uses the official
`post_api_request` hook of the core API (documented in
`website/docs/developer-guide/plugins/index.md`) — no core patch
required.

## Related Documents

- Vault note:
  `~/Second-Brain/02-Knowledge/operations/security/privacy-shield/build/reasoning-block-v1.6.1.md`
- Spike-001 README: `~/Second-Brain/02-Knowledge/operations/security/privacy-shield/build/reasoning-block-v1.6.0.md`
