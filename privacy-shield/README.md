# Privacy-Shield

🌐 [Deutsch](README.de.md) | English

DSGVO-/GDPR-compliant Hermes plugin for tokenizing personal data (PII) in visible LLM output and reasoning content.

**Version:** 1.9.3 (2026-11-11) — 58 detection patterns · pure upstream plugin contract (llm_request middleware + pre_llm_call veto) · PDF + Image OCR · Audit-trail PDF/CSV/JSON export with Ed25519 signature · Desktop-Controls pane · Reasoning pre-intake tokenization (state.db-safe)

## Features

- **58 detection patterns** across 7 categories (email, IBAN, phone, crypto wallets, JWT, OAuth, GitHub PAT, MAC/IMEI/IMSI, etc.)
- **Text + Markdown + Code** — plain-text processing
- **PDF pipeline** — extracts text from text-based PDFs, tokenizes, produces sanitized PDF
- **Image OCR** — JPG/PNG/HEIC/WebP/TIFF/BMP via Tesseract 5.5.2, multi-language (deu+eng default)
- **AES-256-GCM encryption** with PBKDF2 (100k iterations) for token mapping
- **In-memory mapping table** with crypto-shredding (no disk leak)
- **Egress whitelist** — restore only in allowed channels (e.g. your Telegram bot)
- **Modes:** off / audit / limited / strict / paranoid
- **Provider detection** — Ollama-local = bypass (no cloud egress = no shield needed)
- **Unicode normalization** (NFKC + homoglyph mapping)
- **Cache-bypass tag** for local reads (local data = no shield)
- **GDPR compliance** — out-of-the-box with processor agreement checklist + records template

## History Masking (v1.9.2)

The shield covers **every user message** of an outgoing LLM request, not only the current turn: live prompt, earlier conversation turns (strings and multimodal `text`/`input_text` parts) and the sidecar context suffix (memory prefetch, plugin context) are scanned and tokenized per turn for each message. A turn-scoped per-message memo keeps the cost at one scan per message per turn, even when the core re-fires the middleware per API attempt.

```yaml
plugins:
  entries:
    privacy-shield:
      mask_history: true            # default on; false reproduces the old live-prompt-only behavior
      mask_sidecar_suffix: true     # default on; false keeps sidecar context byte-exact
```

**Known limitation (P4):** Hermes-core summary/aux calls (iteration/chat/codex summaries) build their provider kwargs directly and bypass this plugin's `llm_request` middleware — they stay unmasked until the upstream core PR routes all request-building seams through the middleware (Option c).

## Quickstart (5 minutes)

```bash
# 1. Install through the Hermes plugin system (installs the dashboard +
#    desktop halves itself; no pip into Hermes's venv, no core patching)
hermes plugins install <source>/privacy-shield
hermes plugins enable privacy-shield   # per profile

# 2. Provide the encryption key
privacy-shield setup                    # stores a generated key in pass
# Or declare PRIVACY_SHIELD_KEY via any Hermes secret source
# (keychain / pass-store secret-source plugin, command source, .env).
# The plugin resolves it through agent.secret_scope (requires_env).

# 3. Test
privacy-shield --help
privacy-shield scan "Contact: alice@example.com"
privacy-shield test --text "Help with alice@example.com and IBAN DE89370400440532013000"
```

### Standalone CLI runs (cron / launchd)

Outside a Hermes runtime the plugin does not resolve the encryption key
itself: it neither reads `PRIVACY_SHIELD_KEY` from the process environment
nor invokes the `pass` binary (upstream plugin contract, see
`_load_key_via_hermes` in `privacy-shield/config.py`). Standalone
invocations (`privacy-shield setup`, `privacy-shield map ...`) must be
provisioned by the caller:

1. **Wrapper provisioning (recommended).** The wrapper resolves the key
   through its own secret store and exports `PRIVACY_SHIELD_KEY` before
   calling the CLI. Hermes' secret scope resolves the value from the
   process environment when no multiplex scope is active (verified
   2026-11-11): the plugin itself still reads neither the key from the
   environment nor pass — the provisioning stays outside the plugin.
   Pattern: `~/.hermes/scripts/privacy-shield-cleanup.sh` (deployed
   wrapper; in-repo copy `privacy-shield/scripts/cron/`).
2. **Key file.** `PRIVACY_SHIELD_KEY_FILE` points to a regular file with
   mode 0600 owned by the current user (group/other access is refused).
3. **Workshop mode.** `PRIVACY_SHIELD_WORKSHOP=1` generates an ephemeral
   key with a loud warning — mapping tables become unreadable on restart.
   Never for production runs.

Without provisioning, standalone commands fail with
`MappingTable requires a non-empty encryption_key` — by design. Inside a
Hermes runtime a missing key never crashes initialization; the plugin
disables itself with a warning instead.

## Desktop Controls (v1.5.0+)

Privacy-Shield ships an official desktop plugin so you can tune settings in the Hermes Desktop app instead of editing YAML:

- Enable/disable the plugin
- Switch operating mode (`off`/`audit`/`limited`/`strict`/`paranoid`)
- Adjust the confidence threshold
- Manage restore-allowed channels
- Toggle PDF / Image OCR / cache bypass
- Run a synthetic restore smoke test

The desktop plugin is bundled in `desktop/` and installed by the Hermes plugin system itself (`hermes plugins install` / `hermes plugins enable`). **No manual copying to `~/.hermes/desktop-plugins/` is required or performed.**

The backend lives in `dashboard/plugin_api.py` and is mounted by the Hermes dashboard plugin system at `/api/plugins/privacy-shield/`.

For a visual walkthrough see `docs/desktop-controls.md`.

## Reasoning Protection v1.7.0 (Pre-Intake)

Privacy-Shield extends protection to **reasoning/thinking blocks** from OpenAI, Anthropic, and Google. These internal thoughts can contain real PII and secrets that never appear in visible output (the [Stolen Thoughts](https://stolen-thoughts.com) problem, 2026).

### How it works (two layers)

**Layer 1 — Pre-Intake Redaction (v1.7.0, closes GB-009):**
- The `post_api_request` hook fires directly after response intake — **before** Hermes persists the turn to `state.db`.
- It mutates reasoning fields (`reasoning`, `reasoning_content`, `reasoning_details`) **in-place on the live assistant message object**.
- Result: the persisted session contains only tokenized reasoning text — no raw-PII window in `state.db`.

**Layer 2 — In-Memory Redaction (v1.6.1, defense-in-depth):**
- The `post_llm_call` hook tokenizes reasoning fields in the `conversation_history` array.
- Covers late consumers that read history after the intake stage.
- Reasoning PII is replaced with tokens before it reaches tools/exporters.

### Configuration

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore  # off | audit | restore (default: restore)
      reasoning_confidence_threshold: 0.85
```

**Limitations:** See [`docs/reasoning-protection.md`](docs/reasoning-protection.md) for coverage details and the (resolved) persistence-limitation history.

> **Data handling note — read this (default behaviour):** by default the
> restore pass writes **real personal data back into replies** on the
> user-facing channels `telegram`, `desktop`, `cli` and `kanban`. Once
> restored, the reply leaves your machine un-redacted. Operators who do not
> want plaintext PII in delivered replies must remove those channels from
> `restore_allowed_channels` or switch restore off.

### Restore-Miss handling, splice repair, kanban channel (v1.7.6)

Tokens that the restore pass cannot resolve on an allowed channel no longer
stay dangling: with `restore_miss_strategy: placeholder` (default) they are
replaced by `[maskiertes PII – nicht wiederherstellbar]` (German default
text; override with `restore_miss_placeholder` for EN deployments — the
text is substituted token-span-only, so glued suffixes survive). Each miss
is logged PII-free (WARNING: session/type/serial, no token string, no
plaintext) and counted (`restore_misses` in `get_metrics()`, Prometheus
`privacy_shield_restore_misses_total`). `keep` preserves the old
leave-the-token-verbatim behaviour.

A model-mangled token (correct serial, broken hash) is repaired from
`(type, serial)` **within the same session only**: exactly one distinct
same-session candidate → original restored, 0 or ≥ 2 distinct candidates
(counter restarts after LRU eviction make collisions expected) →
restore-miss placeholder. Never across sessions; legacy tokens without a
serial never repair (fail-closed). The mapping table gains a nullable
`token_serial` column + `(session_id, type, token_serial)` index; a bounded
lazy backfill migrates legacy rows (≤ 200 rows, once per (session, type)),
and `scripts/backfill_token_serial.py` converges the whole table offline
(resumable, chunked, progress output — a full 61k-row decrypt is host- and
backend-dependent (PBKDF2 ~40–120 ms/row; ~86 ms with hashlib, ~117 ms with
the cryptography backend on the deploy host), which is why operational paths
touch only a few rows per query).

```yaml
plugins:
  entries:
    privacy-shield:
      restore_miss_strategy: placeholder   # placeholder | keep
      restore_miss_placeholder: "[masked PII – cannot be restored]"  # optional EN override
      restore_allowed_channels: ["telegram", "desktop", "cli", "kanban"]
```

> **Warning — an explicit override replaces the entire default list:** an
> explicit `restore_allowed_channels` in the configuration replaces the whole
> default list (`_merge_user_config` overwrites the entire tuple — no auto
> merge). An explicit entry **without** `kanban` silently disables kanban
> restoration — include `kanban` in every explicit entry that should keep
> restoring.

`kanban` is now a default restore channel so board-visible answers can
round-trip. **Trust boundary unchanged:** the chat-ID allowlist
(`allowed_chats` / `allowed_chat_ids` / telegram-send limits) still gates
who can receive restored PII; only the single channel entry was added.
Tool egress (write_file, terminal, MCP, kanban_attach) explicitly stays
non-restoring. Fresh-PII behaviour is preserved (FIX-1B): the
sanitizer-minted tokens for new leaks stay visible and are never restored
or placeholder-substituted.

## Architecture

```
LLM request with PII
    ↓
pre_llm_call() hook  (upstream contract)
    ├─ PDF → pdfplumber → text
    ├─ Image → Tesseract OCR → text
    └─ Plain text directly
    ↓
RegexPIIDetector.scan() — 58 patterns
    ↓   (strict, known cloud provider / paranoid →
    ↓    {"action": "block", "message": ...} turns veto)
Pseudonymizer.replace() — token instead of original
    ↓
MappingTable.store() — in-memory + AES-256-GCM, sanitized prompt STAGED
    ↓
llm_request middleware rewrites the user message in api_kwargs
    ↓
Provider receives only tokens
    ↓
LLM responds with tokens
    ↓
post_api_request() hook          ← v1.7.0: before persistence
    ├─ reasoning fields tokenized on the live message
    └─ state.db receives only tokenized reasoning
    ↓
transform_llm_output() hook
    ↓
MappingTable.restore() — token → original
    ↓
User sees original data (only in whitelisted channels)
```

## Security

- **4 review rounds** (independent profiles: research, validation, architecture, operations, memory, system-admin)
- **1066 tests green** (CI: 3.10/3.11/3.12 + lint + mypy strict + security)
- **0 open CRITICAL/HIGH/MEDIUM findings**
- **AES-256-GCM** with PBKDF2 100k iterations
- **Egress whitelist** prevents accidental PII leaks
- **Bucketed audit log** (SHA-256 hashes instead of plaintext)
- **EU AI Act PDF export** — one-click compliance report from the audit trail
- **Memory-bounded caches** (LRU eviction)

See [docs/SECURITY.md](docs/SECURITY.md) for details.

## Audit PDF Export

Generate a tamper-evident EU AI Act / GDPR compliance report from the JSONL audit log. Reports can be rendered as PDF, CSV or JSON and signed with Ed25519.

### CLI

```bash
# PDF report (unsigned)
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format pdf \
  --output report-2026-08.pdf

# Signed PDF (Ed25519 detached signature)
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format pdf \
  --sign-with ~/.hermes/keys/audit-signing-key.pem \
  --output report-2026-08.pdf

# Machine-readable CSV / JSON
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format csv \
  --output report-2026-08.csv
```

### Python API

```python
from pathlib import Path
from privacy_shield.audit import AuditExporter

exporter = AuditExporter()
result = exporter.export(
    output_path="audit.pdf",
    time_range=("2026-08-01", "2026-08-31"),
    sign=True,
    format="pdf",
    signing_key_path=Path.home() / ".hermes" / "keys" / "audit-signing-key.pem",
)
print(result["output_path"], result["signature"])
```

### Report contents

- Cover page (period, hashed user identifier, generated timestamp)
- Summary (total calls, PII detections, blocked actions, mode changes)
- Token mappings (original hash, token, type, timestamp, session)
- Audit events with severity and bucketed counts
- Detection events (block / warn / restore)
- Mode changes (who changed which mode when)
- Compliance coverage (GDPR Art. 25, 32, 35; EU AI Act Art. 9, 11, 12, 14)
- Test status (passed / failed / skipped / coverage)
- Integrity footer + detached Ed25519 signature (when `--sign-with` is used)

See [docs/eu-ai-act-report.md](docs/eu-ai-act-report.md) for the mapping logic.

## Documentation

- [User Guide](docs/USER-GUIDE.md) — comprehensive guide
- [Installation](docs/INSTALL.md) — setup + Hermes integration
- [Security](docs/SECURITY.md) — security properties + threat model
- [GDPR](docs/dsgvo-mapping.md) — processor agreement + records templates
- [Reasoning Protection](docs/reasoning-protection.md) — v1.7.0 pre-intake redaction (GB-009 closed)
- [Changelog](CHANGELOG.md) — version history

## Profile Activation

Profiles are enabled one at a time — no config.yaml rewriting:

```bash
hermes -p <profile> plugins enable privacy-shield
```

## Version Sync

`plugin.yaml` is the single-source-of-truth for the plugin version. `pyproject.toml` and `__init__.py` are synced via `scripts/sync_version.py`:

```bash
python3 scripts/sync_version.py          # sync to plugin.yaml version
python3 scripts/sync_version.py --check  # CI gate: exit 1 if drift
python3 scripts/sync_version.py --set 1.8.0  # bump all three files
```

## License

MIT License — see [LICENSE](LICENSE).

## Support

- Repository: https://github.com/MOTHR/hermes-privacy-shield
- Issues: GitHub Issues
- GDPR questions: docs/AVV-Checkliste.md

---

> **Deutsch:** [README.de.md](README.de.md) — German version
