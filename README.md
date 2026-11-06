# hermes-security-suite

🌐 [Deutsch](README.de.md) | English

**Security Suite for Hermes Agent by MOTHR** — two battle-tested plugins that together cover the two ways an agent leaks data or gets manipulated: **PII in egress traffic** (Privacy-Shield) and **prompt injection through untrusted content** (Injection-Shield).

> **⭐ Featured: Stolen-Thoughts Reasoning Protection** — Privacy-Shield is, to our knowledge, the only Hermes plugin that tokenizes PII inside model *reasoning/thinking blocks* before anything is persisted. Model reasoning regularly contains real names, emails, and credentials that never show up in the visible reply — the ["Stolen Thoughts"](https://stolen-thoughts.com) problem (2026), and it affects **any cloud provider that surfaces model reasoning**. The redaction is provider-agnostic: it hooks response intake and matches reasoning fields (`reasoning`, `reasoning_content`, `reasoning_details`, Codex reasoning items) regardless of vendor — verified with OpenAI, Anthropic, and Google. Suite hooks redact them **pre-intake**, so no raw-PII window ever reaches `state.db`. See [Reasoning Protection](#-stolen-thoughts-reasoning-protection).

> **⚖️ Why European businesses need this:** In the EU, GDPR and EU AI Act compliance is not a nice-to-have for agents — it is a legal precondition. An agency that sends personal data to cloud LLMs or executes instructions from untrusted content is hard to deploy on real business data under Art. 5/25/32 GDPR and the EU AI Act's transparency and logging obligations. This suite turns a Hermes agent into an agent you can actually put in front of customers and employees: tokenized egress, whitelisted restore, tamper-evident audit trails, and compliance reports you can hand to a DPO or auditor.

## Packages

| Package | What it protects against | Current release |
|---|---|---|
| [privacy-shield](privacy-shield/README.md) | PII egress: names, emails, phones, IBANs, crypto wallets, tokens leak into LLM traffic, reasoning blocks, PDFs and screenshots | **1.8.0** |
| [injection-shield](injection-shield/README.md) | Prompt injection: malicious instructions hidden in web pages, tool results, and LLM responses | **0.7.1** |

## What each package does

### [privacy-shield](privacy-shield/README.md) — GDPR-compliant PII tokenizer

Replaces personal data with deterministic tokens (`TOKEN_EMAIL_a3f8b2c41d_003`) before the provider sees it, and restores originals **only** in channels you whitelist. Fail-closed: anything unresolvable degrades to `[masked PII]`, never to plaintext.

**Detection & processing**
- **58 detection patterns** across 7 categories: email, phone, IBAN, crypto wallets, JWT/OAuth tokens, GitHub PATs, MAC/IMEI/IMSI and more
- **Text, Markdown and code** in one pipeline
- **PDF pipeline** — extracts text (pdfplumber), tokenizes, produces a sanitized PDF
- **Image OCR** — JPG/PNG/HEIC/WebP/TIFF/BMP via Tesseract, multi-language (deu+eng default)
- **Unicode normalization** (NFKC + homoglyph mapping) so lookalike characters don't slip through
- Cache-bypass tag for local reads — local data is not masked because it never leaves the machine

**Mapping security & restore**
- **AES-256-GCM** encrypted mapping store with **PBKDF2 (600k iterations)**
- **Restore-miss placeholder** — unresolvable tokens degrade to `[masked PII]` with a `restore_miss` metric; they never leak
- **Session-fuzzed restore** — repairs model-copied token variants (same session, same type+serial only; serial re-derived from encrypted content, tamper-excluded)
- **Egress whitelist** — restore only in channels you allow (e.g. your Telegram chat ID); everything else stays masked

**Operation**
- Five modes: `off / audit / limited / strict / paranoid`
- Provider detection: Ollama-local traffic bypasses the shield (no cloud egress = nothing to protect)
- Desktop Controls pane: mode, confidence threshold, restore channels, PDF/OCR toggles, restore smoke test

### [injection-shield](injection-shield/README.md) — defense-in-depth against prompt injection

Four hooks around every Hermes turn:

1. **Content tagging** (`post_tool_call`) — wraps `web_extract`, `web_search` and MCP results in `<untrusted_tool_result>` tags so the model treats that content as data, not instructions
2. **Anti-injection firewall** (`pre_llm_call`) — system-prompt firewall against injected directives
3. **Output validation** (`post_llm_call`) — scans responses for credential leaks and user-action directives; blocks in `enforcement` mode
4. **Risky-tool audit** (`pre_tool_call`) — inspects calls to `terminal`/`write_file` for injection patterns before execution

Plus: **7 detector layers** (credential-leak and tool-call patterns among them, 410+ tests), Telegram alerts with severity gate and rate limiting, audit log with rotation and retention, an allowed-domains list, and a Desktop Controls pane (`audit`/`enforcement` switch, detector categories, smoke test).

## ⭐ Stolen-Thoughts Reasoning Protection

Reasoning/thinking blocks can contain real PII and secrets that never appear in the visible output. The "Stolen Thoughts" window is **provider-agnostic** — it opens wherever a provider surfaces model reasoning. Privacy-Shield closes it with two layers:

- **Layer 1 — Pre-intake redaction:** the `post_api_request` hook fires directly after response intake, **before** Hermes persists the turn. Reasoning fields (`reasoning`, `reasoning_content`, `reasoning_details`) are tokenized in-place on the live message → the persisted session contains tokenized reasoning only.
- **Layer 2 — In-memory redaction:** the `post_llm_call` hook also tokenizes reasoning inside `conversation_history`, so late consumers (tools, exporters) never see raw reasoning PII.

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore    # off | audit | restore (default: restore)
      reasoning_confidence_threshold: 0.85
```

Details and coverage: [`privacy-shield/docs/reasoning-protection.md`](privacy-shield/docs/reasoning-protection.md).

## Install

Each package installs with agent hooks **and** its Desktop Controls pane in one step (unified package — the Hermes Desktop app copies the desktop half automatically):

```bash
# suite checkout, editable
pip install -e ./privacy-shield
pip install -e ./injection-shield

# or straight from GitHub (Python ≥ 3.10)
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=privacy-shield
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
```

Verify:

```bash
privacy-shield scan "Contact: alice@example.com"
injection-shield --version
hermes plugins validate
```

## Configuration (short form)

```yaml
plugins:
  enabled:
    - privacy-shield
    - injection-shield
  entries:
    privacy-shield:
      mode: strict
      restore_allowed_channels:
        - telegram:YOUR_CHAT_ID   # tokens restore only here
    injection-shield:
      mode: audit                # start in audit for 24h, then enforcement
      allowed_domains: [api.openai.com, api.anthropic.com, ollama.com]
      telegram:
        enabled: true
        min_severity: medium
```

## Compliance & reporting

- GDPR/DSGVO out of the box: processor-agreement checklist and records template ([`privacy-shield/docs/dsgvo-mapping.md`](privacy-shield/docs/dsgvo-mapping.md))
- EU AI Act / GDPR compliance report from the audit trail — PDF/CSV/JSON, Ed25519-signed, one command: `privacy-shield audit-export --from 2026-08-01 --to 2026-08-31 --format pdf`

## Security & quality

- Independent multi-agent security audit across both packages; confirmed findings fixed, re-audited clean — see [SECURITY-AUDIT.md](SECURITY-AUDIT.md)
- Over 1,000 pytest tests in privacy-shield, 410+ in injection-shield; CI on Python 3.10–3.12 with lint and mypy strict
- Shared token-format contract (`TOKEN_<TYPE>_<10-hex>_<serial>`) between both packages, source of truth in code
- Bucketed audit log (SHA-256 hashes instead of plaintext), memory-bounded caches, fail-closed defaults throughout

## Documentation

- [`privacy-shield/docs/`](privacy-shield/docs/) — user guide, install, security, GDPR, reasoning protection
- [`injection-shield/docs/`](injection-shield/docs/) — architecture, install, operations, troubleshooting
- [SECURITY-AUDIT.md](SECURITY-AUDIT.md) — audit methodology and findings ledger (bilingual)

## License & support

MIT — see [LICENSE](LICENSE). Do **not** file public issues for vulnerabilities; contact the MOTHR maintainers instead.

---

> **Deutsch:** [README.de.md](README.de.md)
