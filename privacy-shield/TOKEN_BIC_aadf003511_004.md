# TOKEN_BIC_aadf003511_004 — Privacy-Shield Security Policy

Status: security policy for public release (Hermes security-suite, catalog admission)
Plugin: privacy-shield (version 1.8.0, requires_hermes ">=0.21.5", license MIT)

## Purpose

Privacy-Shield is a pseudonymization plugin for Hermes agents. It replaces
personal data (PII) in LLM output with opaque pseudonymization tokens
(privacy-shield format `TOKEN_<TYPE>_<HASH>_<SERIAL>`) before the content
reaches a model or another egress route, and restores the original values
exclusively on operator-approved channels.

## What the plugin does

- Tokenizes PII detected in LLM output (regex detectors, optional Presidio,
  name detection) and maintains session-scoped pseudonym mappings.
- Runs as a Hermes hook chain member: `pre_llm_call`, `post_llm_call`,
  `post_api_request`, `transform_llm_output`, `on_session_finalize`
  (hook priority 200 — deliberately after injection-shield, so prompt-injection
  analysis sees original content on `pre_llm_call` and restored content later).
- Pre-processes documents locally (PDF via pdfplumber, images via local OCR)
  and writes sanitized copies to the operator's Hermes restore directories.
- Restores tokens only when the egress target matches an operator-configured
  allowlist of channels (for example Telegram, desktop UI, CLI). Every other
  egress route (file writes, kanban, terminal, MCP) receives pseudonymized
  text only.
- Redacts reasoning artifacts on response intake (`post_api_request`).
- Purges session mappings at real session boundaries (retention = session
  lifetime, DSGVO Art. 5(1)(e)); a TTL acts as a crash fallback.
- No plaintext PII is persisted: the persistent audit trail records
  bucketed counts and SHA-256-hashed session identifiers instead.

## What the plugin reads

- LLM traffic already flowing through the Hermes agent (in-process hooks).
- File content passed to preprocessing (PDF/image) — sanitized locally.
- Its own configuration via the Hermes plugin config system
  (`plugin.yaml` settings / Desktop-Controls), not from external sources.

## What the plugin writes

- A persistent audit trail (JSONL, chmod 600) and an operator log
  (rotating handler, 10 MiB rotation, 5 backups) under the Hermes profile
  workspace. Auto-pruned after `audit_log_retention_days` (default 90).
- Sanitized PDF/image copies under `~/.hermes/privacy/restore/...` (chmod 700).
- No files outside the Hermes data directories.

## Network egress

- None by default. Detection, tokenization, restore and audit are purely local
  processes.

## Telegram alerting (optional, opt-in)

- Disabled by default. If an operator runs the provided cron alert scripts,
  the script path is configured via the `PRIVACY_SHIELD_ALERT_SCRIPT`
  environment variable (default: `$HERMES_HOME/scripts/telegram-alert.sh`);
  the chat target is operator-configured, never hard-coded. No other network
  communication exists in any mode.

## Credentials

- The plugin never embeds, stores, or requests credentials.
- All credentials flow exclusively through established Hermes routes
  (Hermes secrets/config), never through plugin-owned storage.

## Verification

- CI runs lint, type checks, a security scan and the full test suite for
  every change (Python 3.10–3.12).
- Hermes catalog admission requires `hermes plugins validate` to pass and the
  plugin security scan to report no `dangerous` findings; `caution` findings
  are disclosed in the catalog entry.
