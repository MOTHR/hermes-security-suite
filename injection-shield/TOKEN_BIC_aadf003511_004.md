# TOKEN_BIC_aadf003511_004 — Injection-Shield Security Policy

Status: security policy for public release (Hermes security-suite, catalog admission)
Plugin: injection-shield (version 0.7.1, license MIT)

## Purpose

Injection-Shield is an inline defense plugin for Hermes agents. It protects
the agent against prompt-injection attacks arriving through tool outputs and
other untrusted content, and audits risky tool calls.

## What the plugin does

- Scans prompts and tool outputs for known prompt-injection patterns
  (role hijack, system-prompt exfiltration, concealment, credential leaks).
- Validates LLM responses before they reach the user.
- Audits risky tool calls in hook phases `pre_tool_call` / `post_tool_call`.
- Runs before/after privacy-shield through hook priorities so that it sees
  original content on `pre_llm_call` and restored content on `post_llm_call`.
- Operates in three modes: `block`, `alert`, `log`.

## What the plugin reads

- Prompt and tool-output content already flowing through the Hermes agent
  (in-process only).
- Its own configuration from the Hermes plugin config system
  (`~/.hermes/config.yaml`, section `plugins.entries.injection-shield`).

## What the plugin writes

- An audit log in the Hermes data directory, rotated by size
  (`audit_log_max_bytes`, default 10 MiB) and pruned after
  `audit_log_retention_days` (default 90) to respect storage limitation.
- No files outside the Hermes data directory.

## Network egress

- None by default. Detection and audit are purely local.

## Telegram alerting (optional, opt-in)

- Disabled by default (`telegram.enabled: false`, "Privacy by Default").
- If the operator enables it, alert payloads are sent to a Telegram chat
  configured by the operator (`telegram.chat_id` or
  `INJECTION_SHIELD_TELEGRAM_CHAT_ID`). The bot token is the standard
  `TELEGRAM_BOT_TOKEN` env var.
- No other network communication exists in any mode.

## Credentials

- The plugin never embeds, stores, or requests credentials.
- All credentials flow exclusively through established Hermes routes
  (Hermes secrets/config), never through plugin-owned storage.

## Verification

- CI runs the full detector test suite for every change (Python 3.10–3.12).
- Catalog admission requires the Hermes plugin security scan to report no
  `dangerous` findings; `caution` findings are disclosed in the catalog entry.
