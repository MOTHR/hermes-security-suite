🌐 [English](README.md) | Deutsch

# injection-shield

Prompt-injection defense-in-depth plugin for Hermes Agent.

**Version:** 0.6.0 (2026-09-21) — 7 detector layers · 410+ tests · Desktop-Controls pane · Telegram alerting with severity gate + rate limiting · sync hook contract (Hermes v0.20.5+)

## What it does

`injection-shield` adds four defense layers to every Hermes turn:

1. **Layer 1 — Content tagging** (`post_tool_call`): wraps outputs from
   `web_extract`, `web_search`, and any `mcp__*` tool in
   `<untrusted_tool_result>` tags so the LLM treats them as data, not
   instructions.
2. **Layer 2 — Anti-injection firewall** (`pre_llm_call`): injects a
   system-prompt firewall that reminds the model to ignore injected
   directives.
3. **Layer 3 — Output validation** (`post_llm_call`): scans the LLM response
   for credential leaks and user-action directives; blocks the response in
   `enforcement` mode and alerts.
4. **Layer 4 — Risky-tool audit** (`pre_tool_call`): audits/blockscalls to
   risky tools (`terminal`, `write_file`) when their arguments contain
   injection patterns.

## Hooks

- `pre_tool_call`
- `post_tool_call`
- `pre_llm_call`
- `post_llm_call`

## Desktop Controls (v0.5.0)

Injection-Shield ships an official desktop plugin so you can tune settings in
the Hermes Desktop app instead of editing YAML:

- Enable/disable the plugin
- Switch operating mode (`audit` / `enforcement`)
- Manage allowed domains, risky tools, and tool-call detector categories
- Configure Telegram alerting (enabled, chat id, minimum severity)
- Adjust audit log rotation and retention
- Run a synthetic injection-detector smoke test

The desktop plugin is bundled in `desktop-plugin/` and automatically copied to
`~/.hermes/desktop-plugins/injection-shield-controls/` when the package is
installed (`pip install` or `pip install -e .  # in der Monorepo-Paketwurzel ausgefuehrt`). The backend lives in
`dashboard/plugin_api.py` and is mounted by the Hermes dashboard plugin system
at `/api/plugins/injection-shield/`.

To use it, open the Hermes Desktop app, look for the **Injection-Shield** pane
(usually on the right), and adjust the controls. Changes are written to
`~/.hermes/config.yaml` under `plugins.entries.injection-shield` and take effect
on the next plugin reload.

## Configuration

Add to `~/.hermes/config.yaml` (or any profile config) under
`plugins.entries.injection-shield`:

```yaml
plugins:
  enabled:
    - injection-shield
  entries:
    injection-shield:
      enabled: true
      mode: audit              # audit = log only; enforcement = block
      allowed_domains:
        - api.openai.com
        - api.anthropic.com
        - api.x.ai
        - ollama.com
        - hermes-agent.nousresearch.com
        - api.telegram.org
      risky_tools:
        - terminal
        - write_file
      telegram:
        enabled: true
        chat_id: YOUR_CHAT_ID_HERE   # Replace with your Telegram chat_id.
                                       # NEVER use a real chat_id in the
                                       # committed config — see
                                       # docs/DSGVO-KONZEPT.md and the
                                       # INJECTION_SHIELD_TELEGRAM_CHAT_ID
                                       # env-var.
        min_severity: medium
      audit_log_path: ~/.hermes/profiles/{profile}/workspace/logs/prompt-injection-attempts.log
```

All fields are optional — the plugin falls back to safe defaults.

### Modes

- `audit` (default): logs violations, never blocks. Use this for the first
  24 hours to find false positives.
- `enforcement`: blocks risky tool calls and replaces violating LLM outputs.

### Allowed domains

Terminal outputs that contain URLs outside the allowed list are logged and
alerted. Add domains to `allowed_domains` to suppress these alerts.

### Telegram alerts

Set `TELEGRAM_BOT_TOKEN` in the profile `.env` or environment. If the token is
missing, alerts are silently skipped — the plugin never crashes.

## Installation

### From GitHub (any machine with Python ≥3.10)

```bash
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
injection-shield --version
```

### Editable install for local development

```bash
git clone https://github.com/MOTHR/hermes-security-suite.git
cd hermes-security-suite/injection-shield
pip install -e .  # in der Monorepo-Paketwurzel ausgefuehrt
```

## Cross-Plugin Contract

Injection-Shield and [privacy-shield (suite monorepo)](https://github.com/MOTHR/hermes-security-suite) are now independent repositories, but they share a token-format contract.

- Privacy-Shield emits pseudonym tokens as `TOKEN_<TYPE>_<10-hex>_<3-digit>`.
- Injection-Shield accepts this format via `_TOKEN_PATTERN` in
  `detectors/injection_patterns.py`.
- Both repositories must upgrade this format together. The canonical
  source-of-truth is `privacy_shield.TOKEN_FORMAT_PATTERN`.

## Testing

```bash
cd hermes-security-suite/injection-shield
pytest tests/ -v
```

## False positives

If legitimate content is flagged:

1. Check the audit log for the exact pattern match.
2. Add the domain or tool to the relevant whitelist.
3. Consider switching a specific risky tool to audit-only by setting
   `mode: audit`.

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Defense-in-depth layers, hooks, data flow, module layout
- [`docs/INSTALL.md`](docs/INSTALL.md) — Three install variants, Hermes config, Telegram opt-in, verification
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — Modes, audit-log, daily checks, Telegram alerts, performance budget
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — False positives, bypass discovery, plugin crash, log growth
- [`docs/DSGVO-KONZEPT.md`](docs/DSGVO-KONZEPT.md) — GDPR Art. 5/25/32 evaluation, TOMs, AVV, Art. 15/17

## License

MIT
