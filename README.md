# hermes-security-suite

🌐 [Deutsch](README.de.md) | English

Security plugins for Hermes Agent by MOTHR: data privacy and prompt-injection defense for your agent's Telegram, Desktop and CLI surfaces.

## Packages

### [privacy-shield](privacy-shield/README.md)

**GDPR-compliant PII tokenizer.** Masks personal data (names, emails, phone numbers, credentials, IBANs, addresses) in everything the agent sends to a user — Telegram, Desktop, CLI — and restores the original values deterministically, session-scoped and fail-closed.

- AES-256-GCM mapping store (PBKDF2, 600k iterations), key optional — without a key the plugin degrades gracefully to masking-only
- Restore-miss placeholder: unresolvable tokens never leak, they degrade to `[masked PII]`
- Session-fuzzed restore for model-copied token variants (same session, same type+serial only)
- Desktop-controls pane, PDF/OCR preprocessing, size guardrails for attachments

### [injection-shield](injection-shield/README.md)

**Defense-in-depth against prompt injection.** Wraps untrusted tool results, inspects LLM output, and audits risky tool calls.

- 4 layers: content tagging (`post_tool_call`), anti-injection firewall (`pre_llm_call`), output validation (`post_llm_call`), risky-tool audit (`pre_tool_call`)
- 7 detector layers incl. credential-leak and tool-call patterns, 410+ tests
- Desktop-controls pane, Telegram alerts with severity gate and rate limiting
- Shares the token-format contract with privacy-shield

## Install

Each package installs with agent hooks **and** its desktop-controls pane in one step:

```bash
# from the suite root
pip install -e ./privacy-shield
pip install -e ./injection-shield
```

Or straight from GitHub:

```bash
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=privacy-shield
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
```

The desktop controls are picked up by the Hermes Desktop app automatically (unified-package desktop half).

## Security Audits

Both packages have undergone an independent multi-agent security audit (confirmed findings fixed, re-audited clean, no open HIGH). See [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

## Reporting Security Issues

Do not file public issues for vulnerabilities. Contact the MOTHR security team directly.
