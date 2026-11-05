# hermes-security-suite

MOTHR security plugins for Hermes Agent — Defense-in-Depth for AI agents.

## Packages

### privacy-shield
**DSGVO-konformer PII-Tokenizer.** Live-Masking auf Telegram Desktop und CLI, AES-256-GCM Mapping-Store, restore-miss Placeholder, Session-Fuzzed-Restore, Desktop-Controls, PDF-OCR.

### injection-shield
**Defense-in-Depth gegen Prompt-Injection.** Tool-Result-Scanning, Credential-Leak-Detectors, Instruction-Firewall, Telegram-Audit-Notify, Desktop-Controls.

## Install

One install gives you agent protection and a desktop UI for both packages:

```bash
# privacy-shield
pip install privacy-shield

# injection-shield
pip install injection-shield
```

Or install the latest from source:

```bash
# privacy-shield
git clone https://github.com/MOTHR/hermes-privacy-shield.git
cd hermes-privacy-shield
pip install -e .

# injection-shield
git clone https://github.com/MOTHR/hermes-injection-shield.git
cd hermes-injection-shield
pip install -e .
```

## Security Audits

Both packages have undergone independent security review. See [SECURITY-AUDIT.md](SECURITY-AUDIT.md) for the full audit report.
