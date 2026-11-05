"""Runtime surface verification for Privacy-Shield v1.6.1 reasoning redaction."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from privacy_shield.config import PrivacyShieldConfig, ReasoningBlockConfig
from privacy_shield.plugin import PrivacyShieldPlugin


def main() -> int:
    plugin = PrivacyShieldPlugin(
        config=PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            encryption_key="test-key-32-bytes-xxxxxxxxxxxxx",
            storage_mode="memory",
            reasoning=ReasoningBlockConfig(mode="restore", confidence_threshold=0.85),
        )
    )

    shared = {
        "role": "assistant",
        "content": "OK.",
        "reasoning": "Ich schicke die Zugangsdaten an max.mustermann@example.com.",
    }
    conversation_history = [shared]
    messages = [shared]

    plugin.post_llm_call(
        assistant_response="OK.",
        session_id="verify-surface",
        model="openai:gpt-4o",
        platform="test",
        conversation_history=conversation_history,
    )

    ok = True
    if "max.mustermann@example.com" in messages[0]["reasoning"]:
        print("FAIL: reasoning still contains plaintext email")
        ok = False
    if messages[0]["reasoning"] is not conversation_history[0]["reasoning"]:
        print("FAIL: mutation did not reach shared message dict")
        ok = False
    if not plugin.mapper.known_original_values("verify-surface"):
        print("FAIL: mapping table has no entries")
        ok = False

    if ok:
        print("PASS: reasoning redaction reaches shared messages")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
