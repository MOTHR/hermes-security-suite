"""Generate the example audit report PDF."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from privacy_shield.audit_pdf import ReportPeriod, generate_audit_pdf, load_article_mapping


def make_event(i: int) -> dict:
    ts = datetime(2026, 8, 15, 8, 0, 0, tzinfo=timezone.utc).timestamp() + i * 3600
    return {
        "ts": ts,
        "event": "pseudonymization_applied" if i % 5 != 0 else "blocked_action",
        "session_id_hash": f"sess-{i:04d}-" + "a" * 8,
        "mode": "limited",
        "model": "openai:gpt-4o",
        "platform": "telegram",
        "pii_types": ["email"] if i % 2 == 0 else (["phone"] if i % 3 == 0 else []),
        "masked_count_bucket": "1-10" if i % 5 != 0 else "0",
    }


if __name__ == "__main__":
    events = [make_event(i) for i in range(25)]
    output = Path("examples/audit-report-sample.pdf")
    output.parent.mkdir(parents=True, exist_ok=True)
    sig = generate_audit_pdf(
        output,
        events,
        ReportPeriod(
            datetime(2026, 8, 1).date(),
            datetime(2026, 8, 31).date(),
        ),
        "sha256:sample-deadbeef",
        articles=load_article_mapping(),
    )
    print(f"Generated {output} with signature {sig}")
