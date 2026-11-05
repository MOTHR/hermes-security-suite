"""OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping for Privacy-Shield.

This module is the SINGLE-SOURCE-OF-TRUTH for which Privacy-Shield
detections map to which OWASP LLM risks and MITRE ATLAS techniques.
Every event type emitted by the plugin gets an automatic ``owasp_risk``
and ``atlas_technique`` code so compliance auditors can filter
"all LLM02 events" or "all AML.T0024 events" without manual lookup.

The mapping table below is derived from:
  - OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
  - MITRE ATLAS: https://atlas.mitre.org/techniques/AML.T0024

Version history
---------------
v1.4.1 — initial mapping (2026-08-23)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Constants ────────────────────────────────────────────────────────────────

OWASP_LLM01 = "LLM01"  # Prompt Injection
OWASP_LLM02 = "LLM02"  # Sensitive Information Disclosure
OWASP_LLM03 = "LLM03"  # Training Data Poisoning
OWASP_LLM04 = "LLM04"  # Model Denial of Service
OWASP_LLM05 = "LLM05"  # Improper Output Handling
OWASP_LLM06 = "LLM06"  # Excessive Agency
OWASP_LLM07 = "LLM07"  # System Prompt Leakage
OWASP_LLM08 = "LLM08"  # Vector and Embedding Weaknesses
OWASP_LLM09 = "LLM09"  # Misinformation
OWASP_LLM10 = "LLM10"  # Model Theft

ATLAS_AML_T0024 = "AML.T0024"  # Data Leakage via LLM
ATLAS_AML_T0051 = "AML.T0051"  # Adversarial ML — Prompt Injection


@dataclass(frozen=True, slots=True)
class OwaspAtlasMapping:
    """One row in the canonical mapping table."""

    owasp_risk: str          # e.g. "LLM02"
    owasp_name: str          # e.g. "Sensitive Information Disclosure"
    atlas_technique: str     # e.g. "AML.T0024"
    atlas_name: str          # e.g. "Data Leakage via LLM"
    detection_name: str      # Privacy-Shield event / detector name
    plugin_version: str      # Privacy-Shield version where mapping is active
    description: str           # One-line explanation for auditors


# ── Canonical mapping table (Privacy-Shield scope) ──────────────────────────
# Every event type emitted by the plugin is listed here with its OWASP + ATLAS code.

_OWASP_ATLAS_MAP: dict[str, OwaspAtlasMapping] = {
    # LLM02 — Privacy-Shield's primary coverage area
    "pseudonymization_applied": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM02,
        owasp_name="Sensitive Information Disclosure",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Pseudonymization (regex + Presidio)",
        plugin_version="1.4.0",
        description="PII detected and masked before LLM egress; prevents sensitive data disclosure.",
    ),
    "output_pii_detected": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM02,
        owasp_name="Sensitive Information Disclosure",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Output PII Detection (post-LLM scan)",
        plugin_version="1.4.0",
        description="PII detected in LLM output and blocked/restored; prevents egress leakage.",
    ),
    "blocked_action": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM02,
        owasp_name="Sensitive Information Disclosure",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Blocked Action (strict/paranoid mode)",
        plugin_version="1.4.0",
        description="High-confidence PII triggered a hard block; no data reached the LLM.",
    ),
    "strict_mode_block": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM02,
        owasp_name="Sensitive Information Disclosure",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Strict Mode Block",
        plugin_version="1.4.0",
        description="Strict-mode threshold exceeded; action blocked to prevent disclosure.",
    ),
    "paranoid_mode_block": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM02,
        owasp_name="Sensitive Information Disclosure",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Paranoid Mode Block",
        plugin_version="1.4.0",
        description="Paranoid-mode threshold exceeded; action blocked to prevent disclosure.",
    ),
    # LLM07 — System Prompt Leakage (via token-restore loop detection)
    "restore": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM07,
        owasp_name="System Prompt Leakage",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Token Restore (round-trip)",
        plugin_version="1.4.0",
        description="Token restored after LLM response; no leakage via prompt replay.",
    ),
    "token_restore_loop": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM07,
        owasp_name="System Prompt Leakage",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Token Restore Loop Detection",
        plugin_version="1.4.0",
        description="Detected potential system-prompt leakage through repeated restore attempts.",
    ),
    # LLM06 — Excessive Agency (cross-plugin token sync is a mitigation)
    "mode_change": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Mode Change (risk escalation)",
        plugin_version="1.4.0",
        description="Operating-mode changed to higher-risk; demonstrates human oversight per EU AI Act Art. 14.",
    ),
    "approval_required": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Approval Required (human-in-the-loop)",
        plugin_version="1.4.0",
        description="High-impact action requires human approval before execution.",
    ),
    "approval_granted": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Approval Granted",
        plugin_version="1.4.0",
        description="Human explicitly approved a high-impact action.",
    ),
    "approval_denied": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Approval Denied",
        plugin_version="1.4.0",
        description="Human explicitly denied a high-impact action; excessive agency prevented.",
    ),
    "human_review": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Human Review",
        plugin_version="1.4.0",
        description="Event flagged for human review; oversight logged.",
    ),
    # Cross-plugin token contract (mitigates excessive agency via isolation)
    "cross_plugin_token_sync": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0024,
        atlas_name="Data Leakage via LLM",
        detection_name="Cross-Plugin Token Sync",
        plugin_version="1.4.0",
        description="Privacy-Shield and Injection-Shield tokens exchanged safely; scope isolation maintained.",
    ),
    # Fallback / unknown event types
    "unknown": OwaspAtlasMapping(
        owasp_risk="",
        owasp_name="",
        atlas_technique="",
        atlas_name="",
        detection_name="Unknown Event",
        plugin_version="1.4.0",
        description="Event type not yet mapped to OWASP / ATLAS.",
    ),
}


def get_mapping(event_name: str) -> OwaspAtlasMapping:
    """Return the OWASP/ATLAS mapping for ``event_name``.

    Falls back to the ``unknown`` entry if the event type is not yet
    catalogued. Never raises.
    """
    return _OWASP_ATLAS_MAP.get(event_name, _OWASP_ATLAS_MAP["unknown"])


def all_mappings() -> list[OwaspAtlasMapping]:
    """Return every defined mapping (for reports / CLI listing)."""
    return list(_OWASP_ATLAS_MAP.values())


def mappings_by_owasp(owasp_risk: str) -> list[OwaspAtlasMapping]:
    """Return all mappings matching ``owasp_risk`` (e.g. ``LLM02``)."""
    return [m for m in _OWASP_ATLAS_MAP.values() if m.owasp_risk == owasp_risk]


def mappings_by_atlas(atlas_technique: str) -> list[OwaspAtlasMapping]:
    """Return all mappings matching ``atlas_technique`` (e.g. ``AML.T0024``)."""
    return [m for m in _OWASP_ATLAS_MAP.values() if m.atlas_technique == atlas_technique]


def enrich_event(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Add ``owasp_risk``, ``owasp_name``, ``atlas_technique``, ``atlas_name``
    to an audit-event dict based on its ``event`` field.

    This is a pure function — the input dict is copied.
    """
    result = dict(event_dict)
    event_name = result.get("event", "")
    mapping = get_mapping(event_name)
    result["owasp_risk"] = mapping.owasp_risk
    result["owasp_name"] = mapping.owasp_name
    result["atlas_technique"] = mapping.atlas_technique
    result["atlas_name"] = mapping.atlas_name
    return result


# ── Compliance summary helpers ───────────────────────────────────────────────


def owasp_coverage_summary() -> dict[str, dict[str, Any]]:
    """Return a summary dict for compliance reports.

    Keys are OWASP risk codes (``LLM01``..``LLM10``); values contain
    ``covered`` (bool), ``detection_names`` (list), and ``atlas_techniques`` (set).
    """
    summary: dict[str, dict[str, Any]] = {}
    for code in (f"LLM{i:02d}" for i in range(1, 11)):
        ms = mappings_by_owasp(code)
        summary[code] = {
            "covered": bool(ms),
            "detection_names": [m.detection_name for m in ms],
            "atlas_techniques": sorted({m.atlas_technique for m in ms if m.atlas_technique}),
        }
    return summary


def atlas_coverage_summary() -> dict[str, dict[str, Any]]:
    """Return a summary dict keyed by ATLAS technique code."""
    techniques = sorted({m.atlas_technique for m in _OWASP_ATLAS_MAP.values() if m.atlas_technique})
    return {
        tech: {
            "covered": True,
            "detection_names": [m.detection_name for m in mappings_by_atlas(tech)],
            "owasp_risks": sorted({m.owasp_risk for m in mappings_by_atlas(tech) if m.owasp_risk}),
        }
        for tech in techniques
    }
