"""OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping for Injection-Shield.

Single-source-of-truth for which Injection-Shield detections map to
which OWASP LLM risks and MITRE ATLAS techniques. Every audit-log entry
and CLI listing uses this table.

References:
  - OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
  - MITRE ATLAS: https://atlas.mitre.org/techniques/AML.T0051

Version history
---------------
v0.3.3 — initial mapping (2026-08-23)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── OWASP constants ────────────────────────────────────────────────────────
OWASP_LLM01 = "LLM01"  # Prompt Injection
OWASP_LLM04 = "LLM04"  # Model Denial of Service
OWASP_LLM06 = "LLM06"  # Excessive Agency

# ── ATLAS constants ────────────────────────────────────────────────────────
ATLAS_AML_T0051 = "AML.T0051"  # Adversarial ML — Prompt Injection


@dataclass(frozen=True, slots=True)
class OwaspAtlasMapping:
    """One row in the canonical mapping table."""

    owasp_risk: str
    owasp_name: str
    atlas_technique: str
    atlas_name: str
    detector_name: str
    plugin_version: str
    description: str


# ── Mapping by detector / layer ─────────────────────────────────────────────
# Keys are the ``layer`` values passed to ``_log_attempt``.

_OWASP_ATLAS_MAP: dict[str, OwaspAtlasMapping] = {
    # pre_llm_call — Layer 1: Instruction Firewall + Pattern Detection
    "pre_llm_call": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="InjectionPatternDetector + InstructionFirewall",
        plugin_version="0.3.3",
        description="Pattern-based prompt-injection detection before LLM call; 66+ red-team-validated patterns.",
    ),
    # pre_tool_call — Layer 2: Tool Call Validation
    "pre_tool_call": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="ToolCallPatternDetector + CredentialLeakDetector",
        plugin_version="0.3.3",
        description="Tool-call argument validation and credential-exfiltration prevention.",
    ),
    # post_llm_call — Layer 3: Output Validation
    "post_llm_call": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="CredentialLeakDetector + ContentTagger",
        plugin_version="0.3.3",
        description="Post-LLM output scanning for leaked credentials and injection payloads.",
    ),
    # post_tool_call — Layer 4: Tool Result Validation
    "post_tool_call": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="OutputValidator + ZeroWidthDetector",
        plugin_version="0.3.3",
        description="Tool-result validation and steganographic payload detection.",
    ),
    # Circuit-breaker / loop detection (LLM04)
    "circuit_breaker": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM04,
        owasp_name="Model Denial of Service",
        atlas_technique="",
        atlas_name="",
        detector_name="Loop Detection / Circuit-Breaker",
        plugin_version="0.3.3",
        description="Automatic circuit-breaker on excessive recursive tool calls; prevents resource exhaustion.",
    ),
    # Excessive Agency (LLM06)
    "excessive_agency": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="Risky-Pattern-Detection + Tool-Risk-List",
        plugin_version="0.3.3",
        description="Detection of tool calls that exceed the agent's authorized scope.",
    ),
    # ── v0.6.0 layers (M3, Seraph review) ─────────────────────────────────
    # GAP-5: every tool result scanned (cross-agent channels)
    "tool_result_scan": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="DetectorChain (all layers)",
        plugin_version="0.6.0",
        description="Injection-pattern scan of every tool result, including cross-agent channels (kanban bodies, CLI output).",
    ),
    # GAP-6: untrusted content scan
    "untrusted_content_scan": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="ContentTagger + DetectorChain",
        plugin_version="0.6.0",
        description="Scan of untrusted tool outputs (web, files, browser, code execution) before context delivery.",
    ),
    # GAP-3: CSS/DOM concealment (Unit 42 web IDPI classes)
    "css_concealment": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="CssConcealmentDetector",
        plugin_version="0.6.0",
        description="CSS/DOM concealment payloads: hidden markup, offscreen positioning, same-color text, SVG hidden text.",
    ),
    # GAP-1: MCP tool poisoning (OWASP MCP Top 10 MCP03:2025)
    "mcp_tool_baseline_created": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection (MCP03 Tool Poisoning)",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="ToolDescriptionDriftStore",
        plugin_version="0.6.0",
        description="Baseline fingerprint created for an MCP tool (info).",
    ),
    "mcp_tool_description_drift": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM01,
        owasp_name="Prompt Injection (MCP03 Tool Poisoning / Rug Pull)",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="ToolDescriptionDriftStore",
        plugin_version="0.6.0",
        description="MCP tool metadata changed after initial trust — rug-pull detection.",
    ),
    "mcp_tool_removed": OwaspAtlasMapping(
        owasp_risk=OWASP_LLM06,
        owasp_name="Excessive Agency (MCP Tool Shadowing indicator)",
        atlas_technique=ATLAS_AML_T0051,
        atlas_name="Adversarial ML — Prompt Injection",
        detector_name="ToolDescriptionDriftStore",
        plugin_version="0.6.0",
        description="MCP tool disappeared from tools/list — possible tool-shadowing or compromise indicator.",
    ),
    # Unknown / fallback
    "unknown": OwaspAtlasMapping(
        owasp_risk="",
        owasp_name="",
        atlas_technique="",
        atlas_name="",
        detector_name="Unknown Layer",
        plugin_version="0.3.3",
        description="Layer not yet mapped to OWASP / ATLAS.",
    ),
}


def get_mapping(layer: str) -> OwaspAtlasMapping:
    """Return the OWASP/ATLAS mapping for ``layer``."""
    return _OWASP_ATLAS_MAP.get(layer, _OWASP_ATLAS_MAP["unknown"])


def all_mappings() -> list[OwaspAtlasMapping]:
    """Return every defined mapping."""
    return list(_OWASP_ATLAS_MAP.values())


def mappings_by_owasp(owasp_risk: str) -> list[OwaspAtlasMapping]:
    """Return all mappings matching ``owasp_risk``."""
    return [m for m in _OWASP_ATLAS_MAP.values() if m.owasp_risk == owasp_risk]


def mappings_by_atlas(atlas_technique: str) -> list[OwaspAtlasMapping]:
    """Return all mappings matching ``atlas_technique``."""
    return [m for m in _OWASP_ATLAS_MAP.values() if m.atlas_technique == atlas_technique]


def enrich_log_entry(entry: dict[str, Any], layer: str) -> dict[str, Any]:
    """Add ``owasp_risk`` and ``atlas_technique`` to an audit-log entry."""
    result = dict(entry)
    mapping = get_mapping(layer)
    if mapping.owasp_risk:
        result["owasp_risk"] = mapping.owasp_risk
    if mapping.atlas_technique:
        result["atlas_technique"] = mapping.atlas_technique
    return result


# ── Compliance summaries ─────────────────────────────────────────────────────


def owasp_coverage_summary() -> dict[str, dict[str, Any]]:
    """Summary keyed by OWASP risk code."""
    summary: dict[str, dict[str, Any]] = {}
    for code in (OWASP_LLM01, OWASP_LLM04, OWASP_LLM06):
        ms = mappings_by_owasp(code)
        summary[code] = {
            "covered": bool(ms),
            "detector_names": [m.detector_name for m in ms],
            "atlas_techniques": sorted({m.atlas_technique for m in ms if m.atlas_technique}),
        }
    return summary


def atlas_coverage_summary() -> dict[str, dict[str, Any]]:
    """Summary keyed by ATLAS technique code."""
    techniques = sorted({m.atlas_technique for m in _OWASP_ATLAS_MAP.values() if m.atlas_technique})
    return {
        tech: {
            "covered": True,
            "detector_names": [m.detector_name for m in mappings_by_atlas(tech)],
            "owasp_risks": sorted({m.owasp_risk for m in mappings_by_atlas(tech) if m.owasp_risk}),
        }
        for tech in techniques
    }
