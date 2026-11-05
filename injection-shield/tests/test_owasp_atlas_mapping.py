"""Test OWASP LLM Top-10 + MITRE ATLAS mapping correctness (Injection-Shield).

Covers: get_mapping, enrich_log_entry, all_mappings, mappings_by_owasp,
mappings_by_atlas, owasp_coverage_summary, atlas_coverage_summary.
"""

from __future__ import annotations

import pytest

from injection_shield.owasp_atlas_mapping import (
    ATLAS_AML_T0051,
    OWASP_LLM01,
    OWASP_LLM04,
    OWASP_LLM06,
    all_mappings,
    atlas_coverage_summary,
    enrich_log_entry,
    get_mapping,
    mappings_by_atlas,
    mappings_by_owasp,
    owasp_coverage_summary,
)


class TestGetMapping:
    def test_pre_llm_call(self):
        m = get_mapping("pre_llm_call")
        assert m.owasp_risk == OWASP_LLM01
        assert m.atlas_technique == ATLAS_AML_T0051
        assert "InjectionPatternDetector" in m.detector_name

    def test_pre_tool_call(self):
        m = get_mapping("pre_tool_call")
        assert m.owasp_risk == OWASP_LLM01
        assert m.atlas_technique == ATLAS_AML_T0051

    def test_post_llm_call(self):
        m = get_mapping("post_llm_call")
        assert m.owasp_risk == OWASP_LLM01
        assert m.atlas_technique == ATLAS_AML_T0051

    def test_post_tool_call(self):
        m = get_mapping("post_tool_call")
        assert m.owasp_risk == OWASP_LLM01
        assert m.atlas_technique == ATLAS_AML_T0051

    def test_circuit_breaker(self):
        m = get_mapping("circuit_breaker")
        assert m.owasp_risk == OWASP_LLM04
        assert m.atlas_technique == ""

    def test_excessive_agency(self):
        m = get_mapping("excessive_agency")
        assert m.owasp_risk == OWASP_LLM06
        assert m.atlas_technique == ATLAS_AML_T0051

    def test_unknown_layer_falls_back(self):
        m = get_mapping("not_a_layer")
        assert m.owasp_risk == ""
        assert m.atlas_technique == ""
        assert m.detector_name == "Unknown Layer"


class TestEnrichLogEntry:
    def test_enrich_pre_llm_call(self):
        entry = {"layer": "pre_llm_call", "timestamp": "2026-08-23T10:00:00Z"}
        enriched = enrich_log_entry(entry, "pre_llm_call")
        assert enriched["owasp_risk"] == OWASP_LLM01
        assert enriched["atlas_technique"] == ATLAS_AML_T0051

    def test_enrich_circuit_breaker(self):
        entry = {"layer": "circuit_breaker", "timestamp": "2026-08-23T10:00:00Z"}
        enriched = enrich_log_entry(entry, "circuit_breaker")
        assert enriched["owasp_risk"] == OWASP_LLM04
        assert "atlas_technique" not in enriched or enriched["atlas_technique"] == ""

    def test_does_not_mutate_input(self):
        entry = {"layer": "pre_llm_call"}
        enriched = enrich_log_entry(entry, "pre_llm_call")
        assert "owasp_risk" not in entry
        assert "owasp_risk" in enriched


class TestMappingsByOwasp:
    def test_llm01_has_all_layers(self):
        ms = mappings_by_owasp(OWASP_LLM01)
        layers = {m.detector_name for m in ms}
        assert any("InjectionPatternDetector" in n for n in layers)
        assert any("ToolCallPatternDetector" in n for n in layers)

    def test_llm04_is_covered(self):
        ms = mappings_by_owasp(OWASP_LLM04)
        assert len(ms) == 1
        assert "Circuit-Breaker" in ms[0].detector_name

    def test_empty_for_uncovered(self):
        ms = mappings_by_owasp("LLM02")
        assert ms == []


class TestMappingsByAtlas:
    def test_aml_t0051_covers_multiple_layers(self):
        ms = mappings_by_atlas(ATLAS_AML_T0051)
        assert len(ms) >= 4

    def test_empty_for_uncovered(self):
        ms = mappings_by_atlas("AML.T9999")
        assert ms == []


class TestAllMappings:
    def test_at_least_6_mappings(self):
        # 6 concrete + 1 unknown fallback
        assert len(all_mappings()) >= 6


class TestOwaspCoverageSummary:
    def test_llm01_is_covered(self):
        summary = owasp_coverage_summary()
        assert summary[OWASP_LLM01]["covered"] is True
        assert ATLAS_AML_T0051 in summary[OWASP_LLM01]["atlas_techniques"]

    def test_llm04_is_covered(self):
        summary = owasp_coverage_summary()
        assert summary[OWASP_LLM04]["covered"] is True

    def test_llm06_is_covered(self):
        summary = owasp_coverage_summary()
        assert summary[OWASP_LLM06]["covered"] is True


class TestAtlasCoverageSummary:
    def test_atlas_t0051_is_covered(self):
        summary = atlas_coverage_summary()
        assert ATLAS_AML_T0051 in summary
        assert summary[ATLAS_AML_T0051]["covered"] is True
        assert OWASP_LLM01 in summary[ATLAS_AML_T0051]["owasp_risks"]


class TestOwaspAtlasMappingDataclass:
    def test_frozen_and_readonly(self):
        m = get_mapping("pre_llm_call")
        with pytest.raises(AttributeError):
            m.owasp_risk = "LLM99"  # type: ignore[misc]

    def test_slots(self):
        m = get_mapping("pre_llm_call")
        assert "__dict__" not in dir(m)
