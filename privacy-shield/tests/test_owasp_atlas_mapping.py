"""Test OWASP LLM Top-10 + MITRE ATLAS mapping correctness (Privacy-Shield).

Covers: get_mapping, enrich_event, all_mappings, mappings_by_owasp,
mappings_by_atlas, owasp_coverage_summary, atlas_coverage_summary.
"""

from __future__ import annotations

import pytest

from privacy_shield.audit.owasp_atlas_mapping import (
    ATLAS_AML_T0024,
    ATLAS_AML_T0051,
    OWASP_LLM02,
    OWASP_LLM06,
    OWASP_LLM07,
    all_mappings,
    atlas_coverage_summary,
    enrich_event,
    get_mapping,
    mappings_by_atlas,
    mappings_by_owasp,
    owasp_coverage_summary,
)


class TestGetMapping:
    def test_pseudonymization_applied(self):
        m = get_mapping("pseudonymization_applied")
        assert m.owasp_risk == OWASP_LLM02
        assert m.atlas_technique == ATLAS_AML_T0024
        assert m.detection_name == "Pseudonymization (regex + Presidio)"

    def test_output_pii_detected(self):
        m = get_mapping("output_pii_detected")
        assert m.owasp_risk == OWASP_LLM02
        assert m.atlas_technique == ATLAS_AML_T0024

    def test_blocked_action(self):
        m = get_mapping("blocked_action")
        assert m.owasp_risk == OWASP_LLM02
        assert m.atlas_technique == ATLAS_AML_T0024

    def test_strict_mode_block(self):
        m = get_mapping("strict_mode_block")
        assert m.owasp_risk == OWASP_LLM02

    def test_paranoid_mode_block(self):
        m = get_mapping("paranoid_mode_block")
        assert m.owasp_risk == OWASP_LLM02

    def test_restore(self):
        m = get_mapping("restore")
        assert m.owasp_risk == OWASP_LLM07
        assert m.atlas_technique == ATLAS_AML_T0024

    def test_token_restore_loop(self):
        m = get_mapping("token_restore_loop")
        assert m.owasp_risk == OWASP_LLM07

    def test_mode_change(self):
        m = get_mapping("mode_change")
        assert m.owasp_risk == OWASP_LLM06

    def test_approval_required(self):
        m = get_mapping("approval_required")
        assert m.owasp_risk == OWASP_LLM06

    def test_approval_granted(self):
        m = get_mapping("approval_granted")
        assert m.owasp_risk == OWASP_LLM06

    def test_approval_denied(self):
        m = get_mapping("approval_denied")
        assert m.owasp_risk == OWASP_LLM06

    def test_human_review(self):
        m = get_mapping("human_review")
        assert m.owasp_risk == OWASP_LLM06

    def test_cross_plugin_token_sync(self):
        m = get_mapping("cross_plugin_token_sync")
        assert m.owasp_risk == OWASP_LLM06

    def test_unknown_event_falls_back(self):
        m = get_mapping("not_a_real_event")
        assert m.owasp_risk == ""
        assert m.atlas_technique == ""
        assert m.detection_name == "Unknown Event"


class TestEnrichEvent:
    def test_enrich_pseudonymization(self):
        event = {"event": "pseudonymization_applied", "ts": 123.0}
        enriched = enrich_event(event)
        assert enriched["owasp_risk"] == OWASP_LLM02
        assert enriched["atlas_technique"] == ATLAS_AML_T0024
        assert enriched["owasp_name"] == "Sensitive Information Disclosure"

    def test_enrich_unknown(self):
        event = {"event": "something_new", "ts": 456.0}
        enriched = enrich_event(event)
        assert enriched["owasp_risk"] == ""
        assert enriched["atlas_technique"] == ""

    def test_does_not_mutate_input(self):
        event = {"event": "pseudonymization_applied", "ts": 123.0}
        enriched = enrich_event(event)
        assert "owasp_risk" not in event
        assert "owasp_risk" in enriched


class TestMappingsByOwasp:
    def test_llm02_has_multiple_mappings(self):
        ms = mappings_by_owasp(OWASP_LLM02)
        assert len(ms) >= 5
        names = [m.detection_name for m in ms]
        assert "Pseudonymization (regex + Presidio)" in names

    def test_llm06_has_approval_mappings(self):
        ms = mappings_by_owasp(OWASP_LLM06)
        names = [m.detection_name for m in ms]
        assert any("Approval" in n for n in names)

    def test_empty_for_uncovered(self):
        ms = mappings_by_owasp("LLM03")
        assert ms == []


class TestMappingsByAtlas:
    def test_aml_t0024_covers_multiple_events(self):
        ms = mappings_by_atlas(ATLAS_AML_T0024)
        assert len(ms) >= 10

    def test_empty_for_uncovered(self):
        ms = mappings_by_atlas("AML.T9999")
        assert ms == []


class TestAllMappings:
    def test_at_least_13_mappings(self):
        # 12 concrete + 1 unknown fallback
        assert len(all_mappings()) >= 13


class TestOwaspCoverageSummary:
    def test_llm02_is_covered(self):
        summary = owasp_coverage_summary()
        assert summary[OWASP_LLM02]["covered"] is True
        assert ATLAS_AML_T0024 in summary[OWASP_LLM02]["atlas_techniques"]

    def test_llm03_is_not_covered(self):
        summary = owasp_coverage_summary()
        assert summary["LLM03"]["covered"] is False

    def test_all_ten_codes_present(self):
        summary = owasp_coverage_summary()
        assert len(summary) == 10
        for i in range(1, 11):
            assert f"LLM{i:02d}" in summary


class TestAtlasCoverageSummary:
    def test_atlas_t0024_is_covered(self):
        summary = atlas_coverage_summary()
        assert ATLAS_AML_T0024 in summary
        assert summary[ATLAS_AML_T0024]["covered"] is True

    def test_atlas_t0051_is_not_covered_by_privacy_shield(self):
        # Privacy-Shield does not map to T0051 (that's Injection-Shield)
        summary = atlas_coverage_summary()
        assert ATLAS_AML_T0051 not in summary


class TestOwaspAtlasMappingDataclass:
    def test_frozen_and_hashable(self):
        m = get_mapping("pseudonymization_applied")
        # frozen=True means fields are read-only
        with pytest.raises(AttributeError):
            m.owasp_risk = "LLM99"  # type: ignore[misc]

    def test_slots(self):
        m = get_mapping("pseudonymization_applied")
        assert "__dict__" not in dir(m)
