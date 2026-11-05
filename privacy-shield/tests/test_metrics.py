"""Tests for runtime metrics (LINK-PS-8)."""

from __future__ import annotations

from privacy_shield.detectors.regex_detector import PIIMatch
from privacy_shield.metrics import get_metrics, record_masking, reset_metrics
from privacy_shield.pseudonymizer import Pseudonymizer


def test_metrics_counters_on_pseudonymizer():
    reset_metrics()
    pseudo = Pseudonymizer()

    matches = [
        PIIMatch(start=0, end=13, type="email", value="foo@bar.com", confidence=0.9)
    ]
    pseudo.replace("Email foo@bar.com here", matches, session_id="s1")

    metrics = get_metrics()
    assert metrics["masking_volume"] == 1
    assert metrics["cache_misses"] == 1
    assert metrics["cache_hits"] == 0
    assert metrics["cache_hit_rate"] == 0.0

    # Re-using the same value should hit the cache.
    pseudo.replace("Email foo@bar.com here", matches, session_id="s1")
    metrics = get_metrics()
    assert metrics["masking_volume"] == 2
    assert metrics["cache_hits"] == 1
    assert metrics["cache_misses"] == 1
    assert metrics["cache_hit_rate"] == 0.5

    reset_metrics()


def test_record_masking_multiple():
    reset_metrics()
    record_masking(5)
    record_masking(3)
    assert get_metrics()["masking_volume"] == 8
    reset_metrics()


def test_cache_hit_ratio_exposed():
    """PERF-2: get_metrics() must include a cache_hit_ratio key."""
    reset_metrics()
    metrics = get_metrics()
    assert "cache_hit_ratio" in metrics
    assert metrics["cache_hit_ratio"] == metrics["cache_hit_rate"]
    assert 0.0 <= metrics["cache_hit_ratio"] <= 1.0
    reset_metrics()


def test_cache_hit_ratio_after_miss_then_hit():
    """PERF-2: ratio should reflect hit/(hit+miss)."""
    reset_metrics()
    pseudo = Pseudonymizer()
    matches = [
        PIIMatch(start=0, end=13, type="email", value="foo@bar.com", confidence=0.9)
    ]
    pseudo.replace("Email foo@bar.com here", matches, session_id="s1")
    pseudo.replace("Email foo@bar.com here", matches, session_id="s1")
    metrics = get_metrics()
    assert metrics["cache_hits"] == 1
    assert metrics["cache_misses"] == 1
    assert metrics["cache_hit_ratio"] == 0.5
    reset_metrics()
