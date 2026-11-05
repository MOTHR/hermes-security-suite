"""Regression: info-level scans must not trigger Telegram alerts."""

def test_info_severity_below_medium_threshold():
    """2026-09-22: info (untrusted tag) must NOT pass a medium alert gate."""
    from injection_shield.plugin import InjectionShieldPlugin
    p = InjectionShieldPlugin(profile="schluesselmacher")
    assert p._severity_meets_threshold([{"severity": "info"}], "medium") is False
    assert p._severity_meets_threshold([{"severity": "low"}], "medium") is False
    assert p._severity_meets_threshold([{"severity": "medium"}], "medium") is True
    assert p._severity_meets_threshold([{"severity": "critical"}], "medium") is True
    # missing severity key defaults to medium rank — fail closed (security tool:
    # an unclassified violation may alert)
    assert p._severity_meets_threshold([{}], "medium") is True
