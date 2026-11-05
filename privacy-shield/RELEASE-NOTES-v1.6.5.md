## Privacy-Shield v1.6.5

**CI-Fix Release:** v1.6.4 would have been green, but the dashboard API tests
hardcoded version `1.6.3`, which made CI red as soon as the version was bumped.
v1.6.5 contains the original CI fix plus the test assertion fix.

### Fixed
- `config.py:325` now validates `PRIVACY_SHIELD_REASONING_MODE` against the
  allowed `Literal["off", "audit", "restore"]` members and falls back to
  `"restore"` with a warning on invalid input. This resolves the `mypy --strict`
  failure that broke CI since v1.6.0.
- `plugin.py`: removed 4 pre-existing ruff issues
  (unused import, unused variable, nested-if, blind-except).
- `tests/test_dashboard_api.py`: version assertions now read from
  `privacy_shield.__version__` so future version bumps don't break tests.

### Tests
- New `tests/test_config_reasoning_env.py` covers default, valid and invalid
  reasoning mode env values.

### No functional changes
- API compatible with v1.6.3/v1.6.4.
