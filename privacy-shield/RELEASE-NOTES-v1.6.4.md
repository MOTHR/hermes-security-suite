## Privacy-Shield v1.6.4

**CI-Fix:** Reasoning-Mode-Env-Validation

### Fixed
- CI was failing on `main` since v1.6.0 because `mypy --strict` rejected assigning
  `os.environ[str]` to the `Literal["off", "audit", "restore"]` field
  `config.reasoning.mode`.
- The env value is now validated explicitly and falls back to the default
  `"restore"` with a warning on invalid input.

### Also fixed
- 4 pre-existing ruff issues in `plugin.py` (unused import, unused variable,
  nested-if, blind-except) so the lint job is green again.

### No functional changes
- All tests green across Python 3.10, 3.11 and 3.12.
- API compatible with v1.6.3.
