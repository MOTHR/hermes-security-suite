# Privacy-Shield Testing

How the pytest suite is run and how test isolation works.

## Running the suite

```bash
cd /path/to/hermes-privacy-shield
python3 -m pytest tests/ -q --tb=line
```

## Test Log Isolation

Privacy-Shield attaches a rotating operator log handler on plugin init
(`attach_rotating_handler`, `plugin.py`, see `settings_from_config` in
`rotating_log.py`). Without isolation, pytest fixtures that build a
`PrivacyShieldPlugin` append entries to the *production* log at
`~/.hermes/profiles/<profile>/workspace/05-Logs-Snapshots/privacy-shield.log`
(default `audit_log_path`, `config.py`). Cron-driven pytest replays
(eval-honesty-watcher, post-update-check, daily-doctor) therefore leave
synthetic session markers (`sess-1`, `sess-B`, `log-test`, ...) in the
operator log and pollute real audit analysis.

### `PRIVACY_SHIELD_AUDIT_LOG_PATH`

This environment variable redirects the rotating operator log. It is
applied in `load_config()` (`config.py`, env-override block) **regardless
of encryption-key state**, next to `PRIVACY_SHIELD_AUDIT_JSONL_PATH`.

- **Set** → the rotating log goes to the given path (test logs land in the
  pytest tmp base dir).
- **Unset** → production default, unchanged.

### conftest.py behaviour

`tests/conftest.py` sets the variable in `pytest_configure()` with
`os.environ.setdefault(...)` to pytest's tmp base dir
(`config._tmp_path_factory.getbasetemp()`, fallback
`<tempdir>/privacy-shield-pytest`). Because `setdefault` is used, a
pre-existing value stays authoritative — CI or a cron wrapper can override
the location without touching the repo.

This covers every entry point that runs the pytest suite, including the
three cron jobs (eval-honesty-watcher, privacy-shield-post-update-check,
privacy-shield-daily-doctor). The production log stays clean during test
runs.

Related behavior: `plugin.py` (`attach_rotating_handler` on plugin init),
`rotating_log.py` (`settings_from_config`, `DEFAULT_LOG_PATH`).