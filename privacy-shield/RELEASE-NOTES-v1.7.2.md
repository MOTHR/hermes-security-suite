# Privacy-Shield v1.7.2 — Restore whitelist never empty + cron platform

**Closes the recurring "TOKEN_* not reverse-translated" reports (2026-10-06).**

## What happened

Users (and agent final messages) kept seeing raw placeholders such as
`TOKEN_BIC_…_017` instead of the original values. Two independent causes:

1. **Empty default whitelist.** `_default_restore_channels()` returned `()`
   whenever `pass show hermes/telegram/chat_id` / env could not resolve a chat
   ID. Profiles without an explicit
   `plugins.entries.privacy-shield.restore_allowed_channels` override
   (sysadmin, trinity, link-devops, scribe, seraph, merovinger, agent-smith, …)
   therefore skipped every restore. Gateway delivers bare `"telegram"`, so the
   scoped-only default `telegram:<id>` never matched either.

2. **`platform="cron"` not allowed.** The scheduler stamps `platform="cron"` on
   the agent session while the final response is delivered to the user
   (telegram/origin). Cron was not on the restore whitelist → scheduled
   deliveries left tokens intact.

Live evidence: `state.db` assistant rows with unresolved `TOKEN_BIC_*` on
sysadmin / link-devops / orakel; gateway.log lines
`restoration skipped for channel telegram` (2026-10-04); zero
`Restored PII tokens` successes in the same window.

## What v1.7.2 changes

- `_default_restore_channels()` always returns at least
  `("telegram", "desktop", "cli", "cron")`, optionally prepended with
  `telegram:<chat_id>` when known.
- Profile configs backfilled with the same list (incl. `cron`).
- Restore skip / success logs now include channel + session prefix; unresolved
  tokens after an allowed restore emit a WARNING (mapping miss / corrupted
  token) without dumping PII.

## Operator action required

Gateway must re-load the plugin (config is read at plugin init):

```
/restart
```

or `hermes gateway restart` from a shell outside the gateway process.

## Tests

- `tests/test_channel_matching.py::test_restoration_runs_for_cron_platform`
- `tests/test_channel_matching.py::test_default_restore_channels_never_empty`
