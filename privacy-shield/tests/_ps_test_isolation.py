"""Shared test-isolation contract for the privacy-shield suite (Issue #8).

orakel design t_f0434d31: the operator-log leak happens at plugin-INIT
time — never at import — via three channels the old ``setdefault``
conftest could not close:

- **B1** direct-config attach: ``PrivacyShieldPlugin(config=...)`` with
  dataclass defaults (env-blind) attaches the DEFAULT production log
  path, and the idempotent first-attach freeze locks it for the run.
- **B2** the ``~/.hermes/config.yaml`` merge in ``load_config`` wins
  over every env override the test sets.
- **B3** ambient environment survives ``setdefault``.

Layer-1 (conftest) wires :func:`apply_test_isolation` into
``pytest_configure``; this seam keeps the helpers importable for the
targeted regression tests in ``test_suite_log_isolation.py``.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Any

#: Env contract for the in-package attach guard (Layer-2). The conftest
#: hard-sets this; ``attach_rotating_handler`` refuses any sink outside
#: this pytest-tmp base while it is set.
PS_TEST_SINK_ENV = "PRIVACY_SHIELD_TEST_SINK_BASE"

#: Fake-HOME subtree name inside the pytest tmp base.
PS_FAKE_HOME_DIRNAME = "ps-fake-home"

#: Ambient variables the doctor subprocess could leak into ``load_config`` /
#: ``maybe_enable_json_logging`` (orakel R1 scrub list): workshop mode,
#: key-file fallback, reasoning mode/threshold, storage mode, runtime mode,
#: JSON logging. ``PRIVACY_SHIELD_KEY`` is deliberately NOT scrubbed —
#: Hermes secret-scope resolution is the plugin's own logic, not a path sink.
AMBIENT_SCRUB_VARS: tuple[str, ...] = (
    "PRIVACY_SHIELD_WORKSHOP",
    "PRIVACY_SHIELD_KEY_FILE",
    "PRIVACY_SHIELD_REASONING_MODE",
    "PRIVACY_SHIELD_REASONING_CONFIDENCE",
    "PRIVACY_SHIELD_STORAGE_MODE",
    "PRIVACY_SHIELD_MODE",
    "LOG_JSON",
)


#: All env keys :func:`apply_test_isolation` touches — callers simulating
#: the conftest behaviour in a scoped test MUST snapshot and restore these
#: (the session-level values are the conftest's, not the test's).
ISOLATED_ENV_VARS: tuple[str, ...] = (
    "HOME",
    "HERMES_HOME",
    PS_TEST_SINK_ENV,
    "PRIVACY_SHIELD_AUDIT_LOG_PATH",
    "PRIVACY_SHIELD_AUDIT_JSONL_PATH",
    "PRIVACY_SHIELD_RESTORE_CHAT_ID",
)


def fake_home_env(tmp_base: Path) -> tuple[Path, Path]:
    """Return ``(HOME, HERMES_HOME)`` inside the pytest tmp base."""
    home = tmp_base / PS_FAKE_HOME_DIRNAME
    return home, home / ".hermes"


def apply_test_isolation(tmp_base: Path) -> Path:
    """Layer-1 isolation authority: hard-set every ambient channel.

    - redirect ``HOME`` / ``HERMES_HOME`` to a fake tree (covers all
      ``expanduser`` defaults atomically incl. the B2 user-config merge),
    - hard-set both sink paths (never ``setdefault`` — B3),
    - dummy ``PRIVACY_SHIELD_RESTORE_CHAT_ID`` so the bare
      ``PrivacyShieldConfig()`` default factory never shells the pass
      secret store from tests,
    - scrub the ambient doctor-channel variables.

    Returns the sink base the Layer-2 guard must enforce.
    """
    sink_base = Path(tmp_base)
    sink_base.mkdir(parents=True, exist_ok=True)
    home, hermes_home = fake_home_env(sink_base)
    home.mkdir(parents=True, exist_ok=True)
    hermes_home.mkdir(parents=True, exist_ok=True)
    os.environ["HOME"] = str(home)
    os.environ["HERMES_HOME"] = str(hermes_home)
    os.environ[PS_TEST_SINK_ENV] = str(sink_base)
    os.environ["PRIVACY_SHIELD_AUDIT_LOG_PATH"] = str(
        sink_base / "privacy-shield-test.log"
    )
    os.environ["PRIVACY_SHIELD_AUDIT_JSONL_PATH"] = str(
        sink_base / "privacy-shield-test-audit.jsonl"
    )
    os.environ["PRIVACY_SHIELD_RESTORE_CHAT_ID"] = "0-test-fixture"
    for var in AMBIENT_SCRUB_VARS:
        os.environ.pop(var, None)
    return sink_base


def assert_rotating_handlers_inside(sink_base: Path | str) -> list[str]:
    """Return offender descriptions for rotating handlers outside ``sink_base``.

    Empty list == compliant. Enumerates ``privacy_shield*`` loggers only —
    cheap enough for an autouse function-scoped fixture (orakel K2).
    """
    base = Path(sink_base).resolve()
    offenders: list[str] = []
    for name in list(logging.root.manager.loggerDict):
        if not name.startswith("privacy_shield"):
            continue
        for handler in logging.getLogger(name).handlers:
            if isinstance(handler, logging.handlers.RotatingFileHandler):
                if not Path(handler.baseFilename).resolve().is_relative_to(base):
                    offenders.append(f"{name}: {handler.baseFilename}")
    return offenders


def set_direct_config_sinks(config: Any, name: str) -> None:
    """Point a direct-config plugin's sinks at the pytest sink base (B1).

    ``PrivacyShieldConfig()`` is env-blind, so test sites MUST set the
    sink paths explicitly. Fail-closed when the conftest isolation is
    not active instead of silently keeping the production default.
    """
    sink = os.environ.get(PS_TEST_SINK_ENV)
    if not sink:
        raise RuntimeError(
            "Issue #8 test isolation: PRIVACY_SHIELD_TEST_SINK_BASE unset — "
            "direct-config sinks would fall through to production defaults"
        )
    base = Path(sink)
    config.audit_log_path = str(base / f"{name}.log")
    config.audit_jsonl_path = str(base / f"{name}.jsonl")
