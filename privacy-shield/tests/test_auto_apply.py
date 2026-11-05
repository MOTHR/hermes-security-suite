"""Tests for auto_apply_hook.py.

Covers: idempotency, apply, rollback, dry-run, status, unknown layout abort.
"""

import sys
from pathlib import Path

# Make scripts/ importable
scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(scripts_dir))

import auto_apply_hook as aah
import pytest


@pytest.fixture
def fake_turn_context(tmp_path):
    """Create a fake turn_context.py without the patch."""
    tc = tmp_path / "turn_context.py"
    tc.write_text(
        "def run_agent(agent, messages):\n"
        '    """Run one turn."""\n'
        '    logger.info("Starting turn")\n    x = agent.provider\n'
        "\n"
        "    compaction = run_turn_start_compaction(agent, messages=messages)\n"
        "    plugin_user_context = _collect_pre_llm_call_context(\n"
        "        agent, effective_task_id=None, turn_id=None,\n"
        "    )\n"
        "    plugin_user_context = \"\"\n"
        "    try:\n"
        '        _pre_results = invoke_hook("pre_llm_call")\n'
        "        pass\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "    # After hook logic\n"
        "    return messages\n",
        encoding="utf-8",
    )
    return tc


@pytest.fixture
def patched_turn_context(tmp_path):
    """Create a fake turn_context.py WITH the patch already applied."""
    tc = tmp_path / "turn_context.py"
    base = (
        "def run_agent(agent, messages):\n"
        '    """Run one turn."""\n'
        '    logger.info("Starting turn")\n    x = agent.provider\n'
        "\n"
        "    compaction = run_turn_start_compaction(agent, messages=messages)\n"
        "\n"
    )
    patch = "\n".join(aah.PATCH_LINES) + "\n"
    tail = (
        "    plugin_user_context = _collect_pre_llm_call_context(\n"
        "        agent, effective_task_id=None, turn_id=None,\n"
        "    )\n"
        "    try:\n"
        '        _pre_results = invoke_hook("pre_llm_call")\n'
        "        pass\n"
        "    except Exception:\n"
        "        pass\n"
        "\n"
        "    # After hook logic\n"
        "    return messages\n"
    )
    tc.write_text(base + patch + tail, encoding="utf-8")
    return tc


class TestIsPatchApplied:
    def test_not_applied(self, fake_turn_context):
        assert aah.is_patch_applied(fake_turn_context) is False

    def test_applied(self, patched_turn_context):
        assert aah.is_patch_applied(patched_turn_context) is True


class TestLocateInsertionPoint:
    def test_finds_anchor(self, fake_turn_context):
        lines = fake_turn_context.read_text(encoding="utf-8").splitlines()
        idx = aah.locate_insertion_point(lines)
        assert idx is not None
        assert "pre_llm_call" in lines[idx]

    def test_missing_anchor(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text("def foo(): pass\n", encoding="utf-8")
        lines = tc.read_text(encoding="utf-8").splitlines()
        assert aah.locate_insertion_point(lines) is None


class TestValidateContext:
    def test_valid(self, fake_turn_context):
        lines = fake_turn_context.read_text(encoding="utf-8").splitlines()
        idx = aah.locate_insertion_point(lines)
        ok, reason = aah.validate_context(lines, idx)
        assert ok is True
        assert reason == ""

    def test_no_anchor(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text("def foo(): pass\n", encoding="utf-8")
        lines = tc.read_text(encoding="utf-8").splitlines()
        ok, reason = aah.validate_context(lines, None)
        assert ok is False
        assert "unknown layout" in reason.lower()

    def test_no_agent_model(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text(
            "def foo():\n"
            "    pass\n"
            "    pass\n"
            "    plugin_user_context = _collect_pre_llm_call_context(\n"
            "        agent,\n"
            "    )\n"
            "    pass\n",
            encoding="utf-8",
        )
        lines = tc.read_text(encoding="utf-8").splitlines()
        idx = aah.locate_insertion_point(lines)
        ok, reason = aah.validate_context(lines, idx)
        assert ok is False
        assert "unknown layout" in reason.lower()

    def test_not_turn_context(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text(
            "def some_other_func(agent, messages):\n"
            "    pass\n"
            "    plugin_user_context = _collect_pre_llm_call_context(\n"
            "        agent,\n"
            "    )\n"
            "    x = agent.provider\n"
            "    pass\n",
            encoding="utf-8",
        )
        lines = tc.read_text(encoding="utf-8").splitlines()
        idx = aah.locate_insertion_point(lines)
        ok, reason = aah.validate_context(lines, idx)
        assert ok is False
        assert "unknown layout" in reason.lower()


class TestApplyPatch:
    def test_apply_success(self, fake_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path  # redirect backups
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        ok, msg = aah.apply_patch(fake_turn_context, dry_run=False)
        assert ok is True
        assert "applied successfully" in msg.lower()
        assert aah.is_patch_applied(fake_turn_context) is True

    def test_dry_run_does_not_modify(self, fake_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        ok, msg = aah.apply_patch(fake_turn_context, dry_run=True)
        assert ok is True
        assert "dry-run" in msg.lower()
        assert aah.is_patch_applied(fake_turn_context) is False  # NOT modified

    def test_idempotent(self, patched_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        ok, msg = aah.apply_patch(patched_turn_context, dry_run=False)
        assert ok is True
        assert "already applied" in msg.lower()

    def test_unknown_layout_abort(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text("def foo(): pass\n", encoding="utf-8")
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        ok, msg = aah.apply_patch(tc, dry_run=False)
        assert ok is False
        assert "ABORT" in msg
        assert "unknown layout" in msg.lower()


class TestVerifyPatch:
    def test_verify_success(self, patched_turn_context):
        ok, msg = aah.verify_patch(patched_turn_context)
        assert ok is True
        assert "verified OK" in msg

    def test_verify_fail_marker_missing(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text("def foo(): pass\n", encoding="utf-8")
        ok, msg = aah.verify_patch(tc)
        assert ok is False
        assert "marker comment not found" in msg.lower()

    def test_verify_fail_syntax_error(self, tmp_path):
        tc = tmp_path / "turn_context.py"
        tc.write_text(
            aah.MARKER_COMMENT + "\n"
            "def foo(:\n"  # syntax error
        )
        ok, msg = aah.verify_patch(tc)
        assert ok is False
        assert "syntax error" in msg.lower()


class TestRevertPatch:
    def test_revert_success(self, fake_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        # Apply first
        aah.apply_patch(fake_turn_context, dry_run=False)
        assert aah.is_patch_applied(fake_turn_context) is True
        # Revert
        ok, msg = aah.revert_patch(fake_turn_context)
        assert ok is True
        assert "reverted" in msg.lower()
        assert aah.is_patch_applied(fake_turn_context) is False

    def test_revert_no_backup(self, fake_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        ok, msg = aah.revert_patch(fake_turn_context)
        assert ok is False
        assert "no backup" in msg.lower()


class TestGetStatus:
    def test_status_dict(self, fake_turn_context, tmp_path):
        aah.TURN_CONTEXT_PATH = fake_turn_context
        aah.BACKUP_DIR = tmp_path
        status = aah.get_status()
        assert status["file_exists"] is True
        assert status["patch_applied"] is False
        assert isinstance(status["backups"], list)


class TestIntegration:
    """End-to-end: apply + verify + idempotent + revert."""

    def test_full_cycle(self, fake_turn_context, tmp_path):
        aah.BACKUP_DIR = tmp_path
        aah.LOG_PATH = tmp_path / "auto-apply.log"
        aah.TURN_CONTEXT_PATH = fake_turn_context

        # 1. Not applied initially
        assert aah.is_patch_applied(fake_turn_context) is False

        # 2. Apply
        ok, msg = aah.apply_patch(fake_turn_context, dry_run=False)
        assert ok is True
        assert aah.is_patch_applied(fake_turn_context) is True

        # 3. Idempotent re-apply
        ok2, msg2 = aah.apply_patch(fake_turn_context, dry_run=False)
        assert ok2 is True
        assert "already applied" in msg2.lower()

        # 4. Revert
        ok3, msg3 = aah.revert_patch(fake_turn_context)
        assert ok3 is True
        assert aah.is_patch_applied(fake_turn_context) is False
