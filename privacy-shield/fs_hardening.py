"""Filesystem hardening helpers — symlink-race-free directory access.

PS-REST-003 / PS-TOCTOU-008 (Security-Audit PR #17 follow-up): the
previous check-then-use pattern (``mkdir(exist_ok=True)`` followed by
``os.chmod()``) follows a symlink planted at the target path:
``chmod 0700`` is applied to the *linked target* (possibly a foreign
file or directory) and later artifact writes escape the intended base
directory through the same link.

The helper below replaces the pattern with an atomic no-follow
sequence: create the tree (if needed), then open the final component
with ``O_NOFOLLOW | O_DIRECTORY`` and perform *all* verification
(is-directory, owner) plus the permission fixup (``fchmod``) through
that file descriptor.  A symlink swapped in at any point — including
between creation and verification — fails the open with ``ELOOP`` and
never passes verification.

On platforms without ``O_NOFOLLOW`` (e.g. Windows) the helper falls
back to an ``lstat``-based verification; ``chmod`` there applies to the
resolved target, which is the documented pre-existing limitation.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger("privacy_shield")

_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class SecureDirError(OSError):
    """Raised when a directory cannot be secured without following links."""


def ensure_secure_dir(path: Path, mode: int = 0o700) -> None:
    """Create *path* (if needed) and make it a private, no-follow-verified dir.

    Creates the full tree with ``mkdir(parents=True, exist_ok=True)``,
    then verifies the final component through a no-follow file
    descriptor: the descriptor must be an existing directory owned by
    the current effective user, and the permission fixup is applied via
    ``fchmod`` on that descriptor — never via a path-based ``os.chmod``
    that a planted symlink could redirect to a foreign target.

    Raises:
        SecureDirError: *path* is a symlink, not a directory, or owned
            by another user (when the platform exposes ``geteuid``).
        OSError: creation failed for an OS-level reason (permissions,
            missing parent, ...).
    """
    path = Path(path)
    if not _O_NOFOLLOW:
        _ensure_secure_dir_lstat(path, mode)
        return
    if path.parent != path:
        try:
            path.mkdir(parents=True, exist_ok=True, mode=mode)
        except FileExistsError:
            # Exists as a non-directory (file or symlink): swallow and
            # let the no-follow open below produce the precise error.
            pass
    try:
        fd = os.open(
            path,
            os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
        )
    except OSError as exc:
        raise SecureDirError(
            f"{path}: cannot open without following links: {exc}"
        ) from exc
    try:
        st = os.fstat(fd)
        euid_fn = getattr(os, "geteuid", None)
        if euid_fn is not None and st.st_uid != euid_fn():
            raise SecureDirError(
                f"{path}: not owned by current user (uid={st.st_uid}, euid={euid_fn()})"
            )
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _ensure_secure_dir_lstat(path: Path, mode: int) -> None:
    """No-``O_NOFOLLOW`` fallback (documented limitation for Windows)."""
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise SecureDirError(f"{path}: symlink is not a safe target")
    st = os.stat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise SecureDirError(f"{path}: not a directory")
    euid_fn = getattr(os, "geteuid", None)
    if euid_fn is not None and st.st_uid != euid_fn():
        raise SecureDirError(f"{path}: not owned by current user")
    os.chmod(path, mode)


__all__ = ["SecureDirError", "ensure_secure_dir"]
