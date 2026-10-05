"""Filesystem helpers: private directories, atomic writes, and host locks."""

from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Iterator

from .errors import Failure, fail

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and parents) and make the leaf owner-only."""
    path.mkdir(parents=True, exist_ok=True, mode=PRIVATE_DIR_MODE)
    current = path.stat().st_mode & 0o777
    if current != PRIVATE_DIR_MODE:
        os.chmod(path, PRIVATE_DIR_MODE)
    return path


def atomic_write_text(path: Path, text: str, *, mode: int = PRIVATE_FILE_MODE) -> None:
    """Write via a temporary sibling and rename, so readers never see a partial file."""
    ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def atomic_write_json(path: Path, data: object, *, mode: int = PRIVATE_FILE_MODE) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=True) + "\n", mode=mode)


def read_json(path: Path, default: object = None) -> object:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default


@contextlib.contextmanager
def host_lock(path: Path, *, timeout: float = 60.0, poll: float = 0.1) -> Iterator[None]:
    """Exclusive advisory lock on ``path`` shared by every study-room process.

    The resolver holds this lock across read-refresh-write so two concurrent
    credential resolutions on one host can never both spend the same refresh
    token (SPEC 15.4 steps 5-7).
    """
    ensure_private_dir(path.parent)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                    raise
                if time.monotonic() >= deadline:
                    raise fail(
                        Failure.REFRESH_CONFLICT,
                        f"timed out after {timeout:.0f}s waiting for host lock {path.name}",
                        hint="another study-room process is refreshing credentials; retry shortly",
                    ) from None
                time.sleep(poll)
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False
