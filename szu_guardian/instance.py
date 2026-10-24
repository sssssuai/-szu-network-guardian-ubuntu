"""Prevent a desktop window and a service from monitoring the same config."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager

from .storage import default_config_path


@contextmanager
def single_instance():
    if not sys.platform.startswith("linux"):
        yield
        return
    import fcntl

    directory = default_config_path().parent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(directory / "guardian.lock", os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, "a") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OSError("已有守护进程运行。请先关闭窗口或执行 systemctl --user stop szu-network-guardian") from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
