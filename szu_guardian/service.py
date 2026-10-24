"""Install a per-user systemd service; never require root for the application."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .storage import default_config_path

SERVICE_NAME = "szu-network-guardian.service"


def service_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "systemd" / "user" / SERVICE_NAME


def _quote(value: str, command: bool = False) -> str:
    if any(char in value for char in "\n\r\x00"):
        raise ValueError("服务路径不能包含换行符")
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if command:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def service_unit() -> str:
    # Do not resolve the interpreter symlink: preserve the active virtualenv.
    parts = [sys.executable, str(Path(__file__).absolute().parents[1] / "main.py"), "--headless"]
    return (
        "[Unit]\nDescription=SZU campus network guardian\n\n[Service]\nType=simple\n"
        "ExecStart=" + " ".join(_quote(part, command=True) for part in parts) + "\n"
        "Environment=" + _quote(f"SZU_GUARDIAN_DATA_DIR={default_config_path().parent}") + "\n"
        "Environment=PYTHONUNBUFFERED=1\nRestart=on-failure\nRestartPreventExitStatus=2\nRestartSec=15\n"
        "UMask=0077\nTimeoutStopSec=5\n\n[Install]\nWantedBy=default.target\n"
    )


def _systemctl(*arguments: str) -> None:
    try:
        subprocess.run(["systemctl", "--user", *arguments], check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise OSError("systemctl --user 执行失败，请确认用户 systemd 会话可用；服务文件位于 " + str(service_path())) from exc


def install_service() -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("systemd 服务仅支持 Linux")
    path = service_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(service_unit(), encoding="utf-8")
    _systemctl("daemon-reload")
    _systemctl("enable", "--now", SERVICE_NAME)


def remove_service() -> None:
    if not sys.platform.startswith("linux"):
        raise OSError("systemd 服务仅支持 Linux")
    if service_path().exists():
        _systemctl("disable", "--now", SERVICE_NAME)
        service_path().unlink()
        _systemctl("daemon-reload")
