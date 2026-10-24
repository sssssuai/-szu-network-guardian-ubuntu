from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "SZUNetworkGuardian"


def desktop_autostart_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "autostart" / "szu-network-guardian.desktop"


def _desktop_argument(value: str) -> str:
    if any(char in value for char in "\n\r\x00"):
        raise ValueError("启动路径不能包含换行符")
    value = value.replace("%", "%%")
    for char in ("\\", '"', "`", "$"):
        value = value.replace(char, "\\" + char)
    # Desktop files apply general string escaping before Exec argument escaping.
    return '"' + value.replace("\\", "\\\\") + '"'


def _linux_desktop_entry() -> str:
    from .storage import default_config_path

    parts = [
        "/usr/bin/env", f"SZU_GUARDIAN_DATA_DIR={default_config_path().parent}",
        sys.executable, str(Path(__file__).absolute().parents[1] / "main.py"), "--autostart",
    ]
    return (
        "[Desktop Entry]\nType=Application\nName=SZU Network Guardian\n"
        "Comment=Campus network monitor\nTerminal=false\n"
        "Exec=" + " ".join(_desktop_argument(part) for part in parts) + "\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


def _startup_command() -> str:
    if getattr(sys, "frozen", False):
        parts = [sys.executable, "--autostart"]
    else:
        python = Path(sys.executable)
        pythonw = python.with_name("pythonw.exe")
        executable = pythonw if pythonw.exists() else python
        main_file = Path(__file__).resolve().parents[1] / "main.py"
        parts = [str(executable), str(main_file), "--autostart"]
    return subprocess.list2cmdline(parts)


def is_autostart_enabled() -> bool:
    if sys.platform.startswith("linux"):
        return desktop_autostart_path().exists()
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY,
            0,
            winreg.KEY_READ,
        ) as key:
            value, _ = winreg.QueryValueEx(key, VALUE_NAME)
            return bool(value)
    except FileNotFoundError:
        return False


def set_autostart(enabled: bool) -> None:
    if sys.platform.startswith("linux"):
        path = desktop_autostart_path()
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_linux_desktop_entry(), encoding="utf-8")
        else:
            path.unlink(missing_ok=True)
        return
    if sys.platform != "win32":
        if enabled:
            raise OSError("开机自启仅支持 Windows")
        return
    import winreg

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        RUN_KEY,
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        if enabled:
            winreg.SetValueEx(
                key,
                VALUE_NAME,
                0,
                winreg.REG_SZ,
                _startup_command(),
            )
        else:
            try:
                winreg.DeleteValue(key, VALUE_NAME)
            except FileNotFoundError:
                pass
