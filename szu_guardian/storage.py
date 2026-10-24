from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
import tempfile
import stat
from ctypes import wintypes
from pathlib import Path

from .models import AppConfig, ZONE_AUTO


APP_DIRECTORY = "SZUNetworkGuardian"


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _blob_from_bytes(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data, max(1, len(data)))
    blob = DATA_BLOB(
        len(data),
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)),
    )
    return blob, buffer


def protect_secret(secret: str) -> str:
    if not secret:
        return ""
    if sys.platform != "win32":
        raise OSError("安全保存密码仅支持 Windows")

    raw = secret.encode("utf-8")
    input_blob, input_buffer = _blob_from_bytes(raw)
    output_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    description = "SZU Network Guardian"

    ok = crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        description,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    _ = input_buffer
    if not ok:
        raise ctypes.WinError()
    try:
        protected = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        return base64.b64encode(protected).decode("ascii")
    finally:
        kernel32.LocalFree(output_blob.pbData)


def unprotect_secret(encoded: str) -> str:
    if not encoded:
        return ""
    if sys.platform != "win32":
        return ""

    protected = base64.b64decode(encoded)
    input_blob, input_buffer = _blob_from_bytes(protected)
    output_blob = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    _ = input_buffer
    if not ok:
        raise ctypes.WinError()
    try:
        raw = ctypes.string_at(output_blob.pbData, output_blob.cbData)
        return raw.decode("utf-8")
    finally:
        kernel32.LocalFree(output_blob.pbData)


def default_config_path() -> Path:
    override = os.environ.get("SZU_GUARDIAN_DATA_DIR")
    if override:
        return Path(override) / "config.json"
    base = os.environ.get("LOCALAPPDATA")
    if sys.platform == "win32" and base:
        return Path(base) / APP_DIRECTORY / "config.json"
    if sys.platform.startswith("linux"):
        base = os.environ.get("XDG_CONFIG_HOME")
        return (Path(base) if base else Path.home() / ".config") / "szu-network-guardian" / "config.json"
    return Path.home() / f".{APP_DIRECTORY}" / "config.json"


class ConfigStore:
    def __init__(self, path: Path | None = None):
        self.path = path or default_config_path()

    def _linux_cipher(self, create: bool = False):
        from cryptography.fernet import Fernet

        key_path = self.path.with_suffix(".key")
        if create and not key_path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(Fernet.generate_key())
        # Never create a new key when loading: losing the old key must be visible.
        return Fernet(self._read_private_file(key_path))

    @staticmethod
    def _read_private_file(path: Path) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError("配置和密钥必须是普通文件")
            if os.name == "posix":
                if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
                    raise OSError("配置或密钥必须属于当前用户且权限为 600")
            return stream.read()

    def load(self) -> AppConfig:
        if not self.path.exists():
            return AppConfig()
        try:
            raw = self._read_private_file(self.path) if sys.platform.startswith("linux") else self.path.read_bytes()
            payload = json.loads(raw.decode("utf-8"))
            # Previous versions saved passwords implicitly. Require explicit opt-in anew.
            remember = payload.get("remember_password") is True
            if not remember:
                password = ""
            elif sys.platform.startswith("linux") and payload.get("password_fernet"):
                from cryptography.fernet import InvalidToken

                try:
                    password = self._linux_cipher().decrypt(
                        str(payload["password_fernet"]).encode("ascii")
                    ).decode("utf-8")
                except (OSError, ValueError, InvalidToken) as exc:
                    raise OSError("无法解密密码，请检查 config.key 和权限或重新配置") from exc
            else:
                password = unprotect_secret(str(payload.get("password_dpapi", "")))
            schema_version = int(payload.get("schema_version", 1))
            zone = str(payload.get("zone", ZONE_AUTO))
            if schema_version < 2:
                zone = ZONE_AUTO
            return AppConfig(
                username=str(payload.get("username", "")),
                password=password,
                zone=zone,
                interval_minutes=int(payload.get("interval_minutes", 5)),
                autostart=bool(payload.get("autostart", False)),
                start_on_launch=bool(payload.get("start_on_launch", True)),
                direct_mode=bool(payload.get("direct_mode", True)),
                interface=str(payload.get("interface", "")),
                remember_password=remember,
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            return AppConfig()

    def save(self, config: AppConfig) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if sys.platform.startswith("linux") and os.name == "posix":
            if self.path.parent.stat().st_uid != os.getuid():
                raise OSError("配置目录必须属于当前用户")
            self.path.parent.chmod(0o700)
        payload = config.public_dict()
        payload["schema_version"] = 5
        if config.remember_password and sys.platform.startswith("linux"):
            payload["password_fernet"] = (
                self._linux_cipher(create=True).encrypt(config.password.encode("utf-8")).decode("ascii")
                if config.password else ""
            )
        elif config.remember_password:
            payload["password_dpapi"] = protect_secret(config.password)
        descriptor, temporary_name = tempfile.mkstemp(dir=self.path.parent, prefix=".config-", suffix=".tmp")
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, ensure_ascii=False, indent=2))
            temporary.replace(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def forget_password(self) -> None:
        config = self.load_without_password()
        config.remember_password = False
        config.password = ""
        self.save(config)
        self.path.with_suffix(".key").unlink(missing_ok=True)

    def load_without_password(self) -> AppConfig:
        """Load public settings even when an old key has been lost/corrupted."""
        if not self.path.exists():
            return AppConfig()
        raw = self._read_private_file(self.path) if sys.platform.startswith("linux") else self.path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        return AppConfig(
            username=str(payload.get("username", "")), zone=str(payload.get("zone", "office")),
            interval_minutes=int(payload.get("interval_minutes", 5)),
            direct_mode=bool(payload.get("direct_mode", True)),
            interface=str(payload.get("interface", "")),
        )
