"""Fail-closed authentication policy for the teaching/office network."""
from __future__ import annotations

import getpass
import sys
import warnings

import requests

PORTAL_ORIGIN = "https://net.szu.edu.cn"


class SecurityError(ConnectionError):
    """An authentication attempt was blocked before sending credentials."""


def hidden_password() -> str:
    if not sys.stdin.isatty():
        raise ValueError("请在交互终端输入密码；未保存密码时无法无人值守启动")
    # getpass otherwise falls back to visible input when terminal echo cannot be disabled.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("校园网密码（输入不显示）: ")
    except getpass.GetPassWarning as exc:
        raise ValueError("终端无法隐藏密码输入，已取消。请使用正常终端或图形界面") from exc


def authentication_error(exc: Exception) -> ConnectionError:
    # Do not include requests exceptions: they may contain encoded login URLs.
    if isinstance(exc, requests.exceptions.SSLError):
        return SecurityError("认证服务器 TLS 证书或握手校验失败，已阻止认证；请检查系统时间和可信证书，不要关闭校验")
    return ConnectionError(f"认证请求失败（{type(exc).__name__}），未记录请求参数")
