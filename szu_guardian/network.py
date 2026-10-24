from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

import requests

from .direct_network import DirectRoute
from .models import (
    AppConfig,
    ZONE_OFFICE,
)
from .srun import SrunClient
from .security import SecurityError


MICROSOFT_CHECK_URL = "http://www.msftconnecttest.com/connecttest.txt"
MICROSOFT_CHECK_TEXT = "Microsoft Connect Test"
BAIDU_SEARCH_URL = "https://www.baidu.com/s"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 Chrome/124 Safari/537.36"
    )
}

ProgressCallback = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class ConnectionResult:
    connected: bool
    message: str
    latency_ms: int | None = None


def _new_direct_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.headers.update(HEADERS)
    return session


class NetworkClient:
    def __init__(
        self,
        session: requests.Session | None = None,
        portal_session: requests.Session | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        verify_delays: tuple[float, ...] = (2.0, 4.0, 8.0),
    ):
        self.session = session or _new_direct_session()
        self.portal_session = portal_session or (
            session if session is not None else _new_direct_session()
        )
        for active_session in {id(self.session): self.session, id(self.portal_session): self.portal_session}.values():
            active_session.trust_env = False
            active_session.headers.update(HEADERS)
        self.sleeper = sleeper
        self.verify_delays = verify_delays
        self._allow_direct_setup = session is None and portal_session is None
        self.direct_route: DirectRoute | None = None

    def _configure_direct(self, enabled: bool, interface: str = "") -> None:
        if not self._allow_direct_setup:
            return
        # Refresh source address and DNS on each cycle, including after DHCP renewal.
        route = DirectRoute.discover(interface) if enabled else None
        for session in {id(self.session): self.session, id(self.portal_session): self.portal_session}.values():
            session.close()
        self.direct_route = route
        self.session = route.session() if route else _new_direct_session()
        self.portal_session = route.session() if route else _new_direct_session()
        self.session.headers.update(HEADERS)
        self.portal_session.headers.update(HEADERS)

    def _get_check_target(self, url: str) -> requests.Response:
        return self.session.get(
            url,
            timeout=(3, 5),
            allow_redirects=False,
            verify=True,
        )

    def check_connection(self) -> ConnectionResult:
        started = time.perf_counter()
        errors: list[str] = []
        probe_token = f"szu_guardian_{secrets.token_hex(8)}"
        targets = (
            (MICROSOFT_CHECK_URL, MICROSOFT_CHECK_TEXT, None),
            (f"{BAIDU_SEARCH_URL}?wd={probe_token}", "baidu_search", probe_token),
        )
        successful_probes = 0

        for url, expected, token in targets:
            try:
                response = self._get_check_target(url)
                if expected == "baidu_search":
                    location = response.headers.get("Location", "")
                    redirect_host = urlparse(location).hostname or ""
                    redirect_is_baidu = not redirect_host or redirect_host.endswith(
                        ".baidu.com"
                    )
                    response_text = response.text + " " + location
                    valid = (
                        response.status_code in (200, 301, 302, 303, 307, 308)
                        and redirect_is_baidu
                        and bool(token and token in response_text)
                    )
                else:
                    valid = (
                        response.status_code == 200
                        and expected in response.text
                    )
                if valid:
                    successful_probes += 1
                else:
                    errors.append(f"检测页返回 {response.status_code}")
            except requests.RequestException as exc:
                errors.append(type(exc).__name__)

        if successful_probes == len(targets):
            latency = round((time.perf_counter() - started) * 1000)
            mode = "（校园网直连）" if self.direct_route else ""
            return ConnectionResult(True, f"网络连接正常{mode}", latency)

        detail = " / ".join(errors[-2:]) if errors else "无响应"
        return ConnectionResult(False, f"直连外网不可用（{detail}）")

    def _teaching_srun_client(self, config: AppConfig) -> SrunClient:
        return SrunClient(
            config.username,
            config.password,
            session=self.portal_session,
        )

    def _teaching_online_status(self, config: AppConfig) -> bool | None:
        try:
            return self._teaching_srun_client(config).is_online()
        except SecurityError:
            raise
        except (ConnectionError, requests.RequestException):
            return None

    def _login_dormitory(self, config: AppConfig) -> str:
        raise SecurityError("安全版已禁用宿舍区明文 HTTP 认证，仅支持教学／办公区")

    def _login_teaching(self, config: AppConfig) -> str:
        result = self._teaching_srun_client(config).login()
        if not result.success:
            raise ConnectionError(
                f"教学 / 办公区认证失败：{result.message or '请检查账号和密码'}"
            )
        return result.message

    def send_login(
        self,
        config: AppConfig,
        progress_callback: ProgressCallback | None = None,
    ) -> str:
        zone = config.zone
        if zone != ZONE_OFFICE:
            raise SecurityError("安全版仅支持教学／办公区，不会回退到 HTTP 宿舍认证")
        if progress_callback:
            progress_callback("正在使用教学／办公区认证…")
        return self._login_teaching(config)

    def ensure_connected(
        self,
        config: AppConfig,
        progress_callback: ProgressCallback | None = None,
    ) -> ConnectionResult:
        config.validate()
        self._configure_direct(config.direct_mode, config.interface)
        authentication_expired = False
        if config.zone == ZONE_OFFICE:
            authentication_expired = self._teaching_online_status(config) is False
            if authentication_expired and progress_callback:
                progress_callback("检测到校园网认证已失效，正在重新认证…")

        if not authentication_expired:
            current = self.check_connection()
            if current.connected:
                return current

        login_message = self.send_login(config, progress_callback)
        if progress_callback:
            progress_callback(f"{login_message}，正在等待外网恢复…")

        for attempt, delay in enumerate(self.verify_delays, start=1):
            self.sleeper(delay)
            verified = self.check_connection()
            if verified.connected:
                return ConnectionResult(
                    True,
                    "已自动重连，网络恢复正常",
                    verified.latency_ms,
                )
            if progress_callback and attempt < len(self.verify_delays):
                progress_callback(
                    f"外网尚未恢复，{self.verify_delays[attempt]:g} 秒后再次复查…"
                )

        return ConnectionResult(
            False,
            "认证服务器已确认请求，但外网仍不可用；请查看本地日志中的认证结果",
        )
