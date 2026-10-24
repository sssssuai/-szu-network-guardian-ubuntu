from __future__ import annotations

from dataclasses import asdict, dataclass, field
import re


ZONE_AUTO = "auto"
ZONE_OFFICE = "office"
ZONE_DORMITORY = "dormitory"
VALID_ZONES = {ZONE_OFFICE}


@dataclass(slots=True)
class AppConfig:
    username: str = ""
    password: str = field(default="", repr=False)
    zone: str = ZONE_OFFICE
    interval_minutes: int = 5
    autostart: bool = False
    start_on_launch: bool = True
    direct_mode: bool = True
    interface: str = ""
    remember_password: bool = False

    def validate(self, require_password: bool = True) -> None:
        self.username = self.username.strip()
        if not self.username:
            raise ValueError("请输入校园网账号")
        if require_password and not self.password:
            raise ValueError("请输入校园网密码")
        self.interface = self.interface.strip()
        if self.interface and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", self.interface):
            raise ValueError("网卡名称不合法，例如 enp3s0 或 wlp2s0")
        if self.zone not in VALID_ZONES:
            raise ValueError("安全版仅支持教学／办公区，已禁用明文 HTTP 宿舍认证和自动回退")
        try:
            self.interval_minutes = int(self.interval_minutes)
        except (TypeError, ValueError) as exc:
            raise ValueError("监控间隔必须是整数分钟") from exc
        if not 1 <= self.interval_minutes <= 1440:
            raise ValueError("监控间隔应在 1 到 1440 分钟之间")

    def public_dict(self) -> dict[str, object]:
        data = asdict(self)
        data.pop("password", None)
        return data
