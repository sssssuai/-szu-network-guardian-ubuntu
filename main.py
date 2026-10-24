from __future__ import annotations

import argparse
import ctypes
import sys
import os
import signal
import threading

from szu_guardian.models import AppConfig, VALID_ZONES
from szu_guardian.storage import ConfigStore
from szu_guardian.security import SecurityError, hidden_password


def enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SZU 校园网自动重连安全版 2（教学／办公区）")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--configure", action="store_true", help="配置账号与选项；默认不保存密码")
    actions.add_argument("--forget-password", action="store_true", help="删除当前配置中的密码密文及本地密钥")
    actions.add_argument("--check-security", action="store_true", help="无需账号密码，检查学校服务器 TLS 证书")
    actions.add_argument("--headless", action="store_true", help="无桌面后台监控，Ctrl+C 停止")
    actions.add_argument("--once", action="store_true", help="检测并按需认证一次，成功返回 0")
    actions.add_argument("--install-service", action="store_true", help="安装并启动用户 systemd 服务")
    actions.add_argument("--remove-service", action="store_true", help="停止并删除用户 systemd 服务")
    actions.add_argument("--diagnose", action="store_true", help="显示 Linux 网卡和 DNS，无需账号密码")
    actions.add_argument("--autostart", action="store_true", help="由桌面自启动项调用")
    parser.add_argument("--zone", choices=sorted(VALID_ZONES), help="office=教学办公区（安全版仅支持此区域）")
    parser.add_argument("--save-password", action="store_true", help="配合 --configure，明确同意本地加密保存密码")
    parser.add_argument("--ask-password", action="store_true", help="本次重新输入密码，仅保留在内存中")
    parser.add_argument("--interval", type=int, help="检测间隔，1~1440 分钟")
    parser.add_argument("--interface", help="Linux 校园网网卡名称，如 enp3s0；空字符串表示自动选择")
    parser.add_argument("--no-direct", action="store_true", help="使用系统路由与 DNS（仍忽略环境代理）")
    tray = parser.add_mutually_exclusive_group()
    tray.add_argument("--tray", action="store_true", help="启用系统托盘（Linux 需兼容的桌面托盘后端）")
    tray.add_argument("--no-tray", action="store_true", help="禁用系统托盘，关闭窗口退出")
    return parser.parse_args(argv)


def apply_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    if args.zone is not None:
        config.zone = args.zone
    if args.interval is not None:
        config.interval_minutes = args.interval
    if args.interface is not None:
        config.interface = args.interface
    if args.no_direct:
        config.direct_mode = False
    return config


def configure(store: ConfigStore, args: argparse.Namespace) -> int:
    if not sys.stdin.isatty():
        raise ValueError("请在交互终端运行 --configure；密码不会显示或作为命令行参数传入")
    try:
        config = store.load_without_password()
    except OSError:
        config = AppConfig()
        print("原配置不可读取，将重新配置。")
    config = apply_overrides(config, args)
    config.username = input(f"校园网账号 [{config.username}]: ").strip() or config.username
    config.zone = "office"
    config.remember_password = args.save_password
    config.password = hidden_password() if config.remember_password else ""
    config.validate(require_password=config.remember_password)
    store.save(config)
    if not config.remember_password:
        store.path.with_suffix(".key").unlink(missing_ok=True)
    print(f"配置已保存：{store.path}")
    print("密码已在本地加密保存。" if config.remember_password else "未保存密码；运行 --once / --headless 时将在终端询问密码。")
    return 0


def run_headless(config: AppConfig, once: bool = False) -> int:
    from szu_guardian.local_log import LocalLog
    from szu_guardian.network import NetworkClient
    from szu_guardian.redaction import redact_message

    config.validate()
    log = LocalLog()
    stopped = threading.Event()
    previous = {}

    def stop(_signum, _frame):
        stopped.set()

    def report(message: str, level: str = "info"):
        message = redact_message(message, config.password)
        print(message, flush=True)
        log.write(message, level)

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, stop)
    try:
        report(f"开始监控：{config.zone}，间隔 {config.interval_minutes} 分钟")
        client = NetworkClient()
        while not stopped.is_set():
            try:
                result = client.ensure_connected(config, progress_callback=report)
                report(result.message, "success" if result.connected else "warning")
                if once:
                    return 0 if result.connected else 1
            except SecurityError as exc:
                report(f"安全校验失败，监控已停止：{exc}", "error")
                return 2
            except (ConnectionError, OSError, ValueError) as exc:
                report(f"检测或认证失败：{exc}", "error")
                if once:
                    return 1
            if once:
                break
            stopped.wait(config.interval_minutes * 60)
        report("监控已停止")
        return 0
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.save_password and not args.configure:
            raise ValueError("--save-password 仅可配合 --configure 使用")
        store = ConfigStore()
        if args.forget_password:
            store.forget_password()
            print("已移除当前配置中的密码和密钥；正在运行的进程需要退出才能释放内存中的密码。")
            return 0
        if args.diagnose:
            from szu_guardian.direct_network import adapter_dns_configs

            print(f"Python: {sys.version.split()[0]}  Platform: {sys.platform}")
            print(f"Config: {store.path}")
            adapters = adapter_dns_configs(args.interface or "")
            for adapter in adapters:
                print(f"Interface: {adapter.interface or '(Windows)'}  IPv4: {adapter.source_ip}  DNS: {', '.join(adapter.dns_servers) or '(fallback)'}")
            if not adapters:
                raise OSError("没有找到可用的物理网卡，可通过 --interface 手动指定")
            return 0
        if args.configure:
            return configure(store, args)
        if args.check_security:
            from szu_guardian.network import NetworkClient
            from szu_guardian.srun import SrunClient

            config = apply_overrides(store.load_without_password(), args)
            client = NetworkClient()
            try:
                client._configure_direct(config.direct_mode, config.interface)
                SrunClient("", "", session=client.portal_session).discover_ac_id()
                print("https://net.szu.edu.cn 的 TLS 证书和域名校验通过；本次未提交账号密码。")
            finally:
                client.session.close()
                client.portal_session.close()
            return 0
        if args.remove_service:
            from szu_guardian.service import remove_service

            remove_service()
            print("用户服务已移除")
            return 0
        config = apply_overrides(store.load(), args)
        if args.install_service:
            from szu_guardian.service import install_service

            if not config.remember_password:
                raise ValueError("无人值守服务需要明确保存密码；先运行 --configure --save-password")
            config.validate()
            store.save(config)
            install_service()
            print("用户服务已启用。查看状态：systemctl --user status szu-network-guardian")
            return 0
        no_display = sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if args.headless or args.once or no_display:
            from szu_guardian.instance import single_instance

            with single_instance():
                if args.ask_password or not config.password:
                    config.password = hidden_password()
                return run_headless(config, once=args.once)
        # GUI and tray dependencies are never imported by server/CLI commands.
        from szu_guardian.ui import GuardianApp, ZONE_NAMES

        enable_windows_dpi_awareness()
        use_tray = args.tray or (sys.platform == "win32" and not args.no_tray)
        from szu_guardian.instance import single_instance

        with single_instance():
            app = GuardianApp(store, launched_by_autostart=args.autostart, use_tray=use_tray)
            app.zone_var.set(ZONE_NAMES.get(config.zone, ZONE_NAMES["office"]))
            app.interval_var.set(str(config.interval_minutes))
            app.interface_var.set(config.interface)
            app.direct_mode_var.set(config.direct_mode)
            if args.ask_password:
                app.password_var.set("")
                app.remember_password_var.set(False)
                app.autostart_var.set(False)
            app.run()
        return 0
    except (OSError, ValueError, ImportError) as exc:
        print(f"无法运行：{exc}\n首次使用请运行 python main.py --configure --zone office", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
