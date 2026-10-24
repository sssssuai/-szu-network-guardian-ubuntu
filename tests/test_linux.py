import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch, Mock

try:
    from cryptography.fernet import Fernet
except ImportError:
    Fernet = None

import main
from szu_guardian.direct_network import DirectNetworkError, linux_adapter_dns_configs, _linux_dns_servers
from szu_guardian.models import AppConfig
from szu_guardian.network import NetworkClient, ConnectionResult
from szu_guardian.storage import ConfigStore, default_config_path
from szu_guardian.startup import set_autostart, is_autostart_enabled
from szu_guardian.service import install_service, remove_service, service_path, service_unit
from szu_guardian.redaction import redact_message


@unittest.skipIf(Fernet is None, "Linux storage tests require cryptography")
class LinuxStorageTests(unittest.TestCase):
    def test_password_roundtrip_and_config_has_no_plaintext(self):
        with tempfile.TemporaryDirectory() as directory, patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")):
            path = Path(directory) / "data" / "config.json"
            store = ConfigStore(path)
            config = AppConfig(username="test-account", password="secret 密码 !", interface="enp3s0", remember_password=True)
            store.save(config)
            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(config.password, raw)
            self.assertNotIn("password_dpapi", raw)
            self.assertEqual(store.load().password, config.password)
            self.assertEqual(store.load().interface, "enp3s0")
            first_key = path.with_suffix(".key").read_bytes()
            store.save(config)
            self.assertEqual(path.with_suffix(".key").read_bytes(), first_key)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.with_suffix(".key").stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_missing_key_is_reported_and_not_regenerated(self):
        with tempfile.TemporaryDirectory() as directory, patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")):
            store = ConfigStore(Path(directory) / "config.json")
            store.save(AppConfig(username="test", password="secret", remember_password=True))
            store.path.with_suffix(".key").unlink()
            with self.assertRaisesRegex(OSError, "无法解密"):
                store.load()
            self.assertFalse(store.path.with_suffix(".key").exists())

    def test_tampered_token_is_reported(self):
        with tempfile.TemporaryDirectory() as directory, patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")):
            store = ConfigStore(Path(directory) / "config.json")
            store.save(AppConfig(username="test", password="secret", remember_password=True))
            payload = json.loads(store.path.read_text(encoding="utf-8"))
            payload["password_fernet"] = Fernet(Fernet.generate_key()).encrypt(b"other").decode()
            store.path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(OSError, "无法解密"):
                store.load()

    def test_xdg_path_and_override(self):
        with patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")), patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdg", "LOCALAPPDATA": "/ignored"}, clear=True):
            self.assertEqual(str(default_config_path()).replace("\\", "/"), "/tmp/xdg/szu-network-guardian/config.json")
            with patch.dict(os.environ, {"SZU_GUARDIAN_DATA_DIR": "/tmp/custom"}):
                self.assertEqual(str(default_config_path()).replace("\\", "/"), "/tmp/custom/config.json")


class LinuxNetworkTests(unittest.TestCase):
    def setUp(self):
        self.output = json.dumps([
            {"ifname": "tun0", "addr_info": [{"scope": "global", "local": "198.18.0.1"}]},
            {"ifname": "docker0", "addr_info": [{"scope": "global", "local": "172.17.0.1"}]},
            {"ifname": "enp3s0", "addr_info": [
                {"scope": "global", "local": "172.30.8.9"},
                {"scope": "link", "local": "169.254.1.2"},
            ]},
        ])

    def test_selects_physical_campus_interface_and_dns(self):
        with patch("szu_guardian.direct_network._command_output", return_value=self.output), patch("szu_guardian.direct_network._linux_dns_servers", return_value=("192.168.247.6",)), patch.object(Path, "exists", lambda path: path.parent.name == "enp3s0"):
            configs = linux_adapter_dns_configs()
        self.assertEqual([(c.source_ip, c.interface) for c in configs], [("172.30.8.9", "enp3s0")])
        self.assertEqual(configs[0].dns_servers, ("192.168.247.6",))

    def test_explicit_interface_allows_bridge(self):
        with patch("szu_guardian.direct_network._command_output", return_value=self.output), patch("szu_guardian.direct_network._linux_dns_servers", return_value=()):
            configs = linux_adapter_dns_configs("docker0")
            self.assertEqual(configs[0].source_ip, "172.17.0.1")
            with self.assertRaisesRegex(DirectNetworkError, "没有可用"):
                linux_adapter_dns_configs("missing0")

    def test_missing_ip_command_produces_actionable_error(self):
        with patch("szu_guardian.direct_network._command_output", return_value=""):
            with self.assertRaisesRegex(DirectNetworkError, "iproute2"):
                linux_adapter_dns_configs()

    def test_resolved_stub_and_fake_dns_are_excluded(self):
        with patch("szu_guardian.direct_network._command_output", return_value="Link 2 (enp3s0): 127.0.0.53 198.18.0.1 192.168.247.6\n"):
            self.assertEqual(_linux_dns_servers("enp3s0"), ("192.168.247.6",))

    def test_nmcli_fallback(self):
        with patch("szu_guardian.direct_network._command_output", side_effect=["", "192.168.247.6\n223.5.5.5\n"]):
            self.assertEqual(_linux_dns_servers("enp3s0"), ("192.168.247.6", "223.5.5.5"))

    def test_dhcp_address_refreshes_between_checks(self):
        client = NetworkClient()
        with patch("szu_guardian.network.DirectRoute.discover") as discover:
            old_route, new_route = Mock(), Mock()
            discover.side_effect = [old_route, new_route]
            client._configure_direct(True, "enp3s0")
            old_session = client.session
            client._configure_direct(True, "enp3s0")
            old_session.close.assert_called()
            self.assertIs(client.direct_route, new_route)
            self.assertEqual(discover.call_count, 2)
        client._configure_direct(False)
        self.assertIsNone(client.direct_route)
        client.session.close()
        client.portal_session.close()


class LinuxStartupTests(unittest.TestCase):
    def test_desktop_autostart_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}), patch("szu_guardian.startup.sys", SimpleNamespace(platform="linux", executable="/tmp/path with space/.venv/bin/python")):
            self.assertFalse(is_autostart_enabled())
            set_autostart(True)
            self.assertTrue(is_autostart_enabled())
            text = (Path(directory) / "autostart" / "szu-network-guardian.desktop").read_text(encoding="utf-8")
            self.assertIn('"/tmp/path with space/.venv/bin/python"', text)
            self.assertIn("--autostart", text)
            set_autostart(False)
            self.assertFalse(is_autostart_enabled())

    def test_service_preserves_venv_and_persists_data_directory(self):
        with patch("szu_guardian.service.sys", SimpleNamespace(platform="linux", executable="/tmp/my app/.venv/bin/python")), patch("szu_guardian.service.default_config_path", return_value=PurePosixPath("/tmp/my config/config.json")):
            unit = service_unit()
            self.assertIn('"/tmp/my app/.venv/bin/python"', unit)
            self.assertIn('"SZU_GUARDIAN_DATA_DIR=/tmp/my config"', unit)
            self.assertIn("--headless", unit)
            self.assertNotIn("--autostart", unit)

    def test_install_remove_service_only_touches_user_unit(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"XDG_CONFIG_HOME": directory}), patch("szu_guardian.service.sys", SimpleNamespace(platform="linux", executable="/tmp/venv/bin/python")), patch("szu_guardian.service._systemctl") as systemctl:
            install_service()
            self.assertTrue(service_path().exists())
            systemctl.assert_any_call("enable", "--now", "szu-network-guardian.service")
            remove_service()
            self.assertFalse(service_path().exists())
            systemctl.assert_any_call("disable", "--now", "szu-network-guardian.service")


class CliTests(unittest.TestCase):
    def test_once_returns_success_or_failure_without_gui(self):
        config = AppConfig(username="test", password="secret", direct_mode=False)
        for connected, code in [(True, 0), (False, 1)]:
            with patch("szu_guardian.network.NetworkClient") as factory, patch("szu_guardian.local_log.LocalLog"), patch("sys.stdout", new_callable=io.StringIO):
                factory.return_value.ensure_connected.return_value = ConnectionResult(connected, "result")
                self.assertEqual(main.run_headless(config, once=True), code)

    def test_request_error_is_redacted_and_once_fails(self):
        with patch("szu_guardian.network.NetworkClient") as factory, patch("szu_guardian.local_log.LocalLog"), patch("sys.stdout", new_callable=io.StringIO) as output:
            factory.return_value.ensure_connected.side_effect = OSError("http://portal/login?user_password=secret")
            self.assertEqual(main.run_headless(AppConfig(username="test", password="secret"), once=True), 1)
            self.assertNotIn("user_password", output.getvalue())
            self.assertNotIn("secret", output.getvalue())

    def test_cli_options_and_validation(self):
        config = main.apply_overrides(AppConfig(username="test", password="secret"), main.parse_args(["--once", "--zone", "office", "--interface", "enp3s0", "--interval", "3", "--no-direct"]))
        config.validate()
        self.assertEqual(config.interface, "enp3s0")
        self.assertFalse(config.direct_mode)
        config.interface = "bad;name"
        with self.assertRaises(ValueError):
            config.validate()

    def test_password_and_encoded_password_are_redacted(self):
        self.assertEqual(redact_message("a b! a%20b%21 a+b%21", "a b!"), "[redacted] [redacted] [redacted]")


if __name__ == "__main__":
    unittest.main()
