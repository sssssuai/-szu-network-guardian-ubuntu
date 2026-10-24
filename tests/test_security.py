from __future__ import annotations

import datetime as dt
import io
import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = None

import main
from szu_guardian.direct_network import DirectRoute
from szu_guardian.models import AppConfig
from szu_guardian.monitor import MonitorController
from szu_guardian.network import NetworkClient
from szu_guardian.security import SecurityError, hidden_password
from szu_guardian.service import service_unit
from szu_guardian.srun import SrunClient
from szu_guardian.storage import ConfigStore


def mock_response(text='_( {"error":"ok"} )', status=200):
    response = Mock()
    response.text, response.status_code, response.headers = text, status, {}
    return response


class AuthenticationPolicyTests(unittest.TestCase):
    def test_every_srun_request_verifies_tls_and_disables_redirects(self):
        session = Mock(headers={})
        session.get.side_effect = [
            mock_response('<a href="/index?ac_id=1">portal</a>'),
            mock_response('_( {"challenge":"sample-token","client_ip":"172.30.1.2","error":"ok"} )'),
            mock_response(),
        ]
        self.assertTrue(SrunClient("account", "secret", session=session).login().success)
        self.assertEqual(len(session.get.call_args_list), 3)
        for call in session.get.call_args_list:
            self.assertIs(call.kwargs["verify"], True)
            self.assertIs(call.kwargs["allow_redirects"], False)
            self.assertTrue(call.args[0].startswith("https://net.szu.edu.cn/"))

    def test_tls_failure_during_discovery_stops_before_challenge_or_login(self):
        session = Mock(headers={})
        session.get.side_effect = requests.exceptions.SSLError("bad certificate; info=private-token")
        with self.assertRaises(SecurityError) as error:
            SrunClient("account", "secret", session=session).login()
        self.assertEqual(session.get.call_count, 1)
        self.assertNotIn("params", session.get.call_args.kwargs)
        self.assertNotIn("private-token", str(error.exception))

    def test_network_does_not_treat_security_failure_as_unknown_online_status(self):
        session = Mock(headers={})
        session.get.side_effect = requests.exceptions.SSLError("bad certificate")
        client = NetworkClient(session=session, portal_session=session)
        with patch.object(client, "send_login") as login, self.assertRaises(SecurityError):
            client.ensure_connected(AppConfig(username="account", password="secret", direct_mode=False))
        login.assert_not_called()

    def test_auth_redirect_is_rejected_without_followup(self):
        session = Mock(headers={})
        session.get.return_value = mock_response(status=302)
        session.get.return_value.headers = {"Location": "http://evil.invalid/collect"}
        with self.assertRaises(SecurityError):
            SrunClient("account", "secret", session=session).is_online()
        self.assertEqual(session.get.call_count, 1)
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_http_ip_and_foreign_auth_origins_are_rejected_before_request(self):
        for origin in ("http://net.szu.edu.cn", "https://172.30.1.2", "https://evil.invalid", "https://net.szu.edu.cn.evil.invalid"):
            session = Mock(headers={})
            with self.assertRaises(SecurityError):
                SrunClient("account", "secret", session=session, base_url=origin)
            session.get.assert_not_called()

    def test_dormitory_is_blocked_before_sending_any_data(self):
        session = Mock(headers={})
        with self.assertRaises(SecurityError):
            NetworkClient(session=session)._login_dormitory(AppConfig(username="account", password="secret"))
        session.get.assert_not_called()

    def test_server_error_text_is_not_echoed(self):
        session = Mock(headers={})
        session.get.side_effect = [
            mock_response('href="/?ac_id=1"'),
            mock_response('_( {"error":"reject","error_msg":"secret challenge=private-token"} )'),
        ]
        result = SrunClient("account", "secret", session=session).login()
        self.assertFalse(result.success)
        self.assertNotIn("secret", result.message)
        self.assertNotIn("private-token", result.message)

    def test_request_exception_does_not_include_encoded_login_payload(self):
        session = Mock(headers={})
        session.get.side_effect = requests.exceptions.HTTPError("https://net.szu.edu.cn/cgi-bin/srun_portal?info=payload&chksum=token")
        with self.assertRaises(ConnectionError) as error:
            SrunClient("account", "secret", session=session).is_online()
        self.assertNotIn("payload", str(error.exception))
        self.assertNotIn("token", str(error.exception))

    def test_monitor_stops_after_security_failure(self):
        events = []
        client = Mock()
        client.ensure_connected.side_effect = SecurityError("证书校验失败")
        monitor = MonitorController(events.append, client_factory=lambda: client)
        monitor._run_loop(AppConfig(username="account", password="secret"))
        self.assertEqual(client.ensure_connected.call_count, 1)
        self.assertEqual(events[-1].state, "stopped")

    def test_headless_security_failure_returns_two_without_retry(self):
        with patch("szu_guardian.network.NetworkClient") as factory, patch("szu_guardian.local_log.LocalLog"), patch("sys.stdout", new_callable=io.StringIO):
            factory.return_value.ensure_connected.side_effect = SecurityError("证书校验失败")
            self.assertEqual(main.run_headless(AppConfig(username="account", password="secret")), 2)
            self.assertEqual(factory.return_value.ensure_connected.call_count, 1)

    def test_service_will_not_restart_after_security_exit(self):
        self.assertIn("RestartPreventExitStatus=2", service_unit())


class PasswordPolicyTests(unittest.TestCase):
    def test_no_password_is_saved_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            store = ConfigStore(Path(directory) / "config.json")
            config = AppConfig(username="account", password="secret")
            store.save(config)
            payload = json.loads(store.path.read_text(encoding="utf-8"))
            self.assertNotIn("password", payload)
            self.assertNotIn("password_dpapi", payload)
            self.assertNotIn("password_fernet", payload)
            self.assertFalse(payload["remember_password"])
            self.assertEqual(store.load().password, "")
            self.assertFalse(store.path.with_suffix(".key").exists())
            self.assertNotIn("secret", repr(config))

    def test_legacy_password_requires_new_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"schema_version": 4, "username": "account", "zone": "office", "password_fernet": "old-ciphertext"}), encoding="utf-8")
            path.chmod(0o600)
            with patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")):
                config = ConfigStore(path).load()
            self.assertFalse(config.remember_password)
            self.assertEqual(config.password, "")

    @unittest.skipIf(x509 is None, "cryptography required")
    def test_forget_password_removes_ciphertext_and_key(self):
        with tempfile.TemporaryDirectory() as directory, patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")):
            store = ConfigStore(Path(directory) / "config.json")
            store.save(AppConfig(username="account", password="secret", remember_password=True))
            self.assertTrue(store.path.with_suffix(".key").exists())
            store.forget_password()
            self.assertFalse(store.path.with_suffix(".key").exists())
            self.assertEqual(store.load().password, "")
            self.assertEqual(store.load().username, "account")
            self.assertNotIn("password_fernet", store.path.read_text(encoding="utf-8"))

    def test_hidden_input_unavailable_is_rejected_without_fallback(self):
        import getpass

        with patch("szu_guardian.security.sys.stdin.isatty", return_value=True), patch("szu_guardian.security.getpass.getpass", side_effect=getpass.GetPassWarning("cannot disable echo")):
            with self.assertRaisesRegex(ValueError, "无法隐藏"):
                hidden_password()

    def test_noninteractive_password_input_is_rejected(self):
        with patch("szu_guardian.security.sys.stdin.isatty", return_value=False):
            with self.assertRaises(ValueError):
                hidden_password()

    def test_cli_configure_does_not_request_password_unless_saving(self):
        with tempfile.TemporaryDirectory() as directory, patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="account"), patch("main.hidden_password") as password, patch("sys.stdout", new_callable=io.StringIO):
            store = ConfigStore(Path(directory) / "config.json")
            main.configure(store, main.parse_args(["--configure", "--zone", "office"]))
            password.assert_not_called()
            self.assertEqual(store.load().password, "")

    @unittest.skipUnless(os.name == "posix", "Linux file permissions")
    def test_world_readable_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text("{}", encoding="utf-8")
            path.chmod(0o644)
            with patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")), self.assertRaises(OSError):
                ConfigStore(path).load()

    @unittest.skipUnless(os.name == "posix", "Linux O_NOFOLLOW")
    def test_symlink_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.json"
            target.write_text("{}", encoding="utf-8")
            target.chmod(0o600)
            path = Path(directory) / "config.json"
            path.symlink_to(target)
            with patch("szu_guardian.storage.sys", SimpleNamespace(platform="linux")), self.assertRaises(OSError):
                ConfigStore(path).load()


@unittest.skipIf(x509 is None, "cryptography required for TLS integration tests")
class TlsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = dt.datetime.now(dt.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local test CA")])
        cls.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(cls.ca_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=2)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(cls.ca_key, hashes.SHA256()))
        cls.ca_path = cls.root / "ca.pem"
        cls.ca_path.write_bytes(cls.ca.public_bytes(serialization.Encoding.PEM))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    @contextmanager
    def server(self, hostname="net.szu.edu.cn", expired=False):
        now = dt.datetime.now(dt.timezone.utc)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        certificate = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self.ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=2))
            .not_valid_after(now - dt.timedelta(days=1) if expired else now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(self.ca_key, hashes.SHA256()))
        cert_path, key_path = self.root / "server.pem", self.root / "server.key"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        seen, names = [], []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Host")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_):
                pass

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        httpd.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.set_servername_callback(lambda _socket, name, _context: names.append(name))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=lambda: httpd.serve_forever(poll_interval=0.02), daemon=True)
        thread.start()
        route = DirectRoute("127.0.0.1")
        route._cache["net.szu.edu.cn"] = ["127.0.0.1"]
        session = route.session()
        try:
            yield session, f"https://net.szu.edu.cn:{httpd.server_port}/check?marker=synthetic-test", seen, names
        finally:
            session.close()
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=2)

    def test_valid_certificate_sni_and_original_host_succeed_over_bound_ipv4(self):
        with self.server() as (session, url, seen, names), patch("requests.adapters.DEFAULT_CA_BUNDLE_PATH", str(self.ca_path)):
            response = session.get(url, timeout=2, verify=True, allow_redirects=False)
            self.assertEqual(response.text, "ok")
            self.assertEqual(names, ["net.szu.edu.cn"])
            self.assertTrue(seen[0][1].startswith("net.szu.edu.cn:"))

    def test_untrusted_certificate_blocks_http_payload(self):
        with self.server() as (session, url, seen, _):
            with self.assertRaises(requests.exceptions.SSLError):
                session.get(url, timeout=2, verify=True)
            self.assertEqual(seen, [])

    def test_wrong_hostname_blocks_http_payload_even_with_trusted_ca(self):
        with self.server(hostname="other.invalid") as (session, url, seen, _), patch("requests.adapters.DEFAULT_CA_BUNDLE_PATH", str(self.ca_path)):
            with self.assertRaises(requests.exceptions.SSLError):
                session.get(url, timeout=2, verify=True)
            self.assertEqual(seen, [])

    def test_expired_certificate_blocks_http_payload(self):
        with self.server(expired=True) as (session, url, seen, _), patch("requests.adapters.DEFAULT_CA_BUNDLE_PATH", str(self.ca_path)):
            with self.assertRaises(requests.exceptions.SSLError):
                session.get(url, timeout=2, verify=True)
            self.assertEqual(seen, [])

    def test_verify_false_is_rejected_before_connection(self):
        with self.server() as (session, url, seen, names):
            with self.assertRaises(SecurityError):
                session.get(url, timeout=2, verify=False)
            self.assertEqual(seen, [])
            self.assertEqual(names, [])


if __name__ == "__main__":
    unittest.main()
