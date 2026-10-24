import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from szu_guardian.models import AppConfig, ZONE_AUTO, ZONE_DORMITORY
from szu_guardian.network import ConnectionResult, NetworkClient
from szu_guardian.security import SecurityError


def response(url, status=200, text=""):
    value = Mock()
    value.url = url
    value.status_code = status
    value.text = text
    value.headers = {}
    value.raise_for_status.return_value = None
    return value


def connected_probe_response(url, **kwargs):
    if "/cgi-bin/rad_user_info" in url:
        return response(url, text='_( {"error":"ok"} )')
    if "msftconnecttest.com" in url:
        return response(url, text="Microsoft Connect Test")
    token = parse_qs(urlparse(url).query)["wd"][0]
    value = response(url, status=302, text=token)
    value.headers = {"Location": "https://wappass.baidu.com/captcha"}
    return value


class NetworkClientTests(unittest.TestCase):
    def test_online_does_not_send_login(self):
        session = Mock()
        session.headers = {}
        session.get.side_effect = connected_probe_response
        client = NetworkClient(
            session=session,
            portal_session=session,
            sleeper=lambda _: None,
        )

        result = client.ensure_connected(
            AppConfig(
                username="user",
                password="password",
                zone="office",
            )
        )

        self.assertTrue(result.connected)
        session.post.assert_not_called()

    def test_expired_teaching_session_reconnects_even_when_web_is_reachable(self):
        session = Mock()
        session.headers = {}
        client = NetworkClient(
            session=session,
            portal_session=session,
            sleeper=lambda _: None,
            verify_delays=(0,),
        )
        config = AppConfig(username="user", password="password")

        with (
            patch.object(client, "_teaching_online_status", return_value=False),
            patch.object(
                client,
                "check_connection",
                return_value=ConnectionResult(True, "网络连接正常"),
            ) as check,
            patch.object(client, "send_login", return_value="认证成功") as login,
        ):
            result = client.ensure_connected(config)

        self.assertTrue(result.connected)
        login.assert_called_once_with(config, None)
        check.assert_called_once_with()

    def test_offline_sends_login_and_verifies(self):
        session = Mock()
        session.headers = {}
        def handle_request(url, **kwargs):
            if "rad_user_info" in url:
                return response(url, text='_( {"error":"not_online_error"} )')
            if url == "https://net.szu.edu.cn/":
                return response(url, text='href="/index?ac_id=1"')
            if "get_challenge" in url:
                return response(url, text='_( {"challenge":"sample-token","client_ip":"172.30.1.2","error":"ok"} )')
            if "srun_portal" in url:
                return response(url, text='_( {"error":"ok"} )')
            return connected_probe_response(url, **kwargs)

        session.get.side_effect = handle_request
        client = NetworkClient(
            session=session,
            portal_session=session,
            sleeper=lambda _: None,
            verify_delays=(0,),
        )

        progress = []
        result = client.ensure_connected(AppConfig(username="user", password="password"), progress_callback=progress.append)
        self.assertTrue(progress)
        for call in session.get.call_args_list:
            self.assertIs(call.kwargs["verify"], True)
            self.assertIs(call.kwargs["allow_redirects"], False)

        self.assertTrue(result.connected)
        self.assertIn("自动重连", result.message)

    def test_auto_mode_is_rejected_before_authentication(self):
        session = Mock()
        session.headers = {}
        client = NetworkClient(session=session, portal_session=session)
        config = AppConfig(
            username="user",
            password="password",
            zone=ZONE_AUTO,
        )

        with (
            patch.object(
                client,
                "_login_teaching",
                return_value="教学区认证成功",
            ) as teaching,
            patch.object(client, "_login_dormitory") as dormitory,
        ):
            with self.assertRaises(SecurityError):
                client.send_login(config)

        teaching.assert_not_called()
        dormitory.assert_not_called()

    def test_tls_failure_never_falls_back_to_dormitory(self):
        session = Mock()
        session.headers = {}
        client = NetworkClient(session=session, portal_session=session)
        config = AppConfig(
            username="user",
            password="password",
            zone="office",
        )

        with (
            patch.object(
                client,
                "_login_teaching",
                side_effect=SecurityError("证书校验失败"),
            ) as teaching,
            patch.object(
                client,
                "_login_dormitory",
                return_value="宿舍区认证成功",
            ) as dormitory,
        ):
            with self.assertRaises(SecurityError):
                client.send_login(config)

        teaching.assert_called_once_with(config)
        dormitory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
