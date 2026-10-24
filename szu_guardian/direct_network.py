from __future__ import annotations

import ctypes
import ipaddress
import random
import socket
import struct
import sys
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3 import PoolManager

from .security import SecurityError


FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")
PREFERRED_CAMPUS_NETWORK = ipaddress.ip_network("172.30.0.0/16")
DIRECT_DNS_SERVERS = (
    "192.168.247.6",
    "223.5.5.5",
    "119.29.29.29",
    "114.114.114.114",
)

_WINDOWS_NO_ERROR = 0
_WINDOWS_ERROR_BUFFER_OVERFLOW = 111
_WINDOWS_IF_OPER_STATUS_UP = 1
_WINDOWS_GAA_FLAGS = 0x0002 | 0x0004  # Skip anycast and multicast addresses.


class DirectNetworkError(ConnectionError):
    pass


@dataclass(frozen=True, slots=True)
class AdapterDnsConfig:
    source_ip: str
    dns_servers: tuple[str, ...]
    interface: str = ""


def _valid_source_ipv4(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        parsed.version == 4
        and parsed.is_private
        and not parsed.is_loopback
        and not parsed.is_link_local
        and parsed not in FAKE_IP_NETWORK
    )


def _valid_dns_ipv4(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return (
        parsed.version == 4
        and not parsed.is_unspecified
        and not parsed.is_loopback
        and not parsed.is_link_local
        and not parsed.is_multicast
        and parsed not in FAKE_IP_NETWORK
    )


def _merge_dns_servers(*groups: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(server for group in groups for server in group))


def windows_adapter_dns_configs() -> list[AdapterDnsConfig]:
    """Read active IPv4 addresses and their DNS servers via GetAdaptersAddresses."""
    if sys.platform != "win32":
        return []

    from ctypes import wintypes

    class SocketAddress(ctypes.Structure):
        _fields_ = [
            ("lpSockaddr", ctypes.c_void_p),
            ("iSockaddrLength", ctypes.c_int),
        ]

    class AdapterUnicastAddress(ctypes.Structure):
        pass

    class AdapterDnsServerAddress(ctypes.Structure):
        pass

    AdapterUnicastAddress._fields_ = [
        ("Alignment", ctypes.c_ulonglong),
        ("Next", ctypes.POINTER(AdapterUnicastAddress)),
        ("Address", SocketAddress),
    ]
    AdapterDnsServerAddress._fields_ = [
        ("Alignment", ctypes.c_ulonglong),
        ("Next", ctypes.POINTER(AdapterDnsServerAddress)),
        ("Address", SocketAddress),
    ]

    class AdapterAddresses(ctypes.Structure):
        pass

    AdapterAddresses._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(AdapterAddresses)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(AdapterUnicastAddress)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.POINTER(AdapterDnsServerAddress)),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
    ]

    def ipv4_from_socket_address(value: SocketAddress) -> str | None:
        if not value.lpSockaddr or value.iSockaddrLength < 8:
            return None
        raw = ctypes.string_at(value.lpSockaddr, value.iSockaddrLength)
        family = struct.unpack_from("H", raw)[0]
        if family != socket.AF_INET:
            return None
        return socket.inet_ntoa(raw[4:8])

    get_adapters_addresses = ctypes.windll.iphlpapi.GetAdaptersAddresses
    get_adapters_addresses.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.POINTER(AdapterAddresses),
        ctypes.POINTER(wintypes.ULONG),
    ]
    get_adapters_addresses.restype = wintypes.ULONG

    size = wintypes.ULONG(15_000)
    while True:
        buffer = ctypes.create_string_buffer(size.value)
        addresses = ctypes.cast(buffer, ctypes.POINTER(AdapterAddresses))
        result = get_adapters_addresses(
            socket.AF_INET,
            _WINDOWS_GAA_FLAGS,
            None,
            addresses,
            ctypes.byref(size),
        )
        if result == _WINDOWS_ERROR_BUFFER_OVERFLOW:
            continue
        if result != _WINDOWS_NO_ERROR:
            raise OSError(result, "GetAdaptersAddresses failed")
        break

    configs: list[AdapterDnsConfig] = []
    adapter = addresses
    while adapter:
        current = adapter.contents
        if current.OperStatus == _WINDOWS_IF_OPER_STATUS_UP:
            dns_servers: list[str] = []
            dns_address = current.FirstDnsServerAddress
            while dns_address:
                address = ipv4_from_socket_address(dns_address.contents.Address)
                if address and _valid_dns_ipv4(address):
                    dns_servers.append(address)
                dns_address = dns_address.contents.Next

            unicast_address = current.FirstUnicastAddress
            while unicast_address:
                address = ipv4_from_socket_address(unicast_address.contents.Address)
                if address and _valid_source_ipv4(address):
                    configs.append(
                        AdapterDnsConfig(
                            source_ip=address,
                            dns_servers=tuple(dict.fromkeys(dns_servers)),
                        )
                    )
                unicast_address = unicast_address.contents.Next
        adapter = current.Next

    configs.sort(
        key=lambda config: (
            ipaddress.ip_address(config.source_ip) not in PREFERRED_CAMPUS_NETWORK,
            not bool(config.dns_servers),
        )
    )
    return configs


def _skip_dns_name(packet: bytes, offset: int) -> int:
    while offset < len(packet):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += length + 1
    raise DirectNetworkError("直连 DNS 返回了无效数据")


def query_a_record(
    hostname: str,
    dns_server: str,
    source_ip: str,
    timeout: float = 2.0,
) -> list[str]:
    transaction_id = random.randint(0, 0xFFFF)
    labels = hostname.rstrip(".").split(".")
    question_name = b"".join(
        bytes((len(label.encode("idna")),)) + label.encode("idna")
        for label in labels
    ) + b"\x00"
    packet = (
        struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
        + question_name
        + struct.pack("!HH", 1, 1)
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.bind((source_ip, 0))
        sock.sendto(packet, (dns_server, 53))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(response) < 12:
        raise DirectNetworkError("直连 DNS 响应过短")
    response_id, flags, question_count, answer_count, authority_count, extra_count = (
        struct.unpack("!HHHHHH", response[:12])
    )
    if response_id != transaction_id or flags & 0x000F:
        raise DirectNetworkError("直连 DNS 查询失败")

    offset = 12
    for _ in range(question_count):
        offset = _skip_dns_name(response, offset) + 4

    addresses: list[str] = []
    for _ in range(answer_count + authority_count + extra_count):
        offset = _skip_dns_name(response, offset)
        if offset + 10 > len(response):
            break
        record_type, record_class, _ttl, length = struct.unpack(
            "!HHIH", response[offset : offset + 10]
        )
        offset += 10
        value = response[offset : offset + length]
        offset += length
        if record_type == 1 and record_class == 1 and length == 4:
            address = socket.inet_ntoa(value)
            if ipaddress.ip_address(address) not in FAKE_IP_NETWORK:
                addresses.append(address)
    return list(dict.fromkeys(addresses))


def _command_output(arguments: list[str]) -> str:
    try:
        return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _linux_dns_servers(interface: str) -> tuple[str, ...]:
    output = _command_output(["resolvectl", "dns", interface])
    # resolvectl uses `Link N (iface): DNS ...`; nmcli prints one address per line.
    values = output.partition(":")[2].split()
    servers = tuple(value for value in values if _valid_dns_ipv4(value))
    if servers:
        return servers
    output = _command_output(["nmcli", "-g", "IP4.DNS", "device", "show", interface])
    servers = tuple(value for value in output.split() if _valid_dns_ipv4(value))
    if servers:
        return servers
    for filename in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            lines = Path(filename).read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        values = [line.split()[1] for line in lines if line.startswith("nameserver ") and len(line.split()) >= 2]
        servers = tuple(value for value in values if _valid_dns_ipv4(value))
        if servers:
            return servers
    return ()


def linux_adapter_dns_configs(interface: str = "") -> list[AdapterDnsConfig]:
    output = _command_output(["ip", "-j", "-4", "address", "show", "up"])
    if not output:
        raise DirectNetworkError("无法读取 Linux 网卡，请安装 iproute2 并确认校园网网卡已连接")
    try:
        adapters = json.loads(output)
    except ValueError as exc:
        raise DirectNetworkError("ip 命令返回了无效网卡数据") from exc
    configs = []
    for adapter in adapters:
        name = str(adapter.get("ifname", ""))
        if interface:
            if name != interface:
                continue
        elif not (Path("/sys/class/net") / name / "device").exists():
            # Exclude TUN, loopback, Docker/veth and bridges from auto discovery.
            continue
        addresses = [
            str(item.get("local", "")) for item in adapter.get("addr_info", [])
            if item.get("scope") == "global" and _valid_source_ipv4(str(item.get("local", "")))
        ]
        if addresses:
            servers = _linux_dns_servers(name)
            configs.extend(AdapterDnsConfig(address, servers, name) for address in addresses)
    configs.sort(key=lambda config: (
        ipaddress.ip_address(config.source_ip) not in PREFERRED_CAMPUS_NETWORK,
        not bool(config.dns_servers),
    ))
    if interface and not configs:
        raise DirectNetworkError(f"网卡 {interface} 没有可用的校园网 IPv4 地址")
    return configs


def adapter_dns_configs(interface: str = "") -> list[AdapterDnsConfig]:
    if sys.platform.startswith("linux"):
        return linux_adapter_dns_configs(interface)
    if interface:
        raise DirectNetworkError("手动指定网卡名称仅支持 Linux")
    return windows_adapter_dns_configs()


def local_ipv4_candidates() -> list[str]:
    try:
        adapter_addresses = [
            config.source_ip for config in adapter_dns_configs()
        ]
    except OSError:
        adapter_addresses = []
    if adapter_addresses:
        return list(dict.fromkeys(adapter_addresses))

    try:
        addresses = socket.gethostbyname_ex(socket.gethostname())[2]
    except socket.gaierror as exc:
        raise DirectNetworkError("无法读取本机网卡地址") from exc

    valid: list[str] = []
    for address in addresses:
        if _valid_source_ipv4(address):
            valid.append(address)
    valid.sort(
        key=lambda value: ipaddress.ip_address(value) not in PREFERRED_CAMPUS_NETWORK
    )
    return valid


class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_ip: str, *args, **kwargs):
        self.source_ip = source_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs,
    ) -> None:
        pool_kwargs["source_address"] = (self.source_ip, 0)
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


class DirectAddressAdapter(SourceAddressAdapter):
    """Connect to direct DNS IPv4 addresses while retaining URL hostname for TLS."""

    def __init__(self, route: "DirectRoute"):
        self.route = route
        super().__init__(route.source_ip)

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        parsed = urlsplit(request.url)
        if not parsed.hostname or parsed.username or parsed.password:
            raise SecurityError("请求地址不合法")
        if proxies:
            raise SecurityError("校园网直连请求不允许使用代理")
        if parsed.scheme == "https" and verify is not True:
            raise SecurityError("HTTPS 请求必须启用默认可信 CA 与证书校验")
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        try:
            ipaddress.ip_address(parsed.hostname)
            address = parsed.hostname
        except ValueError:
            address = self.route.resolve(parsed.hostname)[0]
        host_params["host"] = address
        if parsed.scheme == "https":
            pool_kwargs["server_hostname"] = parsed.hostname
            pool_kwargs["assert_hostname"] = parsed.hostname
        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)

    def add_headers(self, request, **kwargs):
        # The pool connects to an IP; the HTTP Host must remain the original domain.
        parsed = urlsplit(request.url)
        request.headers["Host"] = parsed.netloc


def create_bound_session(source_ip: str) -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", SourceAddressAdapter(source_ip))
    session.mount("https://", SourceAddressAdapter(source_ip))
    return session


@dataclass(slots=True)
class DirectRoute:
    source_ip: str
    dns_servers: tuple[str, ...] = DIRECT_DNS_SERVERS
    _cache: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def discover(cls, interface: str = "") -> "DirectRoute":
        try:
            adapter_configs = adapter_dns_configs(interface)
        except OSError:
            if sys.platform.startswith("linux"):
                raise
            adapter_configs = []

        if adapter_configs:
            routes = [
                cls(
                    config.source_ip,
                    _merge_dns_servers(config.dns_servers, DIRECT_DNS_SERVERS),
                )
                for config in adapter_configs
            ]
        else:
            routes = [] if sys.platform.startswith("linux") else [cls(source_ip) for source_ip in local_ipv4_candidates()]

        if not routes:
            raise DirectNetworkError(
                "未找到校园网物理网卡；请确认已连接校园有线网络或 SZU_WLAN"
            )

        for route in routes:
            try:
                route.resolve("net.szu.edu.cn")
                return route
            except DirectNetworkError:
                continue
        raise DirectNetworkError(
            "无法通过物理网卡进行直连 DNS 查询；请检查校园网连接"
        )

    def resolve(self, hostname: str) -> list[str]:
        if hostname in self._cache:
            return self._cache[hostname]
        errors: list[str] = []
        for server in self.dns_servers:
            try:
                addresses = query_a_record(hostname, server, self.source_ip)
                if addresses:
                    self._cache[hostname] = addresses
                    return addresses
            except (OSError, DirectNetworkError) as exc:
                errors.append(type(exc).__name__)
        detail = "/".join(errors) or "无 A 记录"
        raise DirectNetworkError(f"无法直连解析 {hostname}（{detail}）")

    def session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        session.mount("http://", DirectAddressAdapter(self))
        session.mount("https://", DirectAddressAdapter(self))
        return session
