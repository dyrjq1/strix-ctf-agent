"""Harness attach wiring: private services, tunnel kinds, guard summary.

All tests are offline: the platform client and the bridge/tunnel are fakes.
The bugs these lock down all happened before any packet reached a target, so
no test needs a live instance to reproduce them.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

import batch_eval  # noqa: E402
import run_strix_ctf  # noqa: E402
from ctf_strix.enum_guard import EnumerationGuard  # noqa: E402

PRIVATE_SVC = {
    "service_type": "http",
    "host": "app.internal",
    "port": 80,
    "access": None,
}


class _Resp:
    def __init__(self, status_code: int, text: str = "", data: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self._data = data or {}

    def json(self) -> dict:
        return self._data


class _StatusSession:
    """Answer ``/status`` and ``/vpn-config``; record every path requested."""

    def __init__(self, services: list[dict], profile: str) -> None:
        self.services = services
        self.profile = profile
        self.paths: list[str] = []

    def get(self, url: str, timeout: float = 0) -> _Resp:  # noqa: ARG002
        self.paths.append(url)
        if url.endswith("/status"):
            return _Resp(200, data={"status": "ready", "attack_surface": {"services": self.services}})
        if url.endswith("/vpn-config"):
            return _Resp(200, text=self.profile)
        raise AssertionError(f"unexpected request: {url}")


def _client(session: _StatusSession) -> batch_eval.Client:
    client = batch_eval.Client("test-token")
    client.s = session  # type: ignore[assignment]
    return client


def test_private_service_with_a_non_empty_profile_is_attach_ready() -> None:
    """052: access=null but the instance profile is 277B, so the tunnel works."""
    session = _StatusSession([PRIVATE_SVC], profile="[Interface]\nPrivateKey = x\n")
    client = _client(session)

    assert client.wait_ready("iid-1") is PRIVATE_SVC
    assert any(path.endswith("/vpn-config") for path in session.paths)


def test_private_service_with_an_empty_profile_still_skips() -> None:
    """A missing profile is still a hard tunnel requirement, not a free pass."""
    session = _StatusSession([PRIVATE_SVC], profile="")
    client = _client(session)

    with pytest.raises(batch_eval.TunnelRequiredError):
        client.wait_ready("iid-2")


def test_declared_vpn_access_keeps_the_original_path() -> None:
    """access=vpn must not pay for a second request; the old route is enough."""
    svc = {**PRIVATE_SVC, "access": "vpn"}
    session = _StatusSession([svc], profile="should-not-be-read")
    client = _client(session)

    assert client.wait_ready("iid-3") is svc
    assert not any(path.endswith("/vpn-config") for path in session.paths)


class _FakeBridge:
    def __init__(self, host: str, port: int, access: str | None = None) -> None:
        self.host = host
        self.port = port
        self.access = access
        self.listen_port = 40473

    def start(self) -> "_FakeBridge":
        return self

    @property
    def local_url(self) -> str:
        return f"127.0.0.1:{self.listen_port}"


class _FakeTunnel:
    iface = "wg-test"

    def __init__(self, profile: str, iface: str) -> None:
        self.profile = profile
        self.iface = iface
        self.up_ok = False

    @classmethod
    def from_profile(cls, text: str, iface: str) -> "_FakeTunnel":
        return cls(text, iface)

    def up(self) -> bool:
        self.up_ok = True
        return True

    def resolve(self, host: str) -> str:
        return "172.16.6.2"

    def down(self) -> None:
        self.up_ok = False


@pytest.fixture()
def fake_network(monkeypatch):
    """Replace the real tunnel/bridge so ``_attach`` never touches the network."""
    from ctf_strix import tcp_bridge, vpn

    monkeypatch.setattr(vpn, "VpnTunnel", _FakeTunnel)
    monkeypatch.setattr(tcp_bridge, "TcpBridge", _FakeBridge)

    class _Client:
        def vpn_config(self, iid: str) -> str:  # noqa: ARG002
            return "[Interface]\nPrivateKey = x\n"

    return _Client()


def test_http_service_over_the_tunnel_is_attached_as_web(fake_network) -> None:
    """The bridge removes the tunnel tax, not the HTTP surface."""
    bridge, tunnel, target, kind, real_host, access = batch_eval._attach(
        "iid-4", dict(PRIVATE_SVC), fake_network
    )

    assert kind == "web"
    assert target == "http://127.0.0.1:40473/"
    assert real_host == "172.16.6.2"
    assert tunnel is not None and tunnel.up_ok
    assert bridge.local_url == "127.0.0.1:40473"


def test_non_http_service_keeps_the_tcp_kind(fake_network) -> None:
    """A raw TCP service must not be handed the web tool surface."""
    svc = {"service_type": "tcp", "host": "app.internal", "port": 1337, "access": "vpn"}
    _, _, target, kind, _, _ = batch_eval._attach("iid-5", svc, fake_network)

    assert kind == "tcp"
    assert kind not in ("web", "checker", "engagement")
    assert target == "127.0.0.1:40473"


def test_guard_summary_reports_mechanism_counts_and_stays_parseable() -> None:
    """Mechanism classes are observational, but must not break existing parsers."""
    guard = EnumerationGuard()
    guard.mechanisms.update({"injection": 4, "information-collection": 2})
    journey = SimpleNamespace(wall_hit=1, authed=True, created=False, payloads=2, prompts=3)
    finisher = SimpleNamespace(refusals=1, allowed=1)

    line = run_strix_ctf._guard_summary(guard, journey, finisher, reached=11)

    assert "| mechanisms: " in line
    assert "injection=4" in line
    assert "information-collection=2" in line
    assert line.index("mechanisms:") > line.index("finish:")
    parsed = batch_eval._parse_guard(line)
    assert parsed["reach"] == 11
    assert parsed["finish_refused"] == 1
    assert parsed["journey_prompts"] == 3


def test_mechanism_counts_is_a_snapshot() -> None:
    """Logging must not be able to mutate the guard's live counter."""
    guard = EnumerationGuard()
    guard.mechanisms["injection"] = 2

    snapshot = guard.mechanism_counts()
    snapshot["injection"] = 99

    assert guard.mechanisms["injection"] == 2
    assert isinstance(guard.mechanisms, type(guard.mechanisms))


class _FakeRelay:
    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.listen_port = 40474
        self.started = False

    def start(self) -> "_FakeRelay":
        self.started = True
        return self

    @property
    def local_url(self) -> str:
        return f"127.0.0.1:{self.listen_port}"

    def stop(self) -> None:
        self.started = False


def test_udp_service_is_relayed_not_tcp_bridged(fake_network, monkeypatch) -> None:
    """SAMPLE-015：UDP 服务套 TCP 桥，agent 的每个数据报都超时。

    这里锁的是接线：service_type=udp 必须选 UdpRelay、kind 记 udp。
    """
    from ctf_strix import tcp_bridge

    monkeypatch.setattr(tcp_bridge, "UdpRelay", _FakeRelay)
    svc = {
        "service_type": "udp",
        "host": "chal.internal",
        "port": 9999,
        "access": "vpn",
    }

    relay, tunnel, target, kind, real_host, _ = batch_eval._attach(
        "iid-6", svc, fake_network
    )

    assert kind == "udp"
    assert target == "127.0.0.1:40474"
    assert isinstance(relay, _FakeRelay) and relay.started
    assert relay.port == 9999
    assert real_host == "172.16.6.2"   # 隧道内解析后的地址
    assert tunnel is not None


def test_udp_relay_carries_datagrams_and_keeps_upstream_source_port() -> None:
    """真回环：中继把数据报双向搬运，且同一客户端共用一条上游 socket。"""
    import socket
    import threading
    import time

    from ctf_strix.tcp_bridge import UdpRelay

    seen: list[tuple[bytes, tuple[str, int]]] = []

    def echo() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
            srv.bind(("127.0.0.1", 0))
            srv.settimeout(5)
            port_holder.append(srv.getsockname()[1])
            try:
                for _ in range(2):
                    data, addr = srv.recvfrom(2048)
                    seen.append((data, addr))
                    srv.sendto(b"echo:" + data, addr)
            except socket.timeout:
                pass

    port_holder: list[int] = []
    t = threading.Thread(target=echo, daemon=True)
    t.start()
    deadline = time.time() + 3
    while not port_holder and time.time() < deadline:
        time.sleep(0.01)
    assert port_holder, "echo server did not bind"

    relay = UdpRelay("127.0.0.1", port_holder[0]).start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as cli:
            cli.settimeout(3)
            for payload in (b"hello", b"flag tok"):
                cli.sendto(payload, ("127.0.0.1", relay.listen_port))
                data, _ = cli.recvfrom(2048)
                assert data == b"echo:" + payload
    finally:
        relay.stop()
        t.join(timeout=2)

    assert [p for p, _ in seen] == [b"hello", b"flag tok"]
    # 同一客户端源地址必须复用上游 socket，源端口才固定（题目"同一源端口"要求）
    assert seen[0][1] == seen[1][1]


class _EstateSession:
    """status 永远 ready 但 services 空；详情端点给 entry_urls。"""

    def __init__(self, detail: dict) -> None:
        self.detail = detail
        self.paths: list[str] = []

    def get(self, url: str, timeout: float = 0) -> _Resp:  # noqa: ARG002
        self.paths.append(url)
        if url.endswith("/status"):
            return _Resp(200, data={"status": "ready", "attack_surface": {"services": []}})
        if url.endswith("/vpn-config"):
            return _Resp(200, text="[Interface]\nPrivateKey = x\n")
        if "/instances/" in url:
            return _Resp(200, data=self.detail)
        raise AssertionError(f"unexpected request: {url}")


def test_entry_urls_become_private_vpn_services() -> None:
    """SAMPLE-023：入口名在 entry_urls，必须派生成 service 形状。"""
    derived = batch_eval._services_from_entry_urls(
        {"entry_urls": ["http://portal.sample023.internal",
                        "https://files.sample023.internal/x"]}
    )

    assert [s["host"] for s in derived] == [
        "portal.sample023.internal",
        "files.sample023.internal",
    ]
    assert all(s["access"] == "vpn" for s in derived)
    assert derived[1]["port"] == 443
    assert derived[1]["path"] == "/x"


def test_entry_urls_ignores_junk() -> None:
    assert batch_eval._services_from_entry_urls({"entry_urls": ["", "not a url", None]}) == []


def test_wait_ready_falls_back_to_entry_urls() -> None:
    """ready + services 空 + entry_urls 非空 → 返回派生条目，不是判死。"""
    session = _EstateSession(
        {
            "services": [],
            "entry_urls": ["http://portal.sample023.internal"],
        }
    )
    client = _client(session)

    svc = client.wait_ready("iid-7", timeout=10)

    assert svc["host"] == "portal.sample023.internal"
    assert svc["access"] == "vpn"
    assert any("/instances/" in p for p in session.paths)


def test_wait_ready_keeps_polling_when_estate_not_connected() -> None:
    """ready 但地址全空：继续轮询到超时，而不是第一瞬间抛 TunnelRequiredError。"""
    session = _EstateSession({"services": [], "entry_urls": []})
    client = _client(session)

    with pytest.raises(TimeoutError):
        client.wait_ready("iid-8", timeout=1)


def test_single_endpoint_needs_no_extra_section() -> None:
    svc = {"host": "10.0.0.5", "port": 80, "service_type": "http", "label": "web"}
    assert batch_eval._endpoints_brief([svc]) == ""
    assert batch_eval._endpoints_brief([]) == ""


def test_every_endpoint_reaches_the_brief() -> None:
    """SAMPLE-022：auth + vault 两个地址都必须出现在题面里。"""
    endpoints = [
        {"host": "172.16.19.2", "port": 80, "service_type": "http", "label": "auth"},
        {"host": "172.16.19.3", "port": 8080, "service_type": "http", "label": "vault",
         "path": "/flag"},
    ]

    text = batch_eval._endpoints_brief(endpoints)

    assert "172.16.19.2:80" in text
    assert "172.16.19.3:8080/flag" in text
    assert text.count("- ") == 2


def test_private_endpoint_is_resolved_for_the_agent() -> None:
    """sandbox 不一定能解析 .internal；简报里要给解析后的 IP。"""
    endpoints = [
        {"host": "portal.sample023.internal", "port": 80, "service_type": "http",
         "label": "portal"},
        {"host": "files.sample023.internal", "port": 80, "service_type": "http",
         "label": "files"},
    ]

    text = batch_eval._endpoints_brief(endpoints, resolve=lambda host: "172.16.8.2")

    assert "172.16.8.2（portal.sample023.internal）:80" in text
    assert "files.sample023.internal" in text


class _RacingTunnel(_FakeTunnel):
    """前 ``misses`` 次解析返回原 host（= 没解析出来），之后给真地址。"""

    misses = 2
    real_ip = "172.16.9.9"

    def __init__(self, profile: str, iface: str) -> None:
        super().__init__(profile, iface)
        self.calls: list[str] = []

    def resolve(self, host: str) -> str:
        self.calls.append(host)
        if len(self.calls) <= self.misses:
            return host
        return self.real_ip


def test_tunnel_dns_race_is_retried_before_skipping(fake_network, monkeypatch) -> None:
    """SAMPLE-001：实例刚 ready 时 estate DNS 还没下发，一次解析失败就整题跳过。

    第一次解析拿回原 host 不等于「这题需要隧道」——同批实例几秒后就能解析。
    """
    from ctf_strix import vpn

    monkeypatch.setattr(vpn, "VpnTunnel", _RacingTunnel)
    slept: list[float] = []
    monkeypatch.setattr(batch_eval.time, "sleep", lambda s: slept.append(s))

    _, tunnel, _, kind, real_host, _ = batch_eval._attach(
        "iid-9", dict(PRIVATE_SVC), fake_network
    )

    assert kind == "web"
    assert real_host == "172.16.9.9"
    assert slept == [5, 5]
    assert len(tunnel.calls) == 3   # 1 次初判 + 2 次重试


def test_tunnel_dns_persistent_failure_still_skips(fake_network, monkeypatch) -> None:
    """重试是窗口不是免死金牌：真解析不出来，仍按「需隧道」跳过。"""
    from ctf_strix import vpn

    class _DeadTunnel(_RacingTunnel):
        misses = 99

    monkeypatch.setattr(vpn, "VpnTunnel", _DeadTunnel)
    slept: list[float] = []
    monkeypatch.setattr(batch_eval.time, "sleep", lambda s: slept.append(s))

    with pytest.raises(batch_eval.TunnelRequiredError):
        batch_eval._attach("iid-10", dict(PRIVATE_SVC), fake_network)

    assert slept == [5] * 6
