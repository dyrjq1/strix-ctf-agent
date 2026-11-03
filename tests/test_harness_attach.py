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