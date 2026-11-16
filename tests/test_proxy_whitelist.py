"""黑洞代理白名单的两处接线：多服务题主机、Caido 的 NO_PROXY 覆盖。

两处都是「该响的时候响 / 不该响的时候不响」成对钉死——只测一边的话，
把白名单改成无条件放行也能过。
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402


@pytest.fixture()
def local_backend(monkeypatch):
    """带假 unix_local 的 ctf_strix.local_backend（Windows 上真模块 import 即 raise）。"""
    fake = types.ModuleType("agents.sandbox.sandboxes.unix_local")
    fake.UnixLocalSandboxClient = type("FakeClient", (), {})
    fake.UnixLocalSandboxClientOptions = type("FakeOptions", (), {})
    fake.UnixLocalSandboxSession = type("FakeSession", (), {})
    monkeypatch.setitem(sys.modules, "agents.sandbox.sandboxes.unix_local", fake)
    monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)
    module = importlib.import_module("ctf_strix.local_backend")
    yield module
    monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)


def _clear_proxy_env(monkeypatch) -> None:
    for key in ("CTF_NO_PROXY_EXTRA", "CTF_EGRESS_PROXY", "LLM_API_BASE"):
        monkeypatch.delenv(key, raising=False)


def test_blackhole_includes_every_service_host(monkeypatch) -> None:
    """多服务题：第二个主机不在白名单里就会被自家黑洞代理吞掉。"""
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("LLM_API_BASE", "https://llm.example.com/v1")
    env = batch_eval._proxy_blackhole(
        "https://main.example.run/",
        extra_hosts=["index.example.run", "", "   "],
    )
    hosts = env["NO_PROXY"].split(",")
    assert "main.example.run" in hosts
    assert "index.example.run" in hosts
    assert "llm.example.com" in hosts
    assert "" not in hosts  # 空串会把整条白名单语义弄坏
    assert env["NO_PROXY"] == env["no_proxy"]


def test_blackhole_single_host_shape_unchanged(monkeypatch) -> None:
    """反例：单服务题不该因为新参数变形。"""
    _clear_proxy_env(monkeypatch)
    env = batch_eval._proxy_blackhole("http://10.0.0.5:8080")
    assert env["NO_PROXY"] == "localhost,127.0.0.1,::1,10.0.0.5"
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:9"


class _Environment:
    def __init__(self, value: dict[str, str]) -> None:
        self.value = value


class _Manifest:
    def __init__(self, value: dict[str, str]) -> None:
        self.environment = _Environment(value)


def test_strip_dead_proxy_keeps_runner_whitelist(monkeypatch, local_backend) -> None:
    """Caido 的 NO_PROXY 只放行回环，覆盖上去等于删掉调用方的靶机白名单。"""
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1,::1,target.example.run")
    monkeypatch.setenv("no_proxy", "localhost,127.0.0.1,::1,target.example.run")
    manifest = _Manifest(
        {
            "http_proxy": "http://127.0.0.1:8099",
            "https_proxy": "http://127.0.0.1:8099",
            "ALL_PROXY": "http://127.0.0.1:8099",
            "NO_PROXY": "localhost,127.0.0.1",
        }
    )
    removed = local_backend._strip_dead_proxy(manifest)
    env = manifest.environment.value
    assert set(removed) == {"http_proxy", "https_proxy", "ALL_PROXY"}
    assert not (set(local_backend._CAIDO_PROXY_KEYS) & set(env))
    hosts = env["NO_PROXY"].split(",")
    assert "target.example.run" in hosts  # 调用方的拿回来
    assert hosts.count("localhost") == 1  # 去重，不是拼接两遍
    assert env["NO_PROXY"] == env["no_proxy"]


def test_strip_dead_proxy_without_runner_whitelist_keeps_caido(monkeypatch, local_backend) -> None:
    """反例：没有调用方白名单时，Caido 那条原样保留，不制造空值。"""
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    manifest = _Manifest({"NO_PROXY": "localhost,127.0.0.1"})
    local_backend._strip_dead_proxy(manifest)
    assert manifest.environment.value["NO_PROXY"] == "localhost,127.0.0.1"