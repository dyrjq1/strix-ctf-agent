"""LLM_MAX_TOKENS 注入：网关端点要求请求显式携带 max_tokens（2026-11-14）。

回归背景：CTFARENA-108 网关冒烟 18+ 次 400 ``Range of max_tokens should be
[1, 8192]``、零工具输出。该端点把「缺参」报成「范围错误」；agent 主循环
的 ModelSettings.max_tokens 为 None，OpenAI SDK 会剔除 None 字段，于是
每次调用都缺参。预检（max_tokens=1）与人工 curl（习惯带 max_tokens:5）
都探测不到。

这些测试钉住注入的三条边界：注入发生、不覆盖显式值、不设置时纯转发。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from agents.model_settings import ModelSettings

from ctf_strix import llm_compat


class _FakeInner:
    """记录调用参数的内层 Model 替身。"""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple, dict]] = []

    async def close(self) -> None:
        return None

    async def _cleanup_on_run_end(self, owner: object) -> None:
        return None

    def get_retry_advice(self, request):  # noqa: ANN001, ANN202
        return None

    async def get_response(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return "response"

    def stream_response(self, *args, **kwargs):
        """与真实 Model 一致：同步返回异步迭代器，不是协程。"""
        self.calls.append((args, kwargs))

        async def _gen():
            yield "event"

        return _gen()


def _call_args(settings):
    """(system_instructions, input, model_settings, tools...) 的位置形态。"""
    return ("system", "input", settings, [], None, [])


@pytest.mark.asyncio
async def test_injects_env_value_into_positional_settings(monkeypatch):
    monkeypatch.setenv("LLM_MAX_TOKENS", "8192")
    inner = _FakeInner()
    proxy = llm_compat._MaxTokensProxy(inner)

    await proxy.get_response(*_call_args(ModelSettings()))

    settings = inner.calls[0][0][2]
    assert settings.max_tokens == 8192


@pytest.mark.asyncio
async def test_injects_env_value_into_keyword_settings(monkeypatch):
    monkeypatch.setenv("LLM_MAX_TOKENS", "4096")
    inner = _FakeInner()
    proxy = llm_compat._MaxTokensProxy(inner)

    await proxy.get_response("system", "input", model_settings=ModelSettings(), tools=[])

    settings = inner.calls[0][1]["model_settings"]
    assert settings.max_tokens == 4096


@pytest.mark.asyncio
async def test_explicit_max_tokens_is_never_overridden(monkeypatch):
    """compaction 摘要显式带的 max_tokens 不许被环境值盖掉。"""
    monkeypatch.setenv("LLM_MAX_TOKENS", "8192")
    inner = _FakeInner()
    proxy = llm_compat._MaxTokensProxy(inner)
    explicit = ModelSettings(max_tokens=4096)

    await proxy.get_response(*_call_args(explicit))

    settings = inner.calls[0][0][2]
    assert settings.max_tokens == 4096
    assert settings is explicit


@pytest.mark.asyncio
async def test_env_unset_is_a_pure_passthrough(monkeypatch):
    monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
    inner = _FakeInner()
    proxy = llm_compat._MaxTokensProxy(inner)
    settings = ModelSettings()

    await proxy.get_response(*_call_args(settings))

    assert inner.calls[0][0][2] is settings
    assert settings.max_tokens is None


@pytest.mark.asyncio
async def test_stream_response_path_is_covered_too(monkeypatch):
    monkeypatch.setenv("LLM_MAX_TOKENS", "2048")
    inner = _FakeInner()
    proxy = llm_compat._MaxTokensProxy(inner)

    stream = proxy.stream_response(*_call_args(ModelSettings()))
    async for _ in stream:
        pass

    settings = inner.calls[0][0][2]
    assert settings.max_tokens == 2048


@pytest.mark.parametrize("raw", ["", "  ", "0", "-5", "abc"])
def test_bad_env_values_are_ignored(monkeypatch, raw):
    monkeypatch.setenv("LLM_MAX_TOKENS", raw)
    assert llm_compat.max_tokens_from_env() is None


def test_install_wraps_the_provider_model(monkeypatch):
    from strix.config.models import StrixProvider

    monkeypatch.setenv("LLM_MAX_TOKENS", "8192")
    sentinel = object()

    def fake_get_model(self, model_name):  # noqa: ANN001, ANN202
        return sentinel

    original = StrixProvider.get_model
    was_patched = getattr(StrixProvider, "_ctf_max_tokens_patched", False)
    try:
        StrixProvider.get_model = fake_get_model  # type: ignore[method-assign]
        # 全量套件里别的用例可能已经装过代理（flag 为真时 install 直接返回，
        # 根本不会包住下面这个假 provider）。测试必须自己清到干净状态。
        if hasattr(StrixProvider, "_ctf_max_tokens_patched"):
            del StrixProvider._ctf_max_tokens_patched
        assert llm_compat.install() is True
        wrapped = StrixProvider.get_model(None, "openai/x")
        assert isinstance(wrapped, llm_compat._MaxTokensProxy)
        assert wrapped._inner is sentinel
        # 幂等：再装一次不叠加。
        assert llm_compat.install() is True
        assert StrixProvider.get_model(None, "openai/x")._inner is sentinel
    finally:
        StrixProvider.get_model = original
        if was_patched:
            StrixProvider._ctf_max_tokens_patched = True
        elif hasattr(StrixProvider, "_ctf_max_tokens_patched"):
            del StrixProvider._ctf_max_tokens_patched


# ------------------------------------------------------------- 入口一致性
# 2026-11-14 冒烟第 4 次仍 400 的根因：注入只加进了官方入口
# src/ctf_strix/agent.py，而评测链路走 scripts/run_strix_ctf.py，
# 后者有一份自己的 [ctx] 安装块——两边分裂，评测永远测不到修复。
# 钉住两个入口都必须装代理，并且 [ctx] 行都带 max_tokens 后缀。
_ROOT = Path(__file__).resolve().parent.parent
_ENTRYPOINTS = (_ROOT / "src" / "ctf_strix" / "agent.py", _ROOT / "scripts" / "run_strix_ctf.py")


@pytest.mark.parametrize("path", _ENTRYPOINTS, ids=lambda p: p.name)
def test_every_entrypoint_installs_the_proxy(path):
    source = path.read_text(encoding="utf-8")
    assert "llm_compat.install()" in source
    assert "max_tokens={explicit}" in source
