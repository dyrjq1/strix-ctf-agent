"""平台 → strix 的环境变量桥接。

这条桥接的失效方式特别隐蔽：key 是对的，端点不对，回来的 401 看起来像
"凭据被吊销"。所以每条分支都要钉住。
"""

from __future__ import annotations

import os

import pytest

from ctf_strix import platform_env


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """每个用例从空环境开始，避免宿主机变量污染断言。"""
    for key in (
        "LLM_MODEL",
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_FLAVOR",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "STRIX_LLM",
        "LLM_API_BASE",
    ):
        monkeypatch.delenv(key, raising=False)


def test_platform_vars_reach_strix(monkeypatch: pytest.MonkeyPatch) -> None:
    """平台的三件套必须原样落到 strix 读的名字上。"""
    monkeypatch.setenv("LLM_MODEL", "glm-5.2")
    monkeypatch.setenv("LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-test")
    monkeypatch.setenv("LLM_FLAVOR", "openai")

    applied = platform_env.normalise()

    assert applied == {"STRIX_LLM": "glm-5.2", "LLM_API_BASE": "platform"}
    assert os.environ["STRIX_LLM"] == "openai/glm-5.2"
    assert os.environ["LLM_API_BASE"] == "https://llm.example/v1"
    assert os.environ["LLM_API_KEY"] == "sk-test"


def test_existing_values_win(monkeypatch: pytest.MonkeyPatch) -> None:
    """本地调试已经设好的 STRIX_LLM / LLM_API_BASE 不能被平台变量覆盖。"""
    monkeypatch.setenv("STRIX_LLM", "openai/DeepSeek-V4.1-Flash")
    monkeypatch.setenv("LLM_API_BASE", "https://local/v1")
    monkeypatch.setenv("LLM_MODEL", "glm-5.2")
    monkeypatch.setenv("LLM_BASE_URL", "https://platform/v1")

    applied = platform_env.normalise()

    assert applied == {}
    assert os.environ["STRIX_LLM"] == "openai/DeepSeek-V4.1-Flash"
    assert os.environ["LLM_API_BASE"] == "https://local/v1"


def test_prefixed_model_not_doubled(monkeypatch: pytest.MonkeyPatch) -> None:
    """平台已经给了 provider 前缀时不能再加一层。"""
    monkeypatch.setenv("LLM_MODEL", "anthropic/claude-sonnet-4")
    monkeypatch.setenv("LLM_FLAVOR", "anthropic")

    platform_env.normalise()

    assert os.environ["STRIX_LLM"] == "anthropic/claude-sonnet-4"


def test_anthropic_bearer_preferred(monkeypatch: pytest.MonkeyPatch) -> None:
    """anthropic flavor 下 AUTH_TOKEN 是 bearer，兼容端点只认它，所以排在 API_KEY 前。"""
    monkeypatch.setenv("LLM_FLAVOR", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x-api-key-value")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "bearer-value")

    platform_env.normalise()

    assert os.environ["LLM_API_KEY"] == "bearer-value"


def test_empty_string_counts_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """§1.1：未注资的 run 里变量是**缺席**而不是空串，空串按未设置处理。"""
    monkeypatch.setenv("LLM_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "real-key")

    platform_env.normalise()

    assert os.environ["LLM_API_KEY"] == "real-key"
