"""沙箱 exec 环境凭据剥离（local_backend._patch_exec_env_credentials）。

runner 的 LLM key 等凭据经 ``os.environ.copy()`` 进每次沙箱 exec 的环境；
包装 ``UnixLocalSandboxClient._resolved_exec_context`` 后必须从返回的 env
里消失，且不能误伤合法系统变量、不能动 runner 自己的 ``os.environ``。

unix_local 在 Windows 上 import 即 raise，因此测试注入一个行为等价的假
模块（``os.environ`` 打底 + 返回固定 cwd），只验证包装层逻辑。
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import types

import pytest


@pytest.fixture()
def local_backend(monkeypatch):
    """加载带假 unix_local 的 ctf_strix.local_backend，返回 (模块, 假类)。"""

    class FakeClient:
        async def _resolved_exec_context(self):
            import os

            env = dict(os.environ)
            env.setdefault("SANDBOX_MARKER", "1")
            return env, "/workspace"

    fake = types.ModuleType("agents.sandbox.sandboxes.unix_local")
    fake.UnixLocalSandboxClient = FakeClient  # type: ignore[attr-defined]
    fake.UnixLocalSandboxClientOptions = type(  # type: ignore[attr-defined]
        "FakeOptions", (), {}
    )
    monkeypatch.setitem(sys.modules, "agents.sandbox.sandboxes.unix_local", fake)
    monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)
    module = importlib.import_module("ctf_strix.local_backend")
    try:
        yield module, FakeClient
    finally:
        monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)


def _setenv(monkeypatch):
    """正例（凭据，应删）+ 反例（合法/无害变量，应保留）。"""
    # 正例：各种命名风格的凭据。
    monkeypatch.setenv("LLM_API_KEY", "sk-should-vanish")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-provider-key")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-style")
    monkeypatch.setenv("PF_TOKEN", "pf-platform-token")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp-token")
    monkeypatch.setenv("VAULT_SECRET", "s3cr3t")
    monkeypatch.setenv("STRIX_SESSION_TOKEN", "strix-token")
    # 反例：合法系统变量 / 非凭据配置。
    monkeypatch.setenv("PATH", r"C:\fake-bin")
    monkeypatch.setenv("LLM_API_BASE", "https://llm.example/v1")
    monkeypatch.setenv("STRIX_LLM", "openai/some-model")
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "True")
    monkeypatch.setenv("PYTHONUNBUFFERED", "1")
    monkeypatch.setenv("KEYCLOAK_HOST", "host.example")


def test_credentials_removed_from_exec_env(local_backend, monkeypatch):
    module, client_cls = local_backend
    _setenv(monkeypatch)
    module._patch_exec_env_credentials()

    env, cwd = asyncio.run(client_cls()._resolved_exec_context())

    for key in (
        "LLM_API_KEY",
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
        "PF_TOKEN",
        "GITHUB_TOKEN",
        "VAULT_SECRET",
        "STRIX_SESSION_TOKEN",
    ):
        assert key not in env, key
    # 反例：合法变量保留，包装不改变 cwd 语义。
    assert env["PATH"] == r"C:\fake-bin"
    assert env["LLM_API_BASE"] == "https://llm.example/v1"
    assert env["STRIX_LLM"] == "openai/some-model"
    assert env["LITELLM_LOCAL_MODEL_COST_MAP"] == "True"
    assert env["SANDBOX_MARKER"] == "1"
    assert cwd == "/workspace"


def test_runner_environ_untouched(local_backend, monkeypatch):
    """删的是返回 dict 的键，runner 进程自己的 os.environ 不能被清。"""
    module, client_cls = local_backend
    _setenv(monkeypatch)
    module._patch_exec_env_credentials()

    asyncio.run(client_cls()._resolved_exec_context())

    import os

    assert os.environ["LLM_API_KEY"] == "sk-should-vanish"
    assert os.environ["PF_TOKEN"] == "pf-platform-token"


def test_patch_idempotent(local_backend):
    module, client_cls = local_backend
    module._patch_exec_env_credentials()
    original = client_cls._resolved_exec_context.__wrapped__
    module._patch_exec_env_credentials()
    # 第二次调用不得再包一层：unwrap 一次仍是原方法。
    assert client_cls._resolved_exec_context.__wrapped__ is original


def test_regex_classification(local_backend):
    """正则分类本身的正反例，防止将来改模式时误伤面扩大。"""
    should_match = (
        "LLM_API_KEY",
        "STRIX_LLM_API_KEY",
        "OPENAI_API_KEY",
        "ZHIPUAI_API_KEY",
        "MY_CUSTOM_API_KEY",
        "PF_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "SESSION_SECRET",
        "SOME_SERVICE_KEY",
    )
    should_not_match = (
        "PATH",
        "HOME",
        "PYTHONPATH",
        "KEYCLOAK_HOST",
        "LLM_API_BASE",
        "STRIX_LLM",
        "LITELLM_LOCAL_MODEL_COST_MAP",
        "PYTHONUNBUFFERED",
        "HTTP_PROXY",
    )
    for name in should_match:
        assert local_backend[0]._CREDENTIAL_ENV_RE.match(name), name
    for name in should_not_match:
        assert not local_backend[0]._CREDENTIAL_ENV_RE.match(name), name
