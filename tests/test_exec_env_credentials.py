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
import inspect
import sys
import types

import pytest


@pytest.fixture()
def local_backend(monkeypatch):
    """加载带假 unix_local 的 ctf_strix.local_backend，返回 (模块, 假 Session 类)。

    假模块镜像真实 SDK 结构：``_resolved_exec_context`` 在
    ``UnixLocalSandboxSession`` 上（真正构造 exec 环境的会话对象），
    ``UnixLocalSandboxClient`` 上**没有**这个方法——第一版实现锚错到
    Client、假模块同样锚错，真机启动即 AttributeError 而单测全绿，
    本结构就是为了不再复现这种「两层同错」。
    """

    class FakeSession:
        async def _resolved_exec_context(self):
            import os

            env = dict(os.environ)
            env.setdefault("SANDBOX_MARKER", "1")
            return env, "/workspace"

    class FakeClient:  # 真实 SDK 的 Client 无此方法，这里刻意不给
        pass

    fake = types.ModuleType("agents.sandbox.sandboxes.unix_local")
    fake.UnixLocalSandboxClient = FakeClient  # type: ignore[attr-defined]
    fake.UnixLocalSandboxClientOptions = type(  # type: ignore[attr-defined]
        "FakeOptions", (), {}
    )
    fake.UnixLocalSandboxSession = FakeSession  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agents.sandbox.sandboxes.unix_local", fake)
    monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)
    module = importlib.import_module("ctf_strix.local_backend")
    try:
        yield module, FakeSession
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


def test_patch_targets_session_not_client(local_backend):
    """补丁必须落在 Session（真正构造 exec 环境）上，且不能碰 Client。"""
    module, session_cls = local_backend

    module._patch_exec_env_credentials()
    # 包装落在 Session 上；Client 上不该出现凭据剥离的任何痕迹。
    assert getattr(session_cls, "_ctfy_env_patched", False) is True
    assert session_cls._resolved_exec_context.__name__ == "_resolved_exec_context"
    assert not hasattr(module.UnixLocalSandboxClient, "_ctfy_env_patched")
    assert not hasattr(module.UnixLocalSandboxClient, "_resolved_exec_context")


def test_patch_fails_loud_when_attribute_missing(monkeypatch):
    """SDK 结构再变（方法被改名/移走）时启动即报可读错误，不在 run 中途炸。"""
    import asyncio
    import importlib
    import sys

    class BareSession:  # 无 _resolved_exec_context
        pass

    fake = types.ModuleType("agents.sandbox.sandboxes.unix_local")
    fake.UnixLocalSandboxClient = type("FakeClient", (), {})
    fake.UnixLocalSandboxClientOptions = type("FakeOptions", (), {})
    fake.UnixLocalSandboxSession = BareSession
    monkeypatch.setitem(sys.modules, "agents.sandbox.sandboxes.unix_local", fake)
    monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)
    module = importlib.import_module("ctf_strix.local_backend")
    try:
        with pytest.raises(RuntimeError, match="_resolved_exec_context"):
            module._patch_exec_env_credentials()
    finally:
        monkeypatch.delitem(sys.modules, "ctf_strix.local_backend", raising=False)
    # BareSession 未被污染，fail-loud 没有半途打标记。
    assert not hasattr(BareSession, "_ctfy_env_patched")
    assert not any(inspect.iscoroutinefunction(getattr(BareSession, n, None))
                   for n in dir(BareSession))


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
