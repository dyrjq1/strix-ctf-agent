"""Local (no-Docker) sandbox backend for strix.

Registers a ``local`` backend into strix's runtime registry so
``session_manager.create_or_reuse`` runs commands on the host filesystem
instead of inside a Docker container.

Why this exists
---------------
strix ships exactly one backend (``docker``, see ``strix/runtime/backends.py:54``)
and fails at ``docker://images/create`` without a reachable daemon. The
upstream authors left ``register_backend`` public precisely for this case
(``strix/runtime/backends.py:79``), and ``strix/agents/factory.py:616``
documents that registering before the first ``build_strix_agent`` is enough.

The heavy lifting is done by ``agents.sandbox.sandboxes.unix_local`` which
already implements a full host-side session (exec, PTY, files, ports). We
only adapt its ``create()`` signature to strix's backend contract.
"""

from __future__ import annotations

import functools
import io
import itertools
import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.sandboxes.unix_local import (
    UnixLocalSandboxClient,
    UnixLocalSandboxClientOptions,
    UnixLocalSandboxSession,
)
from strix.runtime.backends import register_backend


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest


logger = logging.getLogger(__name__)

#: 同一进程内多次建档时保证目录名唯一（子 agent 会复用同一 session，一般只有一个）。
_SEQ = itertools.count()

#: 最近一次建档的私有 workspace root。附件落盘目标由此决定（见
#: `_patch_extra_file_target`）。
_ACTIVE_ROOT: str | None = None


def workspace_root() -> Path | None:
    """本次 run 的沙箱工作目录（绝对路径）；尚未建档时返回 ``None``。

    权限层之外的**路径口径**入口：shell 的 CWD 就是这个目录
    （``unix_local._resolved_exec_context`` 把 ``cwd`` 和 ``HOME`` 都设在这里），
    但提示层与工具都用 ``/workspace/...`` 或进程 CWD 说话，三方不一致（FMT-3）。
    ``file_triage`` / ``nonweb`` 通过本函数把相对路径与 ``/workspace/x`` 统一解析
    到同一处，读到的就是 agent 在 shell 里看到的那份文件。
    """
    return Path(_ACTIVE_ROOT) if _ACTIVE_ROOT else None


#: strix 写死注入的代理变量，指向容器内的 Caido sidecar
#: （``session_manager.py:308-314``，``http://127.0.0.1:<caido_port>``）。
#:
#: ⚠️ **本机没有 Caido 在那个端口监听**，所以任何走这些变量的请求都会打到
#: 一个死端口，立即失败。实测表现：``curl`` 返回 ``000``，且
#: ``Wall time: 0.0230 seconds``——不是超时，是连接被拒。
#:
#: 这个缺陷每次都要 agent 自己花轮次诊断：一次 run 的日志里能看到
#: ``env | grep -i proxy``、``ss -ltnp``，最后靠 ``curl --noproxy '*'`` 绕过
#: 才成功；另一次没诊断出来，一直在 ``000`` 上重试到撞墙。
#: 在适配层删掉这些变量，等于把所有题都省下这段诊断成本。
_CAIDO_PROXY_KEYS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
)

#: runner 进程凭据类变量。``unix_local.py`` 构造每次 exec 的环境时用
#: ``os.environ.copy()`` 打底，runner 的全部环境变量原样进沙箱——模型跑一句
#: ``env`` 就能读到解题用的 LLM key,且已实际发生过:一次失败 run 把 key
#: 当成答案字符串提交(裸 hex 恰好命中答案形状)。
#:
#: 生效点必须在 ``UnixLocalSandboxSession._resolved_exec_context`` 的返回值上:
#: 它先 ``os.environ.copy()`` 再 ``manifest.environment.resolve()`` update——
#: resolve 只增/覆盖不删除，所以在 manifest 层 pop 对 runner 环境来的键无效
#: (第一版踩过)。也不能直接清 runner 的 ``os.environ``:runner 进程自己调
#: LLM 还要靠这些变量。在适配层包装该方法、对返回的 env dict 删凭据键，
#: 把「平台凭据对 agent 不可见」从隐式假设变成硬保证。
#: 模式匹配而非枚举:供应方换前缀(如 OpenRouter/Zhipu 自定义名)也覆盖。
_CREDENTIAL_ENV_RE = re.compile(
    r"^(?:LLM_|STRIX_)?(?:.*(?:API_KEY|TOKEN|SECRET)|.*_KEY)$|"
    r"^(?:OPENAI|ANTHROPIC|GEMINI|ZHIPU|DEEPSEEK|DASHSCOPE|MISTRAL|"
    r"COHERE|GROQ|TOGETHER|FIREWORKS)_[A-Z_]*$",
    re.IGNORECASE,
)

#: 已知合法但字面含 KEY/TOKEN 的系统变量，显式豁免防误伤。
_ENV_KEEP = frozenset({"PATH", "HOME", "PYTHONPATH", "KEYCLOAK_HOST"})


def _strip_dead_proxy(manifest: Manifest) -> list[str]:
    """从沙箱环境里删掉指向不存在 Caido 的代理变量。

    ``environment.value`` 是可变 dict，且 ``unix_local.py:434`` 会把它
    ``update`` 进每次 exec 的环境，所以在这里改就生效。

    Args:
        manifest: strix 构造的沙箱清单。

    Returns:
        被删掉的变量名，供日志核对。
    """
    env = getattr(getattr(manifest, "environment", None), "value", None)
    if not isinstance(env, dict):
        return []
    removed = [k for k in _CAIDO_PROXY_KEYS if k in env]
    for key in removed:
        env.pop(key, None)
    return removed


def _credential_env_keys(env: dict[str, str]) -> list[str]:
    """按 ``_CREDENTIAL_ENV_RE`` 挑出 env dict 里的凭据键名。"""
    return [k for k in env if k not in _ENV_KEEP and _CREDENTIAL_ENV_RE.match(k)]


def _patch_exec_env_credentials() -> None:
    """包装 ``UnixLocalSandboxSession._resolved_exec_context``,删凭据键。

    每次工具 exec 都会走该方法构造环境(常规 exec / PTY / 读文件三条路径)，
    在返回的 env dict 上删一次即覆盖全部路径。类级替换、幂等：重复 install
    不会叠两层包装(叠了也只是白删一次，无害，但日志会重复)。

    ⚠️ 目标类是 ``UnixLocalSandboxSession``(持有 ``state.manifest``、真正构造
    exec 环境的会话对象)，不是 ``UnixLocalSandboxClient``——第一版锚错了类，
    真机启动即 ``AttributeError``(单测假模块同样锚错所以没拦住)。此处对目标
    属性做显式检查，SDK 结构再变时启动即报可读错误，不在 run 中途炸。
    """
    if getattr(UnixLocalSandboxSession, "_ctfy_env_patched", False):
        return
    original = getattr(UnixLocalSandboxSession, "_resolved_exec_context", None)
    if original is None:
        raise RuntimeError(
            "unix_local.UnixLocalSandboxSession._resolved_exec_context 不存在——"
            "agents SDK 结构可能已变化，凭据剥离补丁需要重新对位"
        )

    @functools.wraps(original)
    async def _resolved_exec_context(self: Any) -> tuple[dict[str, str], str]:
        env, cwd = await original(self)
        for key in _credential_env_keys(env):
            env.pop(key, None)
        return env, cwd

    UnixLocalSandboxSession._resolved_exec_context = (  # type: ignore[method-assign]
        _resolved_exec_context
    )
    UnixLocalSandboxSession._ctfy_env_patched = True  # type: ignore[attr-defined]
    logger.info("Sandbox exec env: credential stripping active")


async def _local_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Bring up a host-side session, mirroring strix's ``_docker_backend``.

    ## 隔离：每个 scan 一个独立私有目录

    **必须**把 ``manifest.root`` 改成一个新建的私有空目录，否则本 backend
    会把"主机文件系统"原样当成沙箱：

    · ``stage_extra_files`` 把附件解到 ``$WORKSPACE``，也就是 **主机根**
      ``/``——普通用户在本机没有写权限时会报错；以 root 运行就直接往主机 ``/``
      里写文件。
    · 反过来说，agent 的 ``cd /tmp``、``ls /workspace``、``find /`` 全都能看到
      主机——于是它读到了别题的 ``/tmp/sample/files/<instance>/setup.txt``
      和评测用的 ``challenges.json``。

    第一版没意识到这一点，agent 真的从主机捡了另一题的答案。
    对齐真实运行时（Docker 容器里 CWD 是干净的）是**正确性**问题，不是洁净癖。

    Args:
        image: Ignored. Accepted so the signature matches strix's contract.
        manifest: Workspace layout; its ``root`` is replaced with a private
            temp dir, which also becomes the working directory.
        exposed_ports: Ports strix later resolves via ``resolve_exposed_port``
            (strix asks for 48080, its Caido proxy port).
        bind_mounts: Ignored. Host paths already are host paths here; the
            backend is registered with ``supports_bind_mounts=True`` so
            strix builds bind mounts instead of uploading a manifest archive.

    Returns:
        ``(client, session)`` as strix expects.
    """
    del image, bind_mounts  # unused: no container image, no mount indirection

    removed = _strip_dead_proxy(manifest)
    if removed:
        logger.info("Removed dead Caido proxy vars from sandbox env: %s", ", ".join(removed))

    # 隔离目录由本次调用创建，进程退出即弃。不用 mkdtemp 的默认 /tmp 前缀——
    # 万一 agent 执行 find /，也不该一眼看到名字里带 sandbox 的目录。
    global _ACTIVE_ROOT
    box = Path(f"/tmp/sandbox-{os.getpid()}-{next(_SEQ)}")
    box.mkdir(parents=True, exist_ok=True)
    _ACTIVE_ROOT = str(box)
    logger.info("Local sandbox workspace: %s (was %r)", box, manifest.root)
    manifest.root = str(box)

    client = UnixLocalSandboxClient()
    options = UnixLocalSandboxClientOptions(exposed_ports=exposed_ports)
    session = await client.create(manifest=manifest, options=options)
    await session.start()
    logger.info("Local sandbox session started (root=%s)", manifest.root)
    return client, session


def install() -> None:
    """Register the ``local`` backend. Call before the first sandbox is created."""
    register_backend("local", _local_backend, supports_bind_mounts=True)
    _patch_extra_file_target()
    _patch_exec_env_credentials()
    logger.info("Registered strix sandbox backend: local")


def _patch_extra_file_target() -> None:
    """让附件解到**本 backend 的 root**，而不是写死的 ``/workspace``。

    strix 的 ``stage_extra_files`` 把 harness 塞进来的附件解到模块常量
    ``_WORKSPACE_ROOT = "/workspace"``，并把 ``_extra_file_rel_path`` 的合法
    前缀也写死成 ``/workspace/``。

    这在 Docker 里是对的（容器里 /workspace 就是工作目录），在本机 backend
    上却是错的：工作目录是私有临时目录，解到 ``/workspace`` 等于把附件丢到
    主机上另一个完全不相干的位置，agent 在自己的 CWD 里永远看不到它。
    实测代价是 每道题各花 2-3 个 turn 满盘 find 一个"已注入"的附件。

    这里替换两个符号，目标目录取最近一次建档的私有 root。
    """
    from strix.runtime import session_manager as sm

    def _current_root() -> str:
        return _ACTIVE_ROOT or "/workspace"

    original_rel = sm._extra_file_rel_path

    def rel_path(workspace_path: str) -> str | None:
        # 仍然只接受 /workspace/ 前缀（那是调用方与 harness 的约定），
        # 但不改调用方语义：真正落盘的位置由 stage 决定。
        if not workspace_path.startswith("/workspace/"):
            return None
        return original_rel(workspace_path)

    async def stage(session: Any, archive: bytes) -> None:
        root = _current_root()
        archive_path = f"{root}/.strix-extra-files.tar"
        await session.write(Path(archive_path), io.BytesIO(archive))
        await session.exec(
            "sh", "-c",
            'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"',
            "sh", archive_path, root,
        )

    sm._extra_file_rel_path = rel_path  # type: ignore[assignment]
    sm.stage_extra_files = stage  # type: ignore[assignment]
