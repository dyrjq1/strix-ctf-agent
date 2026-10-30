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

import io
import itertools
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.sandboxes.unix_local import (
    UnixLocalSandboxClient,
    UnixLocalSandboxClientOptions,
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


#: strix 写死注入的代理变量，指向容器内的 Caido sidecar
#: （``session_manager.py:308-314``，``http://127.0.0.1:<caido_port>``）。
#:
#: ⚠️ **本机没有 Caido 在那个端口监听**，所以任何走这些变量的请求都会打到
#: 一个死端口，立即失败。实测表现：``curl`` 返回 ``000``，且
#: ``Wall time: 0.0230 seconds``——不是超时，是连接被拒。
#:
#: 这个缺陷每次都要 agent 自己花轮次诊断：CTFARENA-013 的日志里能看到
#: ``env | grep -i proxy``、``ss -ltnp``，最后靠 ``curl --noproxy '*'`` 绕过
#: 才成功；CTFARENA-012 没诊断出来，一直在 ``000`` 上重试到撞墙。
#: 在适配层删掉这些变量，等于把所有题都省下这段诊断成本。
_CAIDO_PROXY_KEYS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
)


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
      主机——于是它读到了别题的 ``/tmp/sample/files/SAMPLE-001/setup.txt``
      和评测用的 ``challenges.json``。

    第一版没意识到这一点，SAMPLE-001 的 agent 真的从主机捡了另一题的答案。
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
    logger.info("Registered strix sandbox backend: local")


def _patch_extra_file_target() -> None:
    """让附件解到**本 backend 的 root**，而不是写死的 ``/workspace``。

    strix 的 ``stage_extra_files`` 把 harness 塞进来的附件解到模块常量
    ``_WORKSPACE_ROOT = "/workspace"``，并把 ``_extra_file_rel_path`` 的合法
    前缀也写死成 ``/workspace/``。

    这在 Docker 里是对的（容器里 /workspace 就是工作目录），在本机 backend
    上却是错的：工作目录是私有临时目录，解到 ``/workspace`` 等于把附件丢到
    主机上另一个完全不相干的位置，agent 在自己的 CWD 里永远看不到它。
    实测代价是 SAMPLE-002/001 各花 2-3 个 turn 满盘 find 一个"已注入"的附件。

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
