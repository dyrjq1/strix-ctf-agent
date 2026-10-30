"""把一次 strix run 关进独立的 mount namespace。

## 为什么需要这个

`local_backend` 只把 strix 的 **workspace 逻辑根** 指到隔离目录，agent 的
shell 仍然是宿主机的 shell：一句 ``cd /workspace`` 就能读到评测脚本、平台
token、其他题的 box 目录。SAMPLE-004 实测就发生了——agent 读了
``scripts/eval_sample.py``、从 ``ps`` 里抄走队伍 token，然后直接打平台
API 查实例，600 秒里 2M token 有一大半花在这上面，最后还把源码里的
``SAMPLE_SUITE`` 常量当成 flag 交了回来。

沙箱边界不能只靠 prompt 里的"别去 /workspace"：模型会衰减，命名空间不会。

## 做法

只挂载 run 真正需要的东西，其余用 tmpfs 盖掉：

    /var/ctf/jail/rt/src      ← /workspace/src
    /var/ctf/jail/rt/vendor   ← /workspace/vendor
    /var/ctf/jail/rt/venv     ← /workspace/.venv
    /var/ctf/jail/rt/run.py   ← 复制进去的 run_strix_ctf.py
    /var/ctf/jail/rt/files    ← 本题附件（没有就留空）
    /var/ctf/jail/box         ← 本题 box（可写）

盖掉 ``/tmp``、``/root``、``/workspace``、``/var/ctf/boxes``。顺序很重要：
**先把真 box bind 到 /box**，再用 tmpfs 盖住 boxes 目录——bind 已经拿到
inode，之后的覆盖不影响已挂载的视图。

## 边界

这不是安全容器。root 仍然可以 ``nsenter`` 回父命名空间，这是一道**防误闯**
的墙，不是防提权的墙：它挡住的是"agent 顺手去翻 /workspace"这类行为，
实测占全部 token 浪费的绝大部分。
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

#: 命名空间内的固定布局。宿主侧同名目录只是挂载点，内容全部来自 bind。
JAIL = Path("/var/ctf/jail")
RT = JAIL / "rt"
BOX = JAIL / "box"

#: 需要盖成空 tmpfs 的路径。``/var/ctf/boxes`` 也在这里——它必须在真 box
#: 完成 bind 之后才被覆盖，所以顺序由 :func:`wrap` 保证。
HIDE = ("/tmp", "/root", "/workspace", "/var/ctf/boxes")


def _q(path: str | Path) -> str:
    return shlex.quote(str(path))


def prepare() -> None:
    """建好宿主侧挂载点。幂等。

    ``HIDE`` 里的目录也要先建出来：``mount -t tmpfs`` 挂到一个不存在的路径会
    失败，而 ``wrap()`` 跑在 ``set -e`` 里，一失败整次启动就中止。别人的机器上
    未必有 ``/workspace``、``/var/ctf/boxes``，这一行决定了包裹能不能"拿到就跑"。
    """
    for path in (BOX, RT, RT / "src", RT / "vendor", RT / "venv", RT / "files"):
        path.mkdir(parents=True, exist_ok=True)
    for path in HIDE:
        Path(path).mkdir(parents=True, exist_ok=True)


def stage(project: Path, entry: Path) -> list[tuple[Path, Path]]:
    """把 run 需要的只读资源摆进 ``rt/``，返回 ``(源, 目标)`` 挂载表。

    ``entry`` 是 run_strix_ctf.py 的宿主路径，**复制**而不是 bind 整个
    ``scripts/`` 目录——那里还有 eval_sample.py（含平台地址与评测常量）。

    Args:
        project: 仓库根。
        entry: 要被执行的入口脚本。

    Returns:
        bind 挂载表，按顺序交给 :func:`wrap`。
    """
    prepare()
    shutil.copy2(entry, RT / "run.py")
    return [
        (project / "src", RT / "src"),
        (project / "vendor", RT / "vendor"),
        (project / ".venv", RT / "venv"),
    ]


def wrap(
    cmd: list[str],
    *,
    box: Path,
    binds: list[tuple[Path, Path]],
    hide: tuple[str, ...] | list[str] = (),
) -> list[str]:
    """把 ``cmd`` 包成一次带私有 mount namespace 的启动。

    Args:
        cmd: 命名空间内要执行的命令（路径必须是命名空间内可见的路径）。
        box: 本题 box 的宿主路径，会被 bind 到 ``/var/ctf/jail/box``。
        binds: 额外的只读资源挂载。
        hide: 额外要盖掉的目录（如本题的附件目录）。

    Returns:
        可直接交给 ``subprocess.Popen`` 的 argv。``unshare`` 只是父，真正
        的进程仍是 ``cmd[0]``；父进程侧的 ``_kill_tree`` 照常按 ``/proc``
        父子关系杀干净——这里**故意不 unshare pid**，否则 ``/proc/<pid>``
        在父侧不可见，看门狗会失去击杀能力。
    """
    prepare()
    script = ["set -e"]
    # 先 bind 真 box，再盖 boxes 目录：bind 之后 inode 已经拿到。
    script.append(f"mount --bind {_q(box)} {_q(BOX)}")
    for src, dst in binds:
        script.append(f"mount --bind {_q(src)} {_q(dst)}")
    for path in (*HIDE, *hide):
        script.append(f"mount -t tmpfs -o size=16m,mode=0755 tmpfs {_q(path)}")
    script.append(f"cd {_q(BOX)}")
    script.append('exec "$@"')
    return [
        "unshare",
        "-m",
        "--propagation",
        "private",
        "--",
        "/bin/bash",
        "-c",
        "\n".join(script),
        "ctf-jail",
        *cmd,
    ]


#: 探测用的一次性挂载点：放在 /var/ctf 下，避免和 /tmp 的隐藏冲突。
_PROBE = JAIL / "probe"


def available() -> bool:
    """确认当前内核允许 unshare mount namespace（容器里常被禁）。

    不可用时整条链路会退化成"只靠 prompt 约束"，那正是 SAMPLE-004 踩过的
    坑，所以调用方必须把探测结果打出来，不能假装隔离生效了。

    Returns:
        可用返回 True。
    """
    if os.geteuid() != 0 or shutil.which("unshare") is None:
        return False
    _PROBE.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["unshare", "-m", "--propagation", "private", "--", "/bin/true"],
        capture_output=True,
    )
    return proc.returncode == 0
