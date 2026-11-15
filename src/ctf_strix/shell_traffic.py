"""把 ``exec_command`` 里发出的 HTTP 记进流量台账（只记录，不改行为）。

## 为什么需要它

277 个真实 run 的工具调用里 ``exec_command`` 占 64%，``http_probe`` 只占 14%：
模型大多用 curl / python 脚本直接发请求。这些交换**不进台账**（台账 §4.182），
于是所有建在台账上的东西一起失效——``traffic_list`` 277 个 run 只被调用 27 次，
``viability_probe`` **一次都没有**（它读不到"目标给过的 id 有没有被请求过"，
只在真正会用的题上才有机会被想到，而那类题本来就不触发它）。

换句话说：过去几轮我们默认"做出结构化工具，模型就会用"，277 个 run 否定了它。
本模块是这条结论的直接后果——**把入口放在模型必然经过的地方**
（``exec_command`` 本身），而不是再造一个等人来用的工具。

## 做什么 / 不做什么

做：从命令文本里认出「HTTP 客户端 + 绝对 URL」的组合，以 ``phase="shell"``
记一条条目。这样 ``traffic_list`` / ``traffic_view`` / ``pending_targets``
至少知道"这个 host 已经被 shell 摸过"。

不做：**不记响应**。shell 里的输出在工具结果里，台账拿不到状态码与体；
所以条目的 ``status`` 是 ``None``、``phase`` 是 ``shell``，读的人一眼能看出
"这条只有意图，没有证据"。假装记到了响应，比不记更坏。

不做：不改命令、不改结果、不拦调用。记录失败（正则炸了、台账写盘失败）
一律吞掉并记日志——**观测层不能拖垮挑战本身**（与 ``turn_budget`` 同一条纪律）。

## 保真度（写下来防止被高估）

- 认得：``curl`` / ``wget`` / ``requests.*`` / ``httpx.*`` / ``urlopen`` /
  ``http.client``，``-X``、``--data``、``-F``、``-T`` 推方法。
- 认得：同一命令里 ``B="https://host"`` 这类赋值，客户端调用行只写 ``$B``
  时按该 base 记一条（这是脚本里最常见的形态）。
- 认不得：循环里拼出来的路径、重定向跟随、依赖环境变量展开的 URL。
  所以这是**下界**，不是完整清单。

关掉：``CTF_SHELL_LEDGER=0``（消融用；默认开）。
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from typing import TYPE_CHECKING, Any

from ctf_strix import traffic

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 施加过本层的工具标记。
_MARK = "_ctf_shell_ledger"

#: 模块级单例。``agent.py`` 每 attempt 不重置——台账是整局记忆。
_GUARD: "ShellTraffic | None" = None

#: 一条命令最多记这么多条，防止 ``for i in $(seq 500)`` 灌满台账。
_MAX_PER_COMMAND = 20

#: 认得出的 HTTP 客户端。URL 不带其中任何一个当锚点就不记——
#: XML/SVG 里的命名空间（``http://www.w3.org/...``）正是靠这条挡掉的。
_CLIENT_RE = re.compile(
    r"\b(?:curl|wget|urlopen|urlretrieve|http\.client|httpx|requests\.\w+)\b"
    r"|\brequests\b",
    re.IGNORECASE,
)

#: 绝对 URL。显式排除 shell 元字符与引号，``$`` 也要排除（``$B/x`` 是变量拼接）。
_URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]{}\\|^`;$]+", re.IGNORECASE)

#: 同一命令里 ``NAME=https://host`` 的赋值，供只写 ``$NAME`` 的客户端行回填。
_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)=[\"']?(https?://[^\s\"'<>()\[\]{}\\|^`;$]+)"
)

#: 命令分段：换行、``;``、``&&``、``||``、``|``。方法推断在段内做。
_SPLIT_RE = re.compile(r"\n|;|&&|\|\||\|")

_PY_VERB_RE = re.compile(
    r"\b(?:requests|httpx|session)\.(get|post|put|patch|delete|head|options)\s*\(",
    re.IGNORECASE,
)
_EXPLICIT_METHOD_RE = re.compile(r"(?:\s-X\s*|\s--request\s+|\bmethod\s*=\s*['\"])([A-Za-z]+)")
_BODY_FLAG_RE = re.compile(
    r"(?:^|\s)(?:-d|--data(?:-raw|-binary|-urlencode)?|-F|--form|--post-data|--post-file)(?:\s|=|$)"
)
_UPLOAD_FLAG_RE = re.compile(r"(?:^|\s)(?:-T|--upload-file)(?:\s|=|$)")


def extract_requests(command: str, limit: int = _MAX_PER_COMMAND) -> list[tuple[str, str]]:
    """从一条 shell 命令里认出 (method, url) 对。

    规则（按优先级）：
    1. 段内没有 HTTP 客户端锚点 → 整段不看（挡掉 XML 命名空间之类的假 URL）。
    2. 有绝对 URL → 每个 URL 各记一条，方法按该段的参数推。
    3. 段内没绝对 URL，但本命令有 ``NAME=https://host`` 赋值 → 用该 base 记一条。

    Args:
        command: ``exec_command`` 的 ``command`` 原文。
        limit: 最多返回多少条（去重后）。

    Returns:
        ``(method, url)`` 列表，按出现顺序、已去重。
    """
    if not command or not isinstance(command, str):
        return []
    assignments = {m.group(1): m.group(2) for m in _ASSIGN_RE.finditer(command)}
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def push(method: str, url: str) -> None:
        url = url.rstrip(".,'\"")  # 站外常见的句末标点
        if not url or (method, url) in seen:
            return
        seen.add((method, url))
        out.append((method, url))

    for segment in _SPLIT_RE.split(command):
        if not segment or not _CLIENT_RE.search(segment):
            continue
        urls = _URL_RE.findall(segment)
        method = _infer_method(segment)
        if urls:
            for url in urls:
                push(method, url)
        elif assignments:
            # ``requests.get(B + "/x")``：只写了变量。按 base 记一条 intent，
            # 路径未知——这正是"下界"的含义，不假装知道具体路径。
            for base in assignments.values():
                push(method, base)
        if len(out) >= limit:
            break
    return out[:limit]


def _infer_method(segment: str) -> str:
    """从一段命令里推 HTTP 方法；推不出就是 GET。"""
    explicit = _EXPLICIT_METHOD_RE.search(segment)
    if explicit:
        return explicit.group(1).upper()
    py = _PY_VERB_RE.search(segment)
    if py:
        return py.group(1).upper()
    if _UPLOAD_FLAG_RE.search(segment):
        return "PUT"
    if _BODY_FLAG_RE.search(segment):
        return "POST"
    return "GET"


class ShellTraffic:
    """记 :class:`Exchange` 的守卫。线程安全由台账自己保证。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.commands = 0
        self.recorded = 0

    def note(self, command: str) -> int:
        """把一条命令里的 HTTP 意图记进台账，返回本次记了几条。"""
        pairs = extract_requests(command)
        if not pairs:
            return 0
        ledger = traffic.ledger()
        for method, url in pairs:
            traffic.record(
                request_id=ledger.next_id(),
                method=method,
                url=url,
                phase="shell",
                note="issued through exec_command; response not captured",
            )
        with self._lock:
            self.commands += 1
            self.recorded += len(pairs)
        return len(pairs)


def _enabled() -> bool:
    return os.environ.get("CTF_SHELL_LEDGER", "1").strip().lower() not in (
        "0",
        "off",
        "false",
        "no",
    )


def install() -> "ShellTraffic | None":
    """把记录层挂到工具的调用入口上。

    必须在 ``guard_mount.install_mount_hook()`` 之后调用。装在哪一层都行：
    本层只读 ``command`` 原文、只写台账，不碰结果。（实际装在守卫内层，
    这样 ``finish_scan`` 之类的注入提示不会混进命令文本。）

    Returns:
        守卫实例；``CTF_SHELL_LEDGER=0`` 时返回 ``None``（消融臂）。
    """
    from strix.agents import factory

    global _GUARD  # noqa: PLW0603 - 进程内单例
    if _GUARD is not None:
        return _GUARD
    if not _enabled():
        logger.info("shell traffic ledger disabled by CTF_SHELL_LEDGER")
        return None
    if not getattr(factory, "_ctf_mounted", False):
        raise RuntimeError(
            "call guard_mount.install_mount_hook() before shell_traffic.install()"
        )

    guard = ShellTraffic()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        if getattr(tool, "name", "") != "exec_command":
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                parsed = json.loads(raw_input) if isinstance(raw_input, str) else {}
                # SDK 的 shell 工具字段名是 ``cmd``（vendor README 与实测日志都是），
                # ``command`` 只是早期/兼容写法——两个都认，否则整层静默失效。
                command = None
                if isinstance(parsed, dict):
                    command = parsed.get("cmd") or parsed.get("command")
                if isinstance(command, str) and command.strip():
                    guard.note(command)
            except Exception:  # noqa: BLE001 - 观测失败不能拖垮挑战本身
                logger.warning("shell traffic ledger failed", exc_info=True)
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    _GUARD = guard
    logger.info("Shell traffic ledger installed")
    return guard


def current() -> "ShellTraffic | None":
    """已安装的守卫；未安装返回 ``None``（测试与诊断用）。"""
    return _GUARD


def reset_for_tests() -> None:
    """只给测试用：清掉单例，让下一次 ``install()`` 重新装。"""
    global _GUARD  # noqa: PLW0603
    _GUARD = None