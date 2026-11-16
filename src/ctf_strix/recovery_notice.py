"""失败→下一步：把「死路」变成「有向动作」（确定性，零模型调用）。

## 为什么做这个

失败题的墙钟分布是「同一方向刷到预算耗尽」，不是「试了很多方向」。模型
看到 ``405`` / ``401`` / ``Connection refused`` 时的常见反应是**换个 URL 再试
一次同样的方法**，而不是读响应头里已经写好的 ``Allow``，或者回读一次成功
交换里的 cookie。这不是知识缺口（提示词里写过），是「输出里没有下一步」。

cai 在 ``tools/evidence/capture_notice.py`` 里对 tcpdump 权限失败做了同一件
事：把识别出的失败类别翻译成两行具体的替代动作，前置在输出上。这里把它
泛化成一张 ``(工具, 失败特征) → 替代动作`` 的确定性表。

## 边界

- 只追加文本，不改判定、不拦调用、不新增预算参数；
- 每类失败**每 run 只提示一次**（防止提示本身变成噪声，§4.241 的教训）；
- 规则按失败类别与状态码写，**不含题号 / 路径 / IP / flag**（命名测试）；
- 识别不出来就什么都不做——宁可少说，不可乱说。
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Final

logger = logging.getLogger(__name__)

#: ``(class, 正则, 建议)``。正则只描述**失败形态**，不描述目标。
_RULES: Final[tuple[tuple[str, re.Pattern[str], str], ...]] = (
    (
        "http_405",
        re.compile(r"\b405\b[^\n]{0,120}?(method|allow)", re.IGNORECASE),
        "405 means the route exists and the *method* is the gate. Use the "
        "`Allow:` header from this same response, or send GET with the same "
        "path plus query parameters. Repeating the rejected method is a dead end.",
    ),
    (
        "http_auth_gate",
        re.compile(r"\b40[13]\b"),
        "401/403 is a gate in front of your payload, not a wrong path. Re-read "
        "an exchange on this host that already worked (`traffic_view`) and "
        "replay its cookie/header; if the gate matches strings, `path_variants` "
        "covers case/encoding differences. Do not re-post the same body a third "
        "time.",
    ),
    (
        "unreachable",
        re.compile(
            r"Connection refused|Name or service not known|NameResolutionError|"
            r"Cannot connect to host|SSLError|handshake|Max retries exceeded",
            re.IGNORECASE,
        ),
        "The transport, not the application, is failing. Try another entry "
        "of this challenge first; for TLS failures retry HTTP/1.1 on port 80; "
        "for DNS failures the host is down — record it as evidence and move on.",
    ),
    (
        "empty_200",
        re.compile(r"\[HTTP 200\][^\n]{0,120}\|\s*\d{1,2}B\s*\|"),
        "200 with (almost) no body is a first hop: read `Location` and "
        "`Set-Cookie` from the same response and follow it. The body you "
        "expected is one hop further.",
    ),
    (
        "cmd_timeout",
        re.compile(r"\btimed out\b|TimeoutExpired|\[timeout\]", re.IGNORECASE),
        "The command hit a time limit. Split it into smaller steps, add an "
        "explicit `timeout`, or start it in the background and read its output "
        "file on the next turn.",
    ),
    (
        "tcp_closed",
        re.compile(r"\[tcp\][^\n]{0,80}(closed|reset|EOF)", re.IGNORECASE),
        "The peer closed the connection after your payload: keep the session "
        "open (`tcp` returns the bytes before close) and check whether the "
        "service expects a line terminator or a length prefix before it answers.",
    ),
)

#: 本 run 已经提示过的类别。每类只提示一次——重复提示会让输出变成噪声。
_SEEN: set[str] = set()
_INSTALLED = False


def reset_run() -> None:
    """清空「已提示」集合。每个 run 开始时调用。"""
    _SEEN.clear()


def classify(text: str) -> tuple[str, str] | None:
    """按失败形态给出 ``(class, advice)``；识别不出返回 ``None``。

    Args:
        text: 工具结果的原文。

    Returns:
        第一个命中的失败类别与对应建议。
    """
    if not text:
        return None
    for name, pattern, advice in _RULES:
        if pattern.search(text):
            return name, advice
    return None


def notice(tool_name: str, result: str) -> str:
    """返回要追加的提示文本；不该提示时返回空串。

    纯函数式入口：测试直接打这里，不经过 SDK。
    """
    hit = classify(result)
    if hit is None:
        return ""
    name, advice = hit
    key = f"{tool_name}:{name}"
    if key in _SEEN:
        return ""
    _SEEN.add(key)
    return f"\n[NEXT] {advice}\n"


def _tool_args(raw: Any) -> str:
    """工具参数只用于诊断，不参与分类。"""
    if isinstance(raw, str):
        return raw[:200]
    try:
        return json.dumps(raw, ensure_ascii=False)[:200]
    except Exception:  # noqa: BLE001
        return ""


def _attach(tool: Any) -> Any:
    """把一个 FunctionTool 的 on_invoke_tool 包成「调用→必要时追加提示」。"""
    original = getattr(tool, "on_invoke_tool", None)
    if original is None or getattr(tool, "_ctf_recovery", False):
        return tool
    name = getattr(tool, "name", "")

    async def on_invoke(ctx: Any, raw: Any) -> Any:
        result = await original(ctx, raw)
        try:
            if isinstance(result, str):
                extra = notice(name, result)
                if extra:
                    return result + extra
        except Exception:  # noqa: BLE001 - a hint must never break a tool
            logger.debug("recovery notice failed for %s (%s)", name, _tool_args(raw))
        return result

    tool.on_invoke_tool = on_invoke
    tool._ctf_recovery = True
    return tool


def install() -> bool:
    """把提示挂到统一挂载点上；两个入口（官方 + harness）都经此生效。

    幂等。必须在 ``guard_mount.install_mount_hook()`` 之后、建 agent 之前调用；
    ``tool_trim.install_ctf_toolset`` 是共享接线点。
    """
    global _INSTALLED
    if _INSTALLED:
        return True
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 - no runtime, nothing to mount
        return False

    original = factory._with_bounded_result

    def with_recovery(tool: Any) -> Any:
        return _attach(original(tool))

    factory._with_bounded_result = with_recovery  # type: ignore[assignment]
    _INSTALLED = True
    return True