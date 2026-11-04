"""运行时收工守卫：没有 flag 就不许结束 run。

## 为什么必须硬拦

CTFARENA-013（hard）是本轮最典型的一次失败：agent **只用了 260 秒**，
而预算是 780 秒。它已经注入成功、读到了 ``sqlite_master`` 的表结构，
然后调用 ``finish_scan`` 宣布结束——一次 ``cat`` 都没做。

`config/ctf_goal.txt` 里为此写了"finish_scan 前三问"（是否拿到执行能力、
是否真的去读了 flag 文件、是否还有未测假设），但没有效——**和枚举规则
是同一个教训：写在 prompt 里的自我检查会随轮次衰减。**

`finish_scan` 是 root agent 的终止工具，调用它 = 整个 run 结束。CTF 里
没有 flag 就没有完成，所以这里直接拒绝：返回符合它自身契约的
``{"success": False, "error": ...}``，把控制权交回模型。

## 为什么只拦 root 的 finish_scan，不拦子 agent 的 agent_finish

子 agent 的分工是"侦察""利用""验证"，recon 子 agent 干完活时本来就没有
flag。拦它会把正常编排打死。只有 root 收工才等于 run 结束，那才是该拦的点。

## 为什么允许连续拒绝若干次后放行

真要解不出来时，硬拦会让模型在预算末尾反复撞墙。拒绝 N 次后放行，
让它能正常写结论、退出——失败的 run 也应该干净地结束，而不是耗尽轮次。
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool

#: flag 形态。与 ctf_goal.txt 的定义、平台判分口径一致：CTFY 的 flag 不只有
#: 大写 ``FLAG{}``，也有 ``ctfy{}`` / ``flag{}``。只认大写会让 engagement 之外
#: 的合法答案被误拦三次。
_FLAG_RE = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}")

#: 模板占位符（``FLAG{...}`` / ``FLAG{xxxx}``）。守卫只该认"看起来是内容"的
#: flag；把占位符当答案会让 agent 在根本没解出题时就被放行。
_PLACEHOLDER = re.compile(
    r"^(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{(?:\.{2,}|x{2,}|X{2,}|<[^>]*>|\{[^}]*\})\}$"
)

#: 连续拒绝到这个次数就放行，避免解不出时把预算全耗在撞墙上。
_MAX_REFUSALS = 3

_REFUSAL = {
    "success": False,
    "error": (
        "REFUSED: this summary contains no flag, so the run is not complete. "
        "finish_scan terminates everything — there is no next turn after it. "
        "Do not summarize, do not write a report, go back and get the flag.\n"
        "Concretely, in this order:\n"
        "  1. If you already have code execution, file read, or DB read on the target, "
        "USE IT NOW: `find / -name '*flag*' 2>/dev/null`, `cat /flag*`, "
        "`ls -la /answers /opt /root`, and dump the tables you enumerated "
        "(`SELECT * FROM <table>`) — the flag is a row, not a schema.\n"
        "  2. If you only proved a vulnerability exists, you are not done. Turn it into "
        "reading the actual data.\n"
        "  3. If you never authenticated, the access-control bug is behind a session you "
        "have not created yet — register, log in, then walk IDs around your own.\n"
        "Call finish_scan again only once the flag string is in this summary."
    ),
}


class FinishGuard:
    """拦下"没有 flag 的收工"。"""

    def __init__(self, *, require_flag: bool = True, success: Any = None) -> None:
        """Args:
            require_flag: 是否要求 summary 里有 flag。engagement（报告交付）
                与 checker（副作用交付）题没有 flag，必须传 False，否则每一次
                正常收工都会被拦三次。
        """
        self.refusals = 0
        self.allowed = 0
        self.require_flag = require_flag
        # A structured success ledger, when the caller wires one in.  The guard
        # only reports a flag it already validated; it never inspects prose.
        self.success = success

    def check(self, raw_input: str) -> dict[str, Any] | None:
        """判断这次 finish_scan 是否该被拒。

        Args:
            raw_input: finish_scan 的原始参数（JSON 字符串）。

        Returns:
            拒绝时返回替代结果；允许时返回 None（调用方照常执行真工具）。
        """
        if not self.require_flag:
            self.allowed += 1
            return None
        found = [m.group(0) for m in _FLAG_RE.finditer(raw_input or "")]
        accepted = [flag for flag in found if _PLACEHOLDER.match(flag) is None]
        if accepted:
            if self.success is not None:
                self.success.observe_answer(accepted[0], source="finish_guard")
            self.allowed += 1
            return None
        if self.refusals >= _MAX_REFUSALS:
            # 已经拦够了，放行。让失败的 run 也能干净收尾。
            self.allowed += 1
            return None
        self.refusals += 1
        return dict(_REFUSAL)


def install(*, require_flag: bool = True, success: Any = None) -> FinishGuard:
    """包装工具入口，给 finish_scan 装上收工守卫。

    与另外两个守卫用同一手法（改 ``on_invoke_tool``，不动 vendor 代码）。
    三层可以叠加，各自的幂等标记互相独立。

    Returns:
        已安装的守卫实例，供运行后统计。
    """
    from strix.agents import factory

    guard = FinishGuard(require_flag=require_flag, success=success)
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        # 只碰 root 的终止工具；agent_finish 属于子 agent，不拦。
        if getattr(tool, "name", "") != "finish_scan":
            return tool
        if getattr(tool, "_ctf_finish_guarded", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            refusal = guard.check(raw_input)
            if refusal is not None:
                return refusal
            return await inner(ctx, raw_input)

        tool.on_invoke_tool = invoke
        tool._ctf_finish_guarded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
