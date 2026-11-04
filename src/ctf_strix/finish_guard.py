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

import asyncio
import inspect
import re
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ctf_strix.flag_extract import FLAG_RE

if TYPE_CHECKING:
    from agents import FunctionTool

#: flag 形态。必须与 :data:`ctf_strix.flag_extract.FLAG_RE` 完全一致：run 的
#: 工具输出证据也是按那条正则记录的，两条正则一旦分叉，守卫会认出一个
#: ``EvidenceLedger`` 永远记录不到的 flag 形状。这里复用同一定义，避免
#: "守卫看得见、证据链看不见" 的假阴性/假阳性。
_FLAG_RE = FLAG_RE

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

    def __init__(
        self,
        *,
        require_flag: bool = True,
        success: Any = None,
        evidence: Any = None,
        checker: Callable[[], bool] | None = None,
    ) -> None:
        """Args:
            require_flag: 是否要求 summary 里有 flag。engagement（报告交付）
                与 checker（副作用交付）题没有 flag，必须传 False，否则每一次
                正常收工都会被拦三次。
            success: structured success ledger, wired by the entrypoint.
            evidence: optional ``EvidenceLedger`` recording every flag seen in
                this run's tool output.  When supplied, a flag-shaped summary
                still has to be backed by that output evidence; otherwise the
                guard would accept a fabricated string the model merely
                wrote down.  ``None`` keeps the legacy regex-only policy for
                callers that have not wired an evidence ledger yet.
            checker: optional one-shot platform probe.  It is consulted before
                an answerless finish is refused, and its result is cached for
                the rest of this run.  A solved probe marks ``success``; a
                failed or unreachable one leaves the existing policy intact.
        """
        self.refusals = 0
        self.allowed = 0
        self.require_flag = require_flag
        # A structured success ledger, when the caller wires one in.  The guard
        # only reports a flag it already validated; it never inspects prose.
        self.success = success
        self.evidence = evidence
        self.checker = checker
        self._probe_done = False
        self._probe_started = False
        self._probe_result = False
        self._probe_lock = threading.Lock()
        self._probe_ready = threading.Event()
        #: Last probe diagnostic, surfaced in ``result.json`` so "no signal"
        #: is distinguishable from "probe never armed".
        self.probe_note = ""

    def _evaluate_policy(self, raw_input: str) -> tuple[dict[str, Any] | None, bool]:
        """Apply everything that does not need a platform call.

        A solve already recorded by any channel wins before the flag check:
        otherwise a PoE task would be refused forever after its platform
        verdict was recorded, because there is no flag string to quote.

        Returns:
            ``(refusal, needs_probe)``.  ``refusal`` is ``None`` when the call
            is allowed or when the probe still has to run.
        """
        if self.success is not None and getattr(self.success, "solved", False):
            self.allowed += 1
            return None, False
        if not self.require_flag:
            self.allowed += 1
            return None, False
        found = [m.group(0) for m in _FLAG_RE.finditer(raw_input or "")]
        accepted = [flag for flag in found if _PLACEHOLDER.match(flag) is None]
        if accepted:
            if self.evidence is None:
                supported = accepted
            else:
                supported = [flag for flag in accepted if self.evidence.supports(flag)]
                for flag in accepted:
                    if flag not in supported:
                        reject = getattr(self.evidence, "reject", None)
                        if reject is not None:
                            reject(flag)
            if supported:
                if self.success is not None:
                    self.success.observe_answer(supported[0], source="finish_guard")
                self.allowed += 1
                return None, False
        return None, True

    def _probe_taken(self, result: bool, note: str) -> None:
        with self._probe_lock:
            self._probe_done = True
            self._probe_result = bool(result)
            self.probe_note = note
            self._probe_ready.set()

    def _probe_claim(self) -> bool:
        """Return True when this caller must perform the one-shot probe."""
        with self._probe_lock:
            if self._probe_done:
                return False
            if self._probe_started:
                return False
            self._probe_started = True
            return True

    def _after_probe(self) -> dict[str, Any] | None:
        if self._probe_result:
            if self.success is not None and not getattr(self.success, "solved", False):
                self.success.mark("checker", "finish guard probe")
            self.allowed += 1
            return None
        if self.refusals >= _MAX_REFUSALS:
            self.allowed += 1
            return None
        self.refusals += 1
        return dict(_REFUSAL)

    async def check_async(self, raw_input: str) -> dict[str, Any] | None:
        """Async variant used by the tool wrapper.

        The probe is awaited, never called inline: a synchronous ``urlopen``
        inside ``check`` would block the runner's event loop.  Non-async
        checkers are still offloaded to a worker thread.

        Args:
            raw_input: finish_scan arguments (JSON string).

        Returns:
            A refusal dict, or ``None`` when the call may proceed.
        """
        refusal, needs_probe = self._evaluate_policy(raw_input)
        if refusal is not None or not needs_probe:
            return refusal
        if self.checker is None:
            return self._after_probe()
        if self._probe_claim():
            try:
                if inspect.iscoroutinefunction(self.checker):
                    result = await self.checker()
                else:
                    # A plain ``urlopen`` checker must not stall every other
                    # task on the runner's event loop.
                    result = await asyncio.to_thread(self.checker)
                    if inspect.isawaitable(result):
                        result = await result
                self._probe_taken(bool(result), "passed" if result else "not solved")
            except Exception as exc:  # noqa: BLE001 -- probe failure must not change policy
                self._probe_taken(False, f"{type(exc).__name__}: {exc}")
        elif not self._probe_ready.is_set():
            # Another finish call is probing; wait without blocking the loop.
            await asyncio.to_thread(self._probe_ready.wait)
        return self._after_probe()

    def check(self, raw_input: str) -> dict[str, Any] | None:
        """Synchronous policy evaluation for legacy callers and unit tests.

        This path deliberately never performs the platform probe: a blocking
        ``urlopen`` here could run inside the runner's event loop.  When a
        checker is armed, a call that needs the probe follows the same refusal
        policy as an unreachable probe, and the one-shot probe stays available
        to :meth:`check_async`.  Production wiring always uses the async path.

        Args:
            raw_input: finish_scan arguments (JSON string).

        Returns:
            A refusal dict, or ``None`` when the call may proceed.
        """
        refusal, needs_probe = self._evaluate_policy(raw_input)
        if refusal is not None or not needs_probe:
            return refusal
        return self._after_probe()


def install(
    *,
    require_flag: bool = True,
    success: Any = None,
    evidence: Any = None,
    checker: Callable[[], bool] | None = None,
) -> FinishGuard:
    """包装工具入口，给 finish_scan 装上收工守卫。

    与另外两个守卫用同一手法（改 ``on_invoke_tool``，不动 vendor 代码）。
    三层可以叠加，各自的幂等标记互相独立。

    Returns:
        已安装的守卫实例，供运行后统计。
    """
    from strix.agents import factory

    guard = FinishGuard(
        require_flag=require_flag,
        success=success,
        evidence=evidence,
        checker=checker,
    )
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
            # Always await the guard: with a checker armed it performs the
            # one-shot HTTP probe off the event loop, and with no checker it
            # simply runs the policy above.
            refusal = await guard.check_async(raw_input)
            if refusal is not None:
                return refusal
            return await inner(ctx, raw_input)

        tool.on_invoke_tool = invoke
        tool._ctf_finish_guarded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
