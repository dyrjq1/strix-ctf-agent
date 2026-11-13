"""运行时收工守卫：没有可交付的答案就不许结束 run。

## 为什么必须硬拦

一道 hard 题是本轮最典型的一次失败：agent **只用了 260 秒**，
而预算是 780 秒。它已经注入成功、读到了 ``sqlite_master`` 的表结构，
然后调用 ``finish_scan`` 宣布结束——一次 ``cat`` 都没做。

`config/ctf_goal.txt` 里为此写了"finish_scan 前三问"（是否拿到执行能力、
是否真的去读了 flag 文件、是否还有未测假设），但没有效——**和枚举规则
是同一个教训：写在 prompt 里的自我检查会随轮次衰减。**

`finish_scan` 是 root agent 的终止工具，调用它 = 整个 run 结束。CTF 里
没有可交付的答案就没有完成——flag 形态，或模型在 summary 里显式写下的
``answer:`` 行（slug / token 型题没有 ``tag{...}`` 长相）——所以这里直接
拒绝：返回符合它自身契约的
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
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ctf_strix.flag_extract import (
    FLAG_RE,
    explicit_answer_values,
    is_code_template,
    is_placeholder,
    per_question_answers,
)

if TYPE_CHECKING:
    from agents import FunctionTool

#: flag 形态。必须与 :data:`ctf_strix.flag_extract.FLAG_RE` 完全一致：run 的
#: 工具输出证据也是按那条正则记录的，两条正则一旦分叉，守卫会认出一个
#: ``EvidenceLedger`` 永远记录不到的 flag 形状。这里复用同一定义，避免
#: "守卫看得见、证据链看不见" 的假阴性/假阳性。
_FLAG_RE = FLAG_RE

#: 连续拒绝到这个次数就放行，避免解不出时把预算全耗在撞墙上。
_MAX_REFUSALS = 3

_REFUSAL = {
    "success": False,
    "error": (
        "REFUSED: this summary contains no answer, so the run is not complete. "
        "finish_scan terminates everything — there is no next turn after it. "
        "Do not summarize, do not write a report, go back and get the flag.\n"
        "Concretely, in this order:\n"
        "  1. If you already have code execution, file read, or DB read on the target, "
        "USE IT NOW: search inside the data you already reached — dump the tables "
        "you enumerated (`SELECT * FROM <table>`; the flag is a row, not a schema), "
        "read the files the app itself reads, and check config/leak output with "
        "`cat`. Do not hunt the local filesystem.\n"
        "  2. If you only proved a vulnerability exists, you are not done. Turn it into "
        "reading the actual data.\n"
        "  3. If you never authenticated, the access-control bug is behind a session you "
        "have not created yet — register, log in, then walk IDs around your own.\n"
        "  4. If you are stuck because 'the route does not exist', stop guessing "
        "paths one by one. Map the real surface first: run route_map against the "
        "live host to list actual API paths, method_sweep a candidate path to see "
        "which method answers, and grep the JS/asset files you already downloaded "
        "for fetch/axios/API URL strings — the endpoint is usually named there. "
        "Route discovery tools exist for exactly this; use them instead of more "
        "manual guesses.\n"
        "  5. The answer is not always a `tag{...}` flag: some challenges grade a "
        "slug, a token, or a plain string. If that is what you are holding, do not "
        "keep hunting for a flag that does not exist — deliver it as its own line "
        "inside the executive_summary, exactly as `answer: <the exact string>`. "
        "That line is what the submission layer reads; prose around it is not.\n"
        "  6. Quote the answer exactly as the target emitted it. The tag in front "
        "of the braces belongs to the challenge: if the output shows `utflag{...}`, "
        "`HTB{...}`, `HackTheBox{...}` or any tag you have not seen before, that IS "
        "the answer. Do not rename it to a better-known tag, do not lowercase or "
        "re-case it, do not invent a normalized alias, do not add or drop "
        "characters. A correct body under a rewritten tag scores zero.\n"
        "Call finish_scan again only once the answer is in this summary: the flag "
        "string itself, or an explicit `answer:` line."
    ),
}

#: 第 2 次拒绝起追加的换向指令。
#:
#: 实测：连收三次同一段「回去拿 flag」的通用文案后，模型会把同一份白卷
#: summary 原样再交一次，然后开一条和上次一模一样的线——文案本身没有指出
#: 「你正在重复」。所以第 2 次起要求它先点名一个**本次运行尚未试过的机制**，
#: 把「再来一次」变成一次显式选择。措辞停在机制级、不出现任何题面特定字符串，
#: 才能在所有题上复用。
_REDIRECT = (
    "\n\n[CHANGE MECHANISM] The previous refusal changed nothing: do not call "
    "finish_scan again with the same summary — that is a wasted turn. Before you "
    "try to finish again, name ONE mechanism this run has not exercised yet, "
    "then exercise it:\n"
    "  - authn/authz bypass: a session, role, or identity you have not held\n"
    "  - parameter pollution or type confusion on an endpoint you already reached\n"
    "  - the background / scheduled / job path instead of the request path\n"
    "  - configuration or metadata disclosure: the app's own config, env, "
    "manifest, or backup artifacts\n"
    "  - an information-disclosure entry point you have not opened (debug "
    "endpoint, verbose error, directory listing, export/download)\n"
    "Repeating the same finish_scan without a different mechanism will be "
    "refused again."
)


def _echo_refusal(flags: list[str]) -> dict[str, Any]:
    """Refusal used when every flag in the summary is a self-echo.

    Reusing the generic "no flag" text would tell the model to go get the
    flag, which it may believe it already has.  Name the actual problem: the
    only place the string appeared was an output that replayed the model's
    own arguments.
    """
    listing = ", ".join(flags[:3])
    return {
        "success": False,
        "error": (
            "REFUSED: the only tool-output evidence for this flag is a "
            "self-echo. The same literal was already in the tool call's own "
            "arguments (command / request / payload), and the output merely "
            f"repeated it back: {listing}. That is not retrieval. Read the "
            "flag from an output whose call did not contain that literal "
            "(for example `cat /flag`, a directory listing, or a query that "
            "does not quote the guess), then quote it in the summary."
        ),
    }


class FinishGuard:
    """拦下「没有任何可交付答案」的收工。"""

    def __init__(
        self,
        *,
        require_flag: bool = True,
        success: Any = None,
        evidence: Any = None,
        checker: Callable[[], bool] | None = None,
    ) -> None:
        """Args:
            require_flag: 是否要求 summary 里有可交付答案（flag 形态，或显式
                ``answer:`` 行）。engagement（报告交付）与 checker（副作用交付）
                题没有答案，必须传 False，否则每一次正常收工都会被拦三次。
            success: structured success ledger, wired by the entrypoint.
            evidence: optional ``EvidenceLedger`` recording every flag seen in
                this run's tool output.  When supplied, a flag-shaped summary
                still has to be backed by that output evidence; otherwise the
                guard would accept a fabricated string the model merely
                wrote down.  An output that only echoed the literal back from
                the call's own arguments does not back it either, and the
                refusal says so.  ``None`` keeps the legacy regex-only policy
                for callers that have not wired an evidence ledger yet.
            checker: optional one-shot platform probe.  It is consulted before
                an answerless finish is refused, and its result is cached for
                the rest of this run.  A solved probe marks ``success``; a
                failed or unreachable one leaves the existing policy intact.
        """
        self.refusals = 0
        self.allowed = 0
        # 拒满 ``_MAX_REFUSALS`` 后放行时置位：这一次是「放弃收尾」，不是
        # 「通过收尾」。事后统计要能把白卷与正常收工分开。
        self.gave_up = False
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

    def _evaluate_policy(
        self, raw_input: str
    ) -> tuple[dict[str, Any] | None, bool, list[str]]:
        """Apply everything that does not need a platform call.

        A solve already recorded by any channel wins before the flag check:
        otherwise a PoE task would be refused forever after its platform
        verdict was recorded, because there is no flag string to quote.

        Returns:
            ``(refusal, needs_probe, echo_only)``.  ``refusal`` is ``None``
            when the call is allowed or when the probe still has to run;
            ``echo_only`` lists the summary flags whose only output evidence
            was a self-echo, so a later refusal can say so explicitly.
        """
        if self.success is not None and getattr(self.success, "solved", False):
            self.allowed += 1
            return None, False, []
        if not self.require_flag:
            self.allowed += 1
            return None, False, []
        found = [m.group(0) for m in _FLAG_RE.finditer(raw_input or "")]
        accepted = [flag for flag in found if not is_placeholder(flag)]
        echo_only: list[str] = []
        if accepted:
            if self.evidence is None:
                supported = accepted
            else:
                supported = [flag for flag in accepted if self.evidence.supports(flag)]
                is_echo = getattr(self.evidence, "echoed_only", None)
                for flag in accepted:
                    if flag not in supported:
                        reject = getattr(self.evidence, "reject", None)
                        if reject is not None:
                            reject(flag)
                        if callable(is_echo) and is_echo(flag):
                            echo_only.append(flag)
            if supported:
                if self.success is not None:
                    self.success.observe_answer(supported[0], source="finish_guard")
                self.allowed += 1
                return None, False, []
        # 非 flag 形态答案（slug / token / 任意串）：模型在 summary 里显式
        # 写下的 ``answer:`` 行，与 ``AutoSubmitter.candidates`` 的候选抽取
        # 同源（``flag_extract.explicit_answer_values``）。这类答案没有
        # ``tag{...}`` 长相，``EvidenceLedger``（FLAG_RE 口径）永远无法背书，
        # 所以这里放行**不**调 ``observe_answer``：平台裁决（autosubmit 的
        # verify 预检 / 提交回执）才是 solved 的唯一权威；候选噪声由
        # verify-answer 预检兜住，判错不消耗提交次数。
        if explicit_answer_values(raw_input) or per_question_answers(raw_input):
            # B-4 契约行：``ANSWER[<qid>]=<value>`` 与 ``answer:`` 行同判——
            # 都是模型显式写下的交付。守卫拦它只会让非 flag 题在收工门口
            # 撞满三次拒收后交白卷；solved 的权威仍在平台裁决。
            self.allowed += 1
            return None, False, []
        return None, True, echo_only

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

    def _giveup_answer(self, raw_input: str, echo_only: list[str] | None = None) -> str:
        """拒满放行时从 summary 原文里取最可信的 flag 形状候选。

        放行这一次不是「通过」，只是不再撞墙；但如果 summary 里本来就有一个
        非占位的 flag 形状串，不记下来就等于交白卷（实测有整条 run 因为这里
        返回 ``None`` 而零提交）。优先取有工具输出证据支持、且不是自回声的串。

        **扫描用窄集 ``_FLAG_RE``，不是宽集 ``CANDIDATE_RE``。** 这条路径的产物会
        被上游写成主答案并交给平台提交，属于"判分件"；绑宽集等于把 summary 里的
        ``div{margin:0}`` / ``style{color:red}`` 这类配置与模板串当 flag 交上去，
        白耗一次提交机会。窄集也是 accept 路径（``_evaluate_policy``）与
        ``EvidenceLedger`` 记录证据用的那条——两条正则分叉时，守卫会认出一个证据链
        永远记录不到的答案。

        已知残余：无标点的 ``div{margin}`` 这类 ``word{word}`` 形态仍能过窄集，
        与 accept 路径共享同一处代价（见 ``flag_extract.FLAG_RE`` 的 docstring）。

        这里刻意不调用 ``evidence.reject()``：放行路径不该再留下拒绝记录。
        """
        seen: list[str] = []
        for cand in _FLAG_RE.findall(raw_input or ""):
            if is_placeholder(cand) or is_code_template(cand):
                continue
            if cand not in seen:
                seen.append(cand)
        if not seen:
            return ""
        echoed = set(echo_only or [])
        if self.evidence is not None:
            for cand in seen:
                if cand not in echoed and self.evidence.supports(cand):
                    return cand
        for cand in seen:
            if cand not in echoed:
                return cand
        return seen[0]

    def _after_probe(
        self,
        echo_only: list[str] | None = None,
        raw_input: str = "",
    ) -> dict[str, Any] | None:
        if self._probe_result:
            if self.success is not None and not getattr(self.success, "solved", False):
                self.success.mark("checker", "finish guard probe")
            self.allowed += 1
            return None
        if self.refusals >= _MAX_REFUSALS:
            if self.success is not None and not getattr(self.success, "solved", False):
                best = self._giveup_answer(raw_input, echo_only)
                if best:
                    self.success.observe_answer(best, source="finish_guard_giveup")
            self.allowed += 1
            self.gave_up = True
            return None
        self.refusals += 1
        base = _echo_refusal(echo_only) if echo_only else dict(_REFUSAL)
        if self.refusals >= 2:
            # 第 1 次已经把「回去拿 flag」说清楚了；第 2 次起必须要求换向，
            # 否则模型只会把同一份白卷再交一次。
            base["error"] = base["error"] + _REDIRECT
        return base

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
        refusal, needs_probe, echo_only = self._evaluate_policy(raw_input)
        if refusal is not None or not needs_probe:
            return refusal
        if self.checker is None:
            return self._after_probe(echo_only, raw_input)
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
        return self._after_probe(echo_only, raw_input)

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
        refusal, needs_probe, echo_only = self._evaluate_policy(raw_input)
        if refusal is not None or not needs_probe:
            return refusal
        return self._after_probe(echo_only, raw_input)

    def stats(self) -> dict[str, int]:
        """收工守卫的计数快照，供 result.json 事后归因。"""
        return {
            "refusals": self.refusals,
            "allowed": self.allowed,
            "gave_up": int(self.gave_up),
        }


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
