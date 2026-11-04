"""收工时自动提交：把"解出来"和"交上去"合并成一个不可分的动作。

## 为什么这件事必须在工具里做

昨夜 7 题里 5 题的记录是 ``submissions: null``——agent 一次都没提交。
SAMPLE-001 的日志最典型：第 24 秒就拿到了 slug
``b5efdaae09d5900be5331f45e20180de``，然后直接调 ``finish_scan`` 宣布完成。

原因不是模型笨，是**"解题"和"得分"在 CTFY 里是两个独立动作**，中间隔着一次
可能忘记做的 HTTP 调用。prompt 里写"记得提交"没用——和枚举收敛、收工前三问
是同一个教训：写在 prompt 里的自我检查会随轮次衰减，**代码里的不会**。

父进程事后补交也不是办法：它得先猜哪个字符串是答案（正则 + 噪声排除），
猜错了就是零分；而且整个补交要等子进程退出后才开始，白白吃掉答案宽限的
20 秒。真正知道答案的是刚写完 summary 的模型。

## 为什么提交结果要写回 summary

``finish_scan`` 的返回值就是 agent 的最后一次观测。把平台裁决原样放回去，
这一轮的日志里就有"平台说这个答案是错的"这样一条硬证据，
之后的复盘不必再从 HTTP 状态码猜发生了什么。
"""

from __future__ import annotations

import json
import os
import re
import threading
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool

#: 候选答案形态。与 ctf_goal.txt 的定义、平台判分口径一致。
#: 顺序即优先级：显式 flag 标记优先于裸 hex（SAMPLE-001 的 slug 是 32 位 hex）。
_CAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    # 前缀与 `flag_extract.FLAG_RE` 保持一致：CTFY 的交付示例就是 `ctfy{...}`，
    # 少一个前缀等于把合法答案排除在候选之外。
    re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}"),
    # 显式标注的答案。``seeded`` 题的答案常在实例创建时下发，形状任意
    # （不是 FLAG{...}，也不一定是 hex），只靠前两条正则永远抽不到。
    # 这条只认模型自己写的 ``answer: xxx`` / ``flag=xxx``，不猜自由文本；
    # 噪声由 verify-answer 预检兜住——判错的候选不会消耗提交次数。
    re.compile(
        r"""(?im)^[\s>*`-]*(?:final\s+)?(?:answer|flag)\s*[:=]\s*[`'"]?"""
        r"""([^\s`'"]{6,200})"""
    ),
    re.compile(r"\b[0-9a-fA-F]{32}\b"),
    re.compile(r"\b[0-9a-fA-F]{40,64}\b"),
)

#: 单实例里可能有多个待答 question，每个候选都试一遍，但别无限放大请求量。
_MAX_CANDIDATES = 6

# urllib 的 timeout 只吃**单个浮点数**，不是 requests 那样的 (connect, read)
# 元组。传元组会抛 TypeError，而 `except Exception` 会把它吞成"没有 question"
# ——这个 bug 让 SAMPLE-001 的 autosubmit 静默失效了两轮，日志只说
# "本题没有 flag 类 question"，看不出是参数类型错了。
_TIMEOUT = 45


class AutoSubmitter:
    """在 ``finish_scan`` 里把答案交给平台，并把裁决贴回 summary。"""

    def __init__(
        self,
        platform: str,
        instance: str,
        token: str,
        success: Any = None,
    ) -> None:
        self.platform = platform.rstrip("/")
        self.instance = instance
        self.token = token
        # Optional structured-success ledger.  Only direct JSON verdicts from
        # calls this object made are ever reported to it.
        self.success = success
        self.attempts = 0
        self.correct: list[str] = []
        self.answers_tried: list[dict[str, Any]] = []
        self.last_error: str | None = None
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- HTTP
    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """发一次 JSON POST，永不抛异常。

        Args:
            path: 相对平台的路径。
            body: 请求体。

        Returns:
            平台响应 JSON；任何失败都折算成 ``{"error": ...}``。
        """
        req = urllib.request.Request(
            f"{self.platform}{path}",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                return json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read()[:180].decode(errors='replace')}"}
        except Exception as e:  # noqa: BLE001 — 提交失败不能让收工本身失败
            return {"error": f"{type(e).__name__}: {e}"}

    def _verify(self, qid: str, answer: str) -> dict[str, Any]:
        """Ask the oracle-mode grader without spending a submission attempt.

        ``POST /api/v1/instances/{id}/verify-answer`` is documented in the
        platform openapi as "same grader as /submissions but writes no
        submission record", and it does not consume ``attempts_remaining``.
        A single finish can otherwise spend six candidates x N questions from
        a per-question cap, so probing here first keeps the cap for answers
        that are worth recording.

        Args:
            qid: question id.
            answer: the candidate string.

        Returns:
            ``{"correct": bool, "question_id": str}``, or ``{}`` when the
            endpoint is unavailable -- callers then fall back to the old
            submit-everything behaviour.
        """
        body = self._post(
            f"/api/v1/instances/{self.instance}/verify-answer",
            {"question_id": qid, "answer": answer},
        )
        if "error" in body or "correct" not in body:
            return {}
        if self.success is not None:
            self.success.observe_structured(
                body, source="platform_verify", answer=answer
            )
        return body

    def probe_checkers(self) -> bool:
        """Ask the platform's sidecar checker whether this instance is solved.

        Only ``mode == "checker"`` questions are probed.  The verdict must be
        the direct JSON body of our own ``POST /check``; a checker's page
        saying "passed" is not this.  This is the recovery path's last chance
        to notice a solve before the run is restarted.

        Returns:
            True when a direct checker response says ``passed: true``.
        """
        questions = self._questions()
        for q in questions:
            if q.get("mode") != "checker":
                continue
            qid = q.get("id")
            if not qid:
                continue
            body = self._post(
                f"/api/v1/instances/{self.instance}/check",
                {"question_id": qid},
            )
            if "error" in body:
                self.last_error = str(body["error"])
                continue
            if body.get("passed") is True:
                if self.success is not None:
                    self.success.observe_structured(body, source="checker")
                return True
        return False

    def _questions(self) -> list[dict[str, Any]]:
        """拉当前实例的 question 列表。

        失败时返回空列表并把原因记到 ``self.last_error``：**不能静默**。
        早先这里直接 ``except Exception: return []``，结果 timeout 参数类型
        写错（传了元组）这种硬 bug 在日志里只表现为"本题没有 flag 类
        question"，排查了两轮才定位。

        Returns:
            question 列表；拿不到时返回空列表。
        """
        self.last_error = None
        req = urllib.request.Request(
            f"{self.platform}/api/v1/instances/{self.instance}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                return json.loads(resp.read().decode() or "{}").get("questions") or []
        except Exception as e:  # noqa: BLE001
            self.last_error = f"{type(e).__name__}: {e}"
            return []

    # ---------------------------------------------------------------- 候选
    @staticmethod
    def candidates(text: str) -> list[str]:
        """从 finish_scan 的 summary 里抽答案候选。

        去重并保序：显式 ``FLAG{...}`` 排在裸 hex 之前，因为后者常是哈希、
        链接片段或 session id，误交会白白消耗一次提交。

        Args:
            text: 原始参数字符串。

        Returns:
            去重后的候选列表，最多 :data:`_MAX_CANDIDATES` 个。
        """
        out: list[str] = []
        for pat in _CAND_PATTERNS:
            for m in pat.finditer(text or ""):
                # 带捕获组的模式只取组内容（标签本身不是答案）。
                v = m.group(1) if pat.groups else m.group(0)
                v = v.rstrip(".,;:)]")
                if v and v not in out:
                    out.append(v)
        return out[:_MAX_CANDIDATES]

    # ---------------------------------------------------------------- 主流程
    def submit(self, raw_input: str) -> dict[str, Any]:
        """把 summary 里的候选逐个交给平台。

        Args:
            raw_input: finish_scan 的原始参数（JSON 字符串）。

        Returns:
            ``{"tried": [...], "correct": [...]}``，供调用方拼进 summary。
        """
        cands = self.candidates(raw_input)
        if not cands:
            return {"tried": [], "correct": [], "note": "summary 里没有任何答案候选"}

        questions = self._questions()
        # 只按 mode 筛，**绝不**按 answered_correctly 筛。
        #
        # 这个字段看起来正好是"还没答对的题"，但它不可信：实例一创建就可能是
        # true（平台把题库历史带下来）。我第一版就是用它做过滤，结果
        # SAMPLE-001 收工时打印 "NOT SUBMITTED: 没有待答的 question" ——
        # 明明 slug 就在 summary 里，却被自己的过滤器挡在门外。
        #
        # 实测证据（直接打平台 API）：
        #   answered_correctly=true 时提交 deadbeef... → correct:false
        #   answered_correctly=true 时提交真 slug     → correct:true
        # 也就是说这个标记**不拦提交**，拿它当闸门纯属自伤。
        # ``seeded`` 是第三种会走 /submissions 的模式：答案在实例创建时下发
        # （sample_chals 的 C2O-ALIST-002 就是它）。旧白名单只认 dynamic/static，
        # 这类题会被判成"只有非 flag 类 question"，答案是静默丢掉的。
        pending = [
            q for q in questions
            if q.get("mode") in ("dynamic", "static", "seeded")
        ]
        if not pending:
            # 区分两种"没得投"：拿不到列表（错误）vs 只有 checker 题（正常）。
            if self.last_error:
                why = f"拉 question 列表失败：{self.last_error}"
            elif questions:
                why = f"本题只有非 flag 类 question：{[q.get('id') for q in questions]}"
            else:
                why = "本题没有 flag 类 question"
            return {"tried": [], "correct": [], "note": why}

        tried: list[dict[str, Any]] = []
        correct: list[str] = []
        skipped: list[str] = []
        with self._lock:
            for q in pending:
                qid = q["id"]
                # ``attempts_remaining`` 是平台按 question 记账的剩余次数。为 0
                # 时继续打只会拿到拒绝，白白在日志里制造"我试过了"的假象。
                left = q.get("attempts_remaining")
                if isinstance(left, int) and left <= 0:
                    skipped.append(f"{qid}: attempts_remaining=0")
                    continue
                for ans in cands:
                    # 先问不记账的判分器。它正确 → 只写一条提交记录；
                    # 它不可用（旧平台 / 网络抖动）→ 退回直接提交。
                    probe = self._verify(qid, ans)
                    if probe and not probe.get("correct"):
                        tried.append({"qid": qid, "answer": ans, "correct": False,
                                      "verified": True})
                        continue
                    self.attempts += 1
                    res = self._post(
                        "/api/v1/submissions",
                        {
                            "instance_id": self.instance,
                            "question_id": qid,
                            "answer": ans,
                        },
                    )
                    tried.append({"qid": qid, "answer": ans, **{
                        k: res.get(k) for k in ("correct", "solve_rank", "detail", "error")
                    }})
                    if res.get("correct"):
                        if self.success is not None:
                            self.success.observe_structured(
                                res, source="platform_submit", answer=ans
                            )
                        correct.append(f"{qid}={ans}")
                        break  # 这个 question 已经有了正确答案，换下一个 question
                    if isinstance(left, int):
                        left -= 1
                        if left <= 0:
                            skipped.append(f"{qid}: attempts_remaining exhausted")
                            break
        self.answers_tried.extend(tried)
        self.correct.extend(correct)
        verdict: dict[str, Any] = {"tried": tried, "correct": correct}
        if skipped:
            verdict["skipped"] = skipped
        self._persist(verdict)
        return verdict

    def _persist(self, verdict: dict[str, Any]) -> None:
        """把裁决写入 sidecar，供父进程回读。

        ## 为什么必须落盘，而不是只交给父进程补交

        run 结束后运行时框架会销毁实例。父进程那套"事后解析日志、再提交"
        的兜底于是撞上 ``instance_not_found``——SAMPLE-001 明明在收工时
        已经 ``ACCEPTED: slug=... flag=...``，父进程却判 FAIL。

        这里是**唯一一次**在实例还活着时提交的机会，结果必须落盘。
        路径经环境变量传入，默认不写（非评测场景无父进程可回读）。
        """
        path = os.environ.get("CTF_SUBMIT_PATH")
        if not path:
            return
        try:
            tmp = f"{path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(verdict, fh, ensure_ascii=False)
            os.replace(tmp, path)  # 原子替换：父进程随时读都是完整 JSON
        except OSError:
            pass

    def decorate(self, summary: str, verdict: dict[str, Any]) -> str:
        """把平台裁决附到 summary 末尾，让最终观测里留下硬证据。

        Args:
            summary: 模型写的原 summary。
            verdict: :meth:`submit` 的返回值。

        Returns:
            追加了裁决段的 summary。
        """
        lines = ["", "", "--- platform submission ---"]
        if verdict.get("correct"):
            lines.append(f"ACCEPTED: {', '.join(verdict['correct'])}")
        elif verdict.get("tried"):
            lines.append(
                f"REJECTED: 试了 {len(verdict['tried'])} 个候选，平台都判错。"
                "答案可能是别的形态，回目标侧再取一次。"
            )
        else:
            lines.append(f"NOT SUBMITTED: {verdict.get('note', '无候选')}")
        return summary + "\n".join(lines)


def install(
    platform: str,
    instance: str,
    token: str,
    max_refusals: int = 0,
    success: Any = None,
) -> AutoSubmitter:
    """挂到 ``finish_scan`` 上：允许收工前先提交，答错则拒绝。

    与另外几个守卫同一手法——包 ``factory._with_bounded_result``，不动 vendor。

    Args:
        platform: 平台根地址。
        instance: 实例 id。
        token: 队伍 token。
        max_refusals: 连续答错几次后放行。默认 0 表示不因"答错"而拒绝，
            只做提交并把裁决贴回 summary——夜里跑批时拒绝会白烧轮次。
            单独调参跑时可以提高，让 agent 不得不回去重取。

    Returns:
        已安装的实例，供运行后统计。
    """
    from strix.agents import factory

    sub = AutoSubmitter(platform, instance, token, success=success)
    original = factory._with_bounded_result
    refusal_budget = {"left": max_refusals}

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, "name", "") != "finish_scan":
            return tool
        if getattr(tool, "_ctf_autosubmit", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            import asyncio

            # 提交是阻塞 HTTP，放到线程里，别卡住 agent 的事件循环。
            verdict = await asyncio.to_thread(sub.submit, raw_input or "")
            if not verdict.get("correct") and verdict.get("tried") and refusal_budget["left"] > 0:
                refusal_budget["left"] -= 1
                return {
                    "success": False,
                    "error": (
                        "REFUSED: the platform rejected every answer candidate in your "
                        "summary. The run is not complete — finish_scan ends everything. "
                        "Go back, re-extract the answer from the target, and make sure the "
                        "exact string (case, braces, length) is in your next summary."
                    ),
                }
            result = await inner(ctx, raw_input)
            # 把裁决塞进最终观测：日志里就有一条"平台说对/错"的硬证据。
            if isinstance(result, str):
                return sub.decorate(result, verdict)
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_autosubmit = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return sub
