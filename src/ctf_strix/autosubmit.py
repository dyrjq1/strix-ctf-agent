"""收工时自动提交：把"解出来"和"交上去"合并成一个不可分的动作。

## 为什么这件事必须在工具里做

昨夜 7 题里 5 题的记录是 ``submissions: null``——agent 一次都没提交。
一次附件题 run 的日志最典型：第 24 秒就拿到了 slug
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

from ctf_strix.tool_notes import append_note

import asyncio
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from ctf_strix.flag_extract import (
    CANDIDATE_RE,
    explicit_answer_values,
    is_placeholder,
    per_question_answers,
)
from ctf_strix.success_stop import answer_verdict, check_verdict, question_correct

if TYPE_CHECKING:
    from agents import FunctionTool

#: 候选答案形态。与 ctf_goal.txt 的定义、平台判分口径一致。
#: 顺序即优先级：显式 flag 标记 > 显式 ``answer:`` 行 > 裸 hex（一次
#: run 的 slug 是 32 位 hex）。显式行不是正则条目——``raw_input`` 是 JSON
#: 参数串，值内换行是 ``\n`` 字面量，行锚定正则必须先解码再扫（见
#: :func:`ctf_strix.flag_extract.explicit_answer_values`）——所以它在
#: ``candidates()`` 里以函数调用插在 :data:`CANDIDATE_RE` 与 hex 之间。
_CAND_PATTERNS: tuple[re.Pattern[str], ...] = (
    # 与 `flag_extract.CANDIDATE_RE` 同源：CTFY 的交付示例就是 `ctfy{…}`，
    # 少一个前缀等于把合法答案排除在候选之外；正则本体不再复制一份。
    CANDIDATE_RE,
)

#: 裸 hex：32 位（slug 常见长度）与 40–64 位（sha1/sha256）。排最后：
#: 哈希、链接片段、session id 也长这样，误交白耗一次提交机会。
_HEX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[0-9a-fA-F]{32}\b"),
    re.compile(r"\b[0-9a-fA-F]{40,64}\b"),
)

#: 单实例里可能有多个待答 question，每个候选都试一遍，但别无限放大请求量。
_MAX_CANDIDATES = 6

#: QA 题的 question 元数据来自 task.json，没有 ``attempts_remaining``。
#: 平台对 qa 每题的作答上限是 3；不自己记账就会把 6 个候选一次打光，
#: 正确解排在第 4 位以后就永远交不上，日志里还看不出发生过什么。
_QA_ATTEMPT_CAP = 3


def fits_choices(answer: Any, mode: str, choices: list[str]) -> bool:
    """答案是否落在平台给出的 ``choices`` 里（CTFY-0002 v2 逐字规则）。

    单选：值必须**逐字**等于某个 choice（大小写敏感，``A`` 不是 ``a``）。
    多选：允许 list，或按逗号/空白切分的字符串；每部分都必须属于 choices。
    没有 choices 的题型（dynamic/static/checker）一律放行。

    Args:
        answer: 候选答案（字符串 / list）。
        mode: 平台 question mode。
        choices: 平台给出的可选值列表。

    Returns:
        是否符合；无 choices 恒 True。
    """
    if not choices:
        return True
    if isinstance(answer, (list, tuple, set)):
        parts = [str(x).strip() for x in answer if str(x).strip()]
    else:
        text = str(answer if answer is not None else "").strip()
        if not text:
            return False
        if str(mode or "").strip().lower() in ("multi_select", "multi-select"):
            parts = [p for p in re.split(r"[,\s]+", text) if p]
        else:
            parts = [text]
    return bool(parts) and all(part in choices for part in parts)

#: 平台对每题的作答上限。实例式 question 的元数据里通常**没有**
#: ``attempts_remaining``，旧代码把"没这个字段"当成"不限次数"，于是一道
#: 题的 6 个候选会一次打光——第 6 次起平台直接拒绝，而真正正确的答案如果
#: 排在第 6 位就没机会交。按平台上限记账，超出的候选写进 ``skipped``，
#: 日志里能看出"不是没答案，是次数用完了"。
_PLATFORM_ATTEMPT_CAP = 5

# urllib 的 timeout 只吃**单个浮点数**，不是 requests 那样的 (connect, read)
# 元组。传元组会抛 TypeError，而 `except Exception` 会把它吞成"没有 question"
# ——这个 bug 让一次 run 的 autosubmit 静默失效了两轮，日志只说
# "本题没有 flag 类 question"，看不出是参数类型错了。
_TIMEOUT = 45

#: 会话暂停（competition_paused）在轮内愿意睡的最长秒数（G4，协议 §4）。
#: 比这更长的暂停说明下一轮才可能有效——继续睡只是白烧墙钟预算，记
#: ``last_error`` 交给 rounds 补救；短暂停（赛程切换的间隙）睡过去再重试
#: 一次，提交就不再静默失败。
_PAUSE_WAIT_MAX_S = 300.0


def _pause_wait_seconds(raw: str, code: int) -> float | None:
    """从 403 响应体里取 competition_paused 该睡的秒数（G4，协议 §4）。

    403 + ``competition_paused`` 时平台会带 ``next_session_starts_at``
    （ISO8601）或 ``retry_after_s``：正确行为是睡到那时再试一次，而不是
    记个错继续走——会话中断的窗口（赛程按 session 切）里提交会静默失败。

    Args:
        raw: 响应体文本（调用方先读掉，错误信息里还要用）。
        code: HTTP 状态码，非 403 直接返回 None。

    Returns:
        该睡的秒数；不是暂停响应、时间解析不了、或暂停超出
        :data:`_PAUSE_WAIT_MAX_S` 时返回 ``None``（调用方按普通失败走）。
    """
    if code != 403 or "competition_paused" not in (raw or ""):
        return None
    try:
        body = json.loads(raw or "{}")
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    delay: float | None = None
    retry = body.get("retry_after_s")
    if isinstance(retry, (int, float)) and not isinstance(retry, bool):
        delay = float(retry)
    else:
        starts = str(body.get("next_session_starts_at") or "")
        if starts:
            try:
                when = datetime.fromisoformat(starts.replace("Z", "+00:00"))
                delay = (when - datetime.now(timezone.utc)).total_seconds()
            except ValueError:
                return None
    if delay is None or delay < 0 or delay > _PAUSE_WAIT_MAX_S:
        return None
    return delay


class AutoSubmitter:
    """在 ``finish_scan`` 里把答案交给平台，并把裁决贴回 summary。"""

    def __init__(
        self,
        platform: str,
        instance: str,
        token: str,
        success: Any = None,
        fallback_question_ids: list[str] | None = None,
        fallback_question_modes: dict[str, str] | None = None,
        run_mode: str = "instance",
        challenge_id: str = "",
        competition_id: str = "",
    ) -> None:
        self.platform = platform.rstrip("/")
        self.instance = instance
        self.token = token
        #: ``qa`` 题没有实例，答案按 ``(challenge_id, competition_id)`` 记账，
        #: 走 ``POST /api/v1/qa/submissions``。
        self.run_mode = str(run_mode or "instance").strip().lower()
        self.challenge_id = str(challenge_id or "").strip()
        self.competition_id = str(competition_id or "").strip()
        # Optional structured-success ledger.  Only direct JSON verdicts from
        # calls this object made are ever reported to it.
        self.success = success
        #: question ids from task.json, used only when the metadata GET is
        #: forbidden.  Empty means "do not guess".
        self.fallback_question_ids = list(fallback_question_ids or [])
        #: declared mode per fallback id.  Without this a 403 fallback would
        #: relabel dynamic questions as checker questions.
        self.fallback_question_modes = dict(fallback_question_modes or {})
        self.attempts = 0
        self.correct: list[str] = []
        self.answers_tried: list[dict[str, Any]] = []
        self.last_error: str | None = None
        self._lock = threading.Lock()

    @property
    def is_qa(self) -> bool:
        """是否走 QA 提交通道（无实例，按 challenge/competition 记账）。

        只认显式的 ``run_mode == "qa"``。instance 模式下 ``instance`` 为空是
        配置异常，不能静默当成 qa —— 那只是把一个错请求换到另一个通道上，
        失败起来同样看不出根因。
        """
        return self.run_mode == "qa"

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
            raw = e.read()[:180].decode(errors="replace")
            # G4：会话暂停睡过去重试一次，而不是把整段窗口内的提交静默
            # 折算成错误。只在暂停可预期（≤上限）时睡。
            wait = _pause_wait_seconds(raw, e.code)
            if wait is not None and wait > 0:
                time.sleep(wait)
                try:
                    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                        return json.loads(resp.read().decode() or "{}")
                except urllib.error.HTTPError as e2:
                    raw2 = e2.read()[:180].decode(errors="replace")
                    return {"error": f"HTTP {e2.code}: {raw2}"}
                except Exception as e2:  # noqa: BLE001 — 重试失败不能让收工失败
                    return {"error": f"{type(e2).__name__}: {e2}"}
            return {"error": f"HTTP {e.code}: {raw}"}
        except Exception as e:  # noqa: BLE001 — 提交失败不能让收工本身失败
            return {"error": f"{type(e).__name__}: {e}"}

    def _verify(
        self, qid: str, answer: str, *, multiple: bool = False
    ) -> dict[str, Any] | None:
        """Ask the oracle-mode grader without spending a submission attempt.

        ``POST /api/v1/instances/{id}/verify-answer`` is documented in the
        platform openapi as "same grader as /submissions but writes no
        submission record", and it does not consume ``attempts_remaining``.
        A single finish can otherwise spend six candidates x N questions from
        a per-question cap, so probing here first keeps the cap for answers
        that are worth recording.

        ``verify-answer`` has no ``challenge_fully_solved`` field, so for a
        multi-question challenge it proves only one question.  It therefore
        never marks the run solved there; the later ``/submissions`` response
        (which does carry the flag) is what may stop the run.

        Args:
            qid: question id.
            answer: the candidate string.
            multiple: whether this run has more than one question.

        Returns:
            ``{"correct": bool, "question_id": str}``, or ``{}`` when the
            endpoint is unavailable -- callers then fall back to the old
            submit-everything behaviour.
        """
        if self.is_qa:
            # QA 没有实例路径下的 verify-answer。唯一的判分器就是提交本身，
            # 而它会消耗一次答题机会。
            return None
        body = self._post(
            f"/api/v1/instances/{self.instance}/verify-answer",
            {"question_id": qid, "answer": answer},
        )
        if "error" in body or "correct" not in body:
            return {}
        if self.success is not None and answer_verdict(
            body, qid, multiple=multiple
        ):
            self.success.mark(
                "platform_verify", "correct=true", answer=answer
            )
        return body

    def probe_checkers(
        self,
        *,
        all_questions: bool = False,
        question_ids: list[str] | None = None,
        known_question_ids: list[str] | None = None,
        question_modes: dict[str, str] | None = None,
    ) -> bool:
        """Ask the platform's sidecar checker whether this instance is solved.

        Questions are selected by ``mode in ("", "checker")``; ``dynamic``,
        ``static`` and ``seeded`` are answered through ``/submissions`` and are
        deliberately skipped here.  An empty mode is included because a measured
        task declared ``""`` while still grading a side effect through ``/check``.

        A result only counts when it is the direct JSON body of our own
        ``POST /check`` **and** it names the question that request asked about,
        is not timed out, and -- for a multi-question challenge -- reports
        ``challenge_fully_solved: true``.  A checker's page saying "passed" is
        never enough.

        Args:
            all_questions: legacy switch kept for callers; selection is now
                always ``mode in ("", "checker")``.
            question_ids: explicit ids to probe.  The entrypoint already has
                them in ``task.json``, so this avoids one metadata GET.
            known_question_ids: every id in this run, used to decide whether a
                ``challenge_fully_solved`` flag is required.
            question_modes: declared mode per question id.  With explicit ids,
                this keeps ``dynamic``/``static``/``seeded`` out of ``/check``.

        Returns:
            True when a validated checker verdict says the run is complete.
        """
        if question_ids is not None:
            modes = question_modes or {}
            questions = [
                {"id": qid, "mode": modes.get(qid, "")}
                for qid in question_ids
                if qid
            ]
        else:
            questions = self._questions()
        probe_ids = [str(q.get("id") or "") for q in questions if q.get("id")]
        known = {
            str(qid).strip()
            for qid in (known_question_ids or probe_ids)
            if str(qid).strip()
        }
        multiple = len(known) > 1
        for q in questions:
            mode = str(q.get("mode") or "").strip().lower()
            if mode not in ("", "checker"):
                continue
            qid = str(q.get("id") or "").strip()
            if not qid or qid not in known:
                continue
            body = self._post(
                f"/api/v1/instances/{self.instance}/check",
                {"question_id": qid},
            )
            if "error" in body:
                self.last_error = str(body["error"])
                continue
            if check_verdict(body, qid, multiple=multiple):
                if self.success is not None:
                    self.success.mark("checker", "passed=true")
                return True
        return False

    async def probe_checkers_async(
        self,
        *,
        all_questions: bool = False,
        question_ids: list[str] | None = None,
        known_question_ids: list[str] | None = None,
        question_modes: dict[str, str] | None = None,
    ) -> bool:
        """Run :meth:`probe_checkers` off the event loop.

        The finish guard is awaited from inside the runner; a blocking
        ``urlopen`` there would stall every other agent task.  One worker
        thread per call is fine because :class:`CheckerProbe` caches the result
        for the rest of the run.

        Returns:
            The same verdict as :meth:`probe_checkers`.
        """
        return await asyncio.to_thread(
            self.probe_checkers,
            all_questions=all_questions,
            question_ids=question_ids,
            known_question_ids=known_question_ids,
            question_modes=question_modes,
        )

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
        if self.is_qa:
            # QA 题没有实例可查。旧路径会 GET ``/api/v1/instances//``，
            # 404 被下面的 except 吞成空列表 —— 提交链就此静默断开。
            return [
                {
                    "id": qid,
                    "mode": self.fallback_question_modes.get(qid) or "dynamic",
                }
                for qid in self.fallback_question_ids
                if qid
            ]
        req = urllib.request.Request(
            f"{self.platform}/api/v1/instances/{self.instance}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                return json.loads(resp.read().decode() or "{}").get("questions") or []
        except urllib.error.HTTPError as e:
            raw = e.read()[:180].decode(errors="replace")
            # G4：会话暂停与 _post 同款——睡过去重试一次。
            wait = _pause_wait_seconds(raw, e.code)
            if wait is not None and wait > 0:
                time.sleep(wait)
                try:
                    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                        return (
                            json.loads(resp.read().decode() or "{}").get("questions")
                            or []
                        )
                except Exception:  # noqa: BLE001 — 重试失败走原失败路径
                    pass
            self.last_error = f"HTTP {e.code}: {raw}"
            if e.code in (401, 403) and self.fallback_question_ids:
                return [
                    {
                        "id": qid,
                        "mode": self.fallback_question_modes.get(qid, ""),
                    }
                    for qid in self.fallback_question_ids
                    if qid
                ]
            return []
        except Exception as e:  # noqa: BLE001
            self.last_error = f"{type(e).__name__}: {e}"
            return []

    def _questions_from_challenge(self) -> list[dict[str, Any]]:
        """G1：从 challenge 端点读 question 列表（答对后解锁的 gated 题在这）。

        实例端点的 ``questions`` 只在拉列表时反映当下可见集合；协议 §2 要求
        ``gated_questions > 0`` 时每答对一题就重读 ``GET /api/v1/challenges/{id}``
        ——新解锁的问题只暴露在 challenge 端点，轮内看不到就得多烧一整轮靠
        平台 rounds 补救（平台试跑 SAMPLE-001 实证：flag 题锁在 slug 后）。

        刷新结果**不**自动进提交循环：本轮候选里没有新问题的答案，拿旧候选
        打新题只会烧提交次数。它只进 ``verdict["unlocked"]`` 与 decorate 的
        回写——让模型看见「还有题、继续解」。

        Returns:
            challenge 端点的 question 列表；无 challenge_id / qa / 任何失败
            返回空列表（记录 ``last_error``，不影响提交链）。
        """
        if self.is_qa or not self.challenge_id:
            return []
        req = urllib.request.Request(
            f"{self.platform}/api/v1/challenges/{self.challenge_id}",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                body = json.loads(resp.read().decode() or "{}")
                return body.get("questions") or []
        except Exception as e:  # noqa: BLE001 — 刷新失败不能打断提交链
            self.last_error = f"challenge refresh: {type(e).__name__}: {e}"
            return []

    # ---------------------------------------------------------------- 候选
    @staticmethod
    def candidates(text: str) -> list[str]:
        """从 finish_scan 的 summary 里抽答案候选。

        去重并保序：显式 ``FLAG{...}`` > 显式 ``answer:`` 行 > 裸 hex，
        因为 hex 常是哈希、链接片段或 session id，误交会白白消耗一次提交。

        Args:
            text: 原始参数字符串（finish_scan 的 raw_input，JSON 串）。

        Returns:
            去重后的候选列表，最多 :data:`_MAX_CANDIDATES` 个。
        """
        out: list[str] = []

        def _add(value: str) -> None:
            v = (value or "").rstrip(".,;:)]")
            # 占位符在提交前最后再挡一次：2026-11-06 就是它把一道不可能
            # 解出的题判成了 solved。markdown 装饰（``**FLAG{...}**``）要
            # 剥一层再判，因为 ``is_placeholder`` 要求前缀在首位。
            if v and not is_placeholder(v.strip("*_`#> ")) and v not in out:
                out.append(v)

        for pat in _CAND_PATTERNS:
            for m in pat.finditer(text or ""):
                _add(m.group(0))
        # 显式标注的答案：``seeded`` / slug 型题答案形状任意（不是
        # FLAG{...}，也不一定是 hex），只靠正则永远抽不到。这条只认模型
        # 自己写的 ``answer: xxx`` / ``flag=xxx``，不猜自由文本；噪声由
        # verify-answer 预检兜住——判错的候选不会消耗提交次数。行锚定
        # 正则扫不了 JSON 参数串，解码逻辑在 :func:`explicit_answer_values`。
        for v in explicit_answer_values(text):
            _add(v)
        for pat in _HEX_PATTERNS:
            for m in pat.finditer(text or ""):
                _add(m.group(0))
        return out[:_MAX_CANDIDATES]

    # ---------------------------------------------------------------- 主流程
    def submit(self, raw_input: str) -> dict[str, Any]:
        """把 summary 里的候选逐个交给平台。

        Args:
            raw_input: finish_scan 的原始参数（JSON 字符串）。

        Returns:
            ``{"tried": [...], "correct": [...]}``，供调用方拼进 summary。
        """
        if not self.is_qa and not str(self.instance or "").strip():
            # instance 模式没有 instance id 是配置错，不是 qa 题。
            return {
                "tried": [],
                "correct": [],
                "note": "instance mode without instance_id",
            }
        if self.is_qa and not (self.challenge_id and self.competition_id):
            # 请求体缺一不可；发出去只会换回 422，看起来像平台故障。
            return {
                "tried": [],
                "correct": [],
                "note": "qa 模式缺少 challenge_id/competition_id",
            }
        cands = self.candidates(raw_input)
        # B-4 契约行：``ANSWER[<qid>]=<value>`` 带 qid，是 checker/counter 类
        # 非 flag 题答案唯一的交付通道（平台实测：模型把答案写进终稿，旧码
        # 却在门口以「没有答案候选」拒收，整题零提交判负）。契约行存在时
        # 即使宽集候选为空也必须进提交循环。
        mapped = per_question_answers(raw_input)
        questions = self._questions()
        # 只按 mode 筛，**绝不**按 answered_correctly 筛。
        #
        # 这个字段看起来正好是"还没答对的题"，但它不可信：实例一创建就可能是
        # true（平台把题库历史带下来）。我第一版就是用它做过滤，结果
        # 一次 run 收工时打印 "NOT SUBMITTED: 没有待答的 question" ——
        # 明明 slug 就在 summary 里，却被自己的过滤器挡在门外。
        #
        # 实测证据（直接打平台 API）：
        #   answered_correctly=true 时提交 deadbeef... → correct:false
        #   answered_correctly=true 时提交真 slug     → correct:true
        # 也就是说这个标记**不拦提交**，拿它当闸门纯属自伤。
        # ``seeded`` 是第三种会走 /submissions 的模式：答案在实例创建时下发
        # （sample_chals 里的一次挑战就是它）。旧白名单只认 dynamic/static，
        # 这类题会被判成"只有非 flag 类 question"，答案是静默丢掉的。
        pending = [
            q for q in questions
            # single_select / multi_select 是 CTFY-0002 v2 的选择题模式
            # （2026-11-13 平台实测：SAMPLE-020 三问分别为 single_select /
            # multi_select / static）。旧白名单只认三模式，选择题答案会被
            # 静默丢掉——和当初 seeded 被漏掉是同一类断链。
            if q.get("mode") in (
                "dynamic", "static", "seeded", "single_select", "multi_select",
            )
            # B-17：checker 题的交付是靶机副作用（deface / outage / persist），
            # 平台在 POST /instances/{id}/check 里裁决并记 "<checker>"。没有
            # 答案字符串也要给它一次机会——SAMPLE-006 就是这样零提交的。
            or str(q.get("mode") or "") == "checker"
            # 契约行点名的 question 一并入围：counter 类 checker 题仍可能
            # 用"提交值"语义（claimed="3" 实证），映射到的值照交。
            or str(q.get("id") or "") in mapped
        ]
        multiple = len(questions) > 1
        if not pending:
            # 区分两种"没得投"：拿不到列表（错误）vs 只有 checker 题（正常）。
            if self.last_error:
                why = f"拉 question 列表失败：{self.last_error}"
            elif questions:
                why = f"本题只有非 flag 类 question：{[q.get('id') for q in questions]}"
            elif self.is_qa:
                why = "qa 题的 task.json 没有 questions[].id，无法定位要交哪一题"
            else:
                why = "本题没有 flag 类 question"
            return {"tried": [], "correct": [], "note": why}

        # B-26：checker 题的正确答案是"靶机副作用"，本来就没有答案字符串可交。
        # 旧码在拿到 question 列表**之前**就以"没有任何答案候选"返回，/check
        # 永远没被调用——SAMPLE-006 收工时 banner 已篡改、judge 可达，却零交付。
        if (
            not cands
            and not mapped
            and not any(str(q.get("mode") or "") == "checker" for q in pending)
        ):
            return {"tried": [], "correct": [], "note": "summary 里没有任何答案候选"}

        tried: list[dict[str, Any]] = []
        correct: list[str] = []
        #: Last explicit platform answer for "is the whole challenge done?".
        #: ``None`` means the platform never said.
        platform_flag: bool | None = None
        skipped: list[str] = []
        with self._lock:
            for q in pending:
                qid = q["id"]
                # ``attempts_remaining`` 是平台按 question 记账的剩余次数。为 0
                # 时继续打只会拿到拒绝，白白在日志里制造"我试过了"的假象。
                left = q.get("attempts_remaining")
                qa_budget = self.is_qa and not isinstance(left, int)
                if qa_budget:
                    left = _QA_ATTEMPT_CAP
                capped_budget = False
                if not self.is_qa and not isinstance(left, int):
                    # 字段缺失 ≠ 不限次数。平台每题上限是 5，多打只会换来拒绝。
                    left = _PLATFORM_ATTEMPT_CAP
                    capped_budget = True
                if isinstance(left, int) and left <= 0:
                    skipped.append(f"{qid}: attempts_remaining=0")
                    continue
                # 契约行答案优先投。非白名单 mode 的 question 只投契约行答案
                # ——把宽集候选（flag 形状/hex）往 checker 题上打，白耗一次
                # 提交；verify 预检对 checker 类恒 False（平台实测：状态已
                # 满足、答案正确仍返回 False），契约行答案必须绕过预检直接
                # 提交，否则正确答案被预检压在门外。
                # B-17：先走 /check。它对侧车读靶机状态，通过即记账——
                # 值通道对 deface/outage/persist 这类题恒判否（平台流水
                # 2026-10-28 vs 2026-11-13 对照），先交值等于白耗次数。
                if str(q.get("mode") or "") == "checker":
                    body = self._post(
                        f"/api/v1/instances/{self.instance}/check",
                        {"question_id": qid},
                    )
                    if os.environ.get("CTF_SUBMIT_DEBUG"):
                        # 只读观测：checker 判否时唯一能定位"为什么"的原始回执。
                        print(
                            f"[submit] check {qid}: "
                            f"{json.dumps(body, ensure_ascii=False)[:400]}",
                            flush=True,
                        )
                    if "error" not in body and check_verdict(
                        body, qid, multiple=multiple
                    ):
                        correct.append(f"{qid}=<checker>")
                        tried.append({"qid": qid, "answer": "<checker>",
                                      "correct": True, "channel": "check"})
                        if self.success is not None:
                            self.success.mark(
                                "checker", "passed via /check", answer="<checker>"
                            )
                        break
                whitelisted = q.get("mode") in (
                    "dynamic", "static", "seeded", "single_select", "multi_select",
                )
                first = mapped.get(str(qid))
                probe_skip = first is not None and not whitelisted
                q_cands = ([first] if first is not None else []) + (
                    cands if whitelisted else []
                )
                # 选择题：不在 choices 里的候选直接丢弃。平台对越界值返回
                # refused（不计次数但也不得分），发出去只会污染台账。
                q_choices = [str(c) for c in (q.get("choices") or [])]
                if q_choices:
                    q_cands = [
                        a for a in q_cands
                        if fits_choices(a, str(q.get("mode") or ""), q_choices)
                    ]
                for pos, ans in enumerate(q_cands):
                    # 先问不记账的判分器。它正确 → 只写一条提交记录；
                    # 它不可用（旧平台 / 网络抖动）→ 退回直接提交。
                    probe = (
                        None if probe_skip else self._verify(qid, ans, multiple=multiple)
                    )
                    if probe and not probe.get("correct"):
                        tried.append({"qid": qid, "answer": ans, "correct": False,
                                      "verified": True})
                        continue
                    self.attempts += 1
                    if self.is_qa:
                        res = self._post(
                            "/api/v1/qa/submissions",
                            {
                                "challenge_id": self.challenge_id,
                                "competition_id": self.competition_id,
                                "question_id": qid,
                                "answer": ans,
                            },
                        )
                    else:
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
                    if question_correct(res, qid):
                        correct.append(f"{qid}={ans}")
                        flag = res.get("challenge_fully_solved")
                        if flag is True:
                            platform_flag = True
                        elif flag is False:
                            platform_flag = False
                        if answer_verdict(res, qid, multiple=multiple):
                            if self.success is not None:
                                self.success.mark(
                                    "platform_submit", "correct=true", answer=ans
                                )
                        # One right answer ends this question.  On a
                        # multi-question challenge the outer loop moves on to
                        # the next id; trying more candidates for a question
                        # that is already correct only burns attempts.
                        break
                    if res.get("correct"):
                        # The platform said correct but did not name the
                        # question; keep it visible without marking the run.
                        self.last_error = "correct response had no matching question_id"
                        break  # this question already has the right answer
                    if isinstance(left, int):
                        left -= 1
                        if left <= 0:
                            if qa_budget:
                                untried = len(q_cands) - pos - 1
                                skipped.append(
                                    f"{qid}: qa attempt cap {_QA_ATTEMPT_CAP} reached, "
                                    f"{untried} candidates untried"
                                )
                            elif capped_budget:
                                untried = len(q_cands) - pos - 1
                                skipped.append(
                                    f"{qid}: platform attempt cap "
                                    f"{_PLATFORM_ATTEMPT_CAP} reached, "
                                    f"{untried} candidates untried"
                                )
                            else:
                                skipped.append(f"{qid}: attempts_remaining exhausted")
                            break
        unlocked: list[str] = []
        if correct and not self.is_qa and self.challenge_id:
            # G1（协议 §2）：答对过才值得重读 challenge 端点——解锁由「答对」
            # 触发，别在每次 finish 都多打一串请求。
            fresh = self._questions_from_challenge()
            if fresh:
                known = {str(q.get("id") or "") for q in questions}
                unlocked = [
                    str(q.get("id") or "")
                    for q in fresh
                    if q.get("id") and str(q.get("id") or "") not in known
                ]
        self.answers_tried.extend(tried)
        self.correct.extend(correct)
        # A single correct answer on a multi-question challenge is progress,
        # not a complete solve.  The platform's own flag wins when present;
        # otherwise all pending ids answered is the only local evidence.
        if not multiple or platform_flag is True:
            fully_solved = True
        else:
            fully_solved = platform_flag is not False and len(correct) == len(pending)
        if unlocked:
            # 新解锁的问题一个都没答，这轮当然不算完全解出（G1）。
            fully_solved = False
        verdict: dict[str, Any] = {
            "tried": tried,
            "correct": correct,
            "challenge_fully_solved": fully_solved,
        }
        if skipped:
            verdict["skipped"] = skipped
        if unlocked:
            verdict["unlocked"] = unlocked
        self._persist(verdict)
        return verdict

    def _persist(self, verdict: dict[str, Any]) -> None:
        """把裁决写入 sidecar，供父进程回读。

        ## 为什么必须落盘，而不是只交给父进程补交

        run 结束后运行时框架会销毁实例。父进程那套"事后解析日志、再提交"
        的兜底于是撞上 ``instance_not_found``——一次 run 明明在收工时
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
        if verdict.get("unlocked"):
            lines.append(
                "UNLOCKED: 答对后平台解锁了新问题（本轮内已可见）："
                + ", ".join(str(q) for q in verdict["unlocked"])
                + "。继续解它们——这一轮还没完，先别 finish。"
            )
        elif verdict.get("tried"):
            lines.append(
                f"REJECTED: 试了 {len(verdict['tried'])} 个候选，平台都判错。"
                "答案可能是别的形态，回目标侧再取一次。"
            )
        else:
            lines.append(f"NOT SUBMITTED: {verdict.get('note', '无候选')}")
        return append_note(summary, "\n".join(lines))


class CheckerProbe:
    """One-shot, process-local cache shared by every finish/recovery guard.

    The probe costs one HTTP round trip per question and can block for the
    full request timeout, so it runs at most once per run.  A negative result
    is cached too: if the platform was transiently unreachable at finish time,
    later finish attempts and recovery nudges reuse "not solved" instead of
    retrying.  That trade is deliberate -- without it, a flaky platform turns
    every nudge into another multi-second stall.  The cache lives on this
    object (never in the work directory), so a model cannot forge it and a
    later run cannot inherit it.
    """

    def __init__(
        self,
        submitter: AutoSubmitter,
        *,
        question_ids: list[str] | None = None,
        known_question_ids: list[str] | None = None,
        question_modes: dict[str, str] | None = None,
    ) -> None:
        self.submitter = submitter
        self.question_modes = dict(question_modes or {})
        self.question_ids = list(question_ids or [])
        self.known_question_ids = list(
            known_question_ids if known_question_ids is not None else self.question_ids
        )
        self._done = False
        self._result = False
        self._lock = asyncio.Lock()
        self.note = ""

    async def check(self) -> bool:
        """Probe once and return the cached verdict.

        Returns:
            True only for a validated direct ``passed`` verdict.
        """
        async with self._lock:
            if self._done:
                return self._result
            self._done = True
            try:
                result = await self.submitter.probe_checkers_async(
                    all_questions=True,
                    question_ids=self.question_ids or None,
                    known_question_ids=self.known_question_ids or None,
                    question_modes=self.question_modes or None,
                )
            except Exception as exc:  # noqa: BLE001 -- probe failure is silent
                self.note = f"{type(exc).__name__}: {exc}"
                result = False
            else:
                self.note = "passed" if result else "not solved"
            self._result = bool(result)
            return self._result


def install(
    platform: str,
    instance: str,
    token: str,
    max_refusals: int = 0,
    success: Any = None,
    fallback_question_ids: list[str] | None = None,
    fallback_question_modes: dict[str, str] | None = None,
    submitter: AutoSubmitter | None = None,
    run_mode: str = "instance",
    challenge_id: str = "",
    competition_id: str = "",
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

    # ``submitter`` lets the entrypoint build the object first (so the finish
    # guard can hold its probe) and then install this wrapper afterwards.  The
    # last installed wrapper runs first, which is what keeps submission ahead
    # of the flag guard.
    sub = submitter or AutoSubmitter(
        platform,
        instance,
        token,
        success=success,
        fallback_question_ids=fallback_question_ids,
        fallback_question_modes=fallback_question_modes,
        run_mode=run_mode,
        challenge_id=challenge_id,
        competition_id=competition_id,
    )
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
