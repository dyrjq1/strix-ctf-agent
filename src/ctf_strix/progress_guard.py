"""运行时"零进展"守卫：判据是观测增益，不是"有没有拿到 flag"。

## 为什么要和枚举守卫分开

``enum_guard`` 的计数单位是**同一个主机 + 同一路径族**。这在"一个目录刷 52 个
名字"时有效，但失败轨迹的大头是另一种形态：**每一步都在换族、换工具、换参数，
却没有换来任何新观测**——同一份 Go ``404 page not found``、同一个登录页、同一份
默认 ``index.html``。族计数每次归零，stall 计数只用来追加一句软提示，run 依然烧
完轮次。

所以这里的判据只看一件事：``_obs_signature``（这是不是同一个观测）。
连续 ``_STALL_WINDOW`` 次探测没有任何新观测 → 落盘标记 + 转入少量自适应深挖轮；
深挖轮里仍然连续零增益 → :class:`NoProgress` 结束 run。**找没找到 flag 不参与
判断**：找到 flag 由 ``SolvedStop`` 负责，"这条路还有没有信息"由这里负责。

## 为什么结束 run 而不自己换策略

换策略需要 run 之外的信息（还剩多少样本、上一轮试过什么）。agent 自己决定
"换个思路再来一次"实测代价最高：它会把同一批路径用不同措辞再刷一遍，因为历史
里上一轮的失败原因已经被后来的输出埋掉了。所以这里只做三件事：

1. 把停滞的结构化事实落盘（host + path family + mechanism class + 响应签名）；
2. 在结果尾部给一次自适应换向提示（点名**没试过**的机制类）；
3. 深挖预算（复用 ``_ENUM_REFUSAL_LIMIT``）耗尽后抛 :class:`NoProgress`，
   由 ``agent.py`` 映射成 ``stop_reason="no_progress"`` 并照常写 result.json。

要不要用剩余样本重开、要不要换哪种策略，是外层 harness 的事
（``scripts/batch_eval.py --max-samples``），不是 agent 的事。

## 落盘内容里没有答案

标记字段只有 ``host / family / mechanism / signature``，其中 signature 是
``_obs_signature`` 的 12 位指纹，不含响应正文。文件通过
``CTFY_STALL_MARKERS`` 指定；未设置时守卫只在内存里计数。
"""

from __future__ import annotations

from ctf_strix.tool_notes import append_note

import json
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Final

from ctf_strix.enum_guard import (
    MECHANISM_NAMES,
    _ENUM_REFUSAL_LIMIT,
    _STALL_AFTER,
    _fingerprint,
    _host_of,
    _mechanism_of,
    _obs_signature,
    _path_family,
)
from ctf_strix.probe_surface import is_probe_tool

if TYPE_CHECKING:
    from agents import FunctionTool

logger = logging.getLogger(__name__)

#: 连续多少次探测没有任何新观测算"停滞"。**不引入新预算**：与枚举守卫的
#: stall 阈值同源（6 次），物理依据就是那边写过的"六次调用、零新地面"。
_STALL_WINDOW: Final[int] = _STALL_AFTER

#: 停滞标记落盘后允许的深挖轮数。复用 ``_ENUM_REFUSAL_LIMIT``（3）：这是
#: "已经告诉过你换方向，再给三次真的去换"的同一份预算，不是新参数。
_DEEP_DIVE_ROUNDS: Final[int] = _ENUM_REFUSAL_LIMIT

#: 标记文件路径的环境变量名。外部 harness 用它把上一轮的事实带进下一轮。
_MARKERS_ENV: Final[str] = "CTFY_STALL_MARKERS"

#: 单次标记里保留的响应签名：``_obs_signature`` 的产物，12 位十六进制。
_SIGNATURE_LEN: Final[int] = 12


class NoProgress(BaseException):
    """The run produced no new observation anywhere and the deep dive is spent.

    ``BaseException`` for the same reason as :class:`enum_guard.EnumExhausted`:
    the runner and the tool wrappers are full of ``except Exception``, and a
    swallowed stop would hand control back to the retry loop this exists to
    break.

    Attributes:
        stats: the guard's snapshot at trip time (no answer values).
        host: last target host, ``""`` when it could not be read.
        family: last path family, ``""`` when it could not be read.
        mechanism: last CAPEC mechanism class, ``""`` when unclassified.
        signature: last observation fingerprint.
    """

    def __init__(
        self,
        message: str,
        *,
        stats: dict[str, Any] | None = None,
        host: str = "",
        family: str = "",
        mechanism: str = "",
        signature: str = "",
    ) -> None:
        super().__init__(message)
        self.stats = dict(stats or {})
        self.host = host
        self.family = family
        self.mechanism = mechanism
        self.signature = signature


class ProgressGuard:
    """Track observation gain across path families and stop a stalled run.

    Only calls that reach a target are judged (``_fingerprint`` needs a host):
    a local ``ls`` or a script edit is not evidence about the target, and
    counting it would make the window fire on ordinary work.
    """

    def __init__(self, markers_path: str | None = None) -> None:
        self._lock = threading.Lock()
        self._markers_path = (
            markers_path if markers_path is not None else os.environ.get(_MARKERS_ENV, "")
        )
        #: 全局观测集：**只放签名，不掺族键**。和 enum_guard 的族内 ``_seen``
        #: 不同，这里要抓的是"换了十个族、拿到同一份 404"——把族键混进键里，
        #: 十个族就是十条新观测，这个守卫会和族计数一样永远不响。
        #: 代价：一个早就见过的响应被再次看到时也算"没有新观测"，这正是本意
        #: （它对本次 run 已经不提供信息），但它不阻止调用，只累加 streak。
        self._seen: set[str] = set()
        self._mechanisms: set[str] = set()
        self.probes = 0
        self.fresh = 0
        self.streak = 0
        self.deep_left = 0
        self.deep_active = False
        self.marks = 0
        self.tripped = False
        self.trip_stage = ""
        self._last: tuple[str, str, str, str] = ("", "", "", "")
        #: negative_guard 里"同参数同响应已达 K"的组数，上一次见到的值。
        self._neg_seen = 0

    # -- read-only views ---------------------------------------------------

    @property
    def fresh_rate(self) -> float:
        """Share of probes that produced a new observation (0.0 when none)."""
        return (self.fresh / self.probes) if self.probes else 0.0

    def stats(self) -> dict[str, Any]:
        """Read-only snapshot for the run diagnostics (never holds a value)."""
        with self._lock:
            return {
                "probes": self.probes,
                "fresh": self.fresh,
                "fresh_rate": round(self.fresh_rate, 3),
                "streak": self.streak,
                "deep_left": self.deep_left,
                "deep_active": self.deep_active,
                "marks": self.marks,
                "tripped": self.tripped,
                "window": _STALL_WINDOW,
            }

    @property
    def last_probe(self) -> tuple[str, str, str, str]:
        """The last judged probe as ``(host, family, mechanism, signature)``.

        Empty strings mean "could not be read from the arguments"; the values
        never contain a response body, only the 12-hex observation fingerprint.
        """
        with self._lock:
            return self._last

    def trip_detail(self) -> str:
        """One-line reason for the ``NoProgress`` exception."""
        host, family, mechanism, _sig = self._last
        where = " ".join(
            part
            for part in (
                f"host={host}" if host else "",
                f"family={family}" if family else "",
                f"mechanism={mechanism}" if mechanism else "",
            )
            if part
        )
        return (
            f"no progress: {self.probes} probes, {self.fresh} new observations "
            f"(fresh rate {self.fresh_rate:.0%}), {self.streak} in a row without "
            f"gain and the deep dive is spent"
            + (f"; last probe {where}" if where else "")
        )

    # -- state transitions -------------------------------------------------

    def note_answer(self) -> None:
        """An answer is recorded: nothing may stop the run that carries it."""
        with self._lock:
            self._seen.clear()
            self._mechanisms.clear()
            self.streak = 0
            self.deep_left = 0
            self.deep_active = False
            self.tripped = False
            self.trip_stage = ""

    def observe(self, tool_name: str, args: str, result: Any = None) -> str | None:
        """Feed one probe result; return text for its tail, or ``None``.

        Args:
            tool_name: the tool that ran.
            args: the raw argument blob.
            result: the bounded tool result.

        Returns:
            A hint to append to the result, or ``None``.
        """
        if not is_probe_tool(tool_name):
            return None
        key = _fingerprint(tool_name, args)
        if key is None:
            # 没打到目标：本地命令、文件读写、脚本编辑都不判。
            return None

        text = result if isinstance(result, str) else str(result)
        sig = _obs_signature(text, args)
        host = _host_of(args) or ""
        family = _path_family(args) or ""
        mechanism = _mechanism_of(args) or ""
        neg_stuck = self._negative_stuck()

        marker: dict[str, Any] | None = None
        hint: str | None = None
        with self._lock:
            self.probes += 1
            self._last = (host, family, mechanism, sig)
            if mechanism:
                self._mechanisms.add(mechanism)
            repeat = sig in self._seen
            # K=3 同参数同响应是另一条独立判据：那三次可能换了换行/换了输出
            # 包装，``_obs_signature`` 会判成"新观测"，但 negative_guard 已经
            # 断定是同一个死路。组数增长一次，这里就强制记一次非增益。
            forced = neg_stuck > self._neg_seen
            self._neg_seen = max(self._neg_seen, neg_stuck)
            gain = not repeat and not forced
            self._seen.add(sig)

            if gain:
                self.fresh += 1
                self.streak = 0
                if self.deep_active:
                    # 深挖期拿到新观测：说明换向有效，预算复位，继续正常探测。
                    self.deep_active = False
                    self.deep_left = 0
            else:
                self.streak += 1
                if self.deep_active:
                    self.deep_left -= 1
                    if self.deep_left <= 0:
                        self.deep_active = False
                        self.tripped = True
                        self.trip_stage = "deep_exhausted"
                        self.marks += 1
                        marker = self._marker(streak=self.streak, stage="deep_exhausted")
                    else:
                        hint = self._deep_hint()
                elif self.streak >= _STALL_WINDOW:
                    self.deep_active = True
                    self.deep_left = _DEEP_DIVE_ROUNDS
                    self.marks += 1
                    marker = self._marker(streak=self.streak, stage="stall")
                    hint = self._stall_hint()

        if marker is not None:
            self._write_marker(marker)
        return hint

    # -- internals ---------------------------------------------------------

    def _negative_stuck(self) -> int:
        """How many negative-evidence groups have closed (K=3) so far."""
        try:
            from ctf_strix import negative_guard

            return len(negative_guard.current().stuck_groups())
        except Exception:  # noqa: BLE001 - a guard fault must not break tools
            return self._neg_seen

    def _marker(self, *, streak: int, stage: str) -> dict[str, Any]:
        host, family, mechanism, sig = self._last
        return {
            "ts": int(time.time()),
            "host": host,
            "family": family,
            "mechanism": mechanism,
            "signature": sig[:_SIGNATURE_LEN],
            "streak": streak,
            "fresh_rate": round(self.fresh_rate, 3),
            "probes": self.probes,
            "stage": stage,
        }

    def _write_marker(self, marker: dict[str, Any]) -> None:
        path = self._markers_path
        if not path:
            return
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(marker, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception:  # noqa: BLE001 - persistence must not break the run
            logger.warning("progress guard marker write failed", exc_info=True)

    def _untried(self) -> str:
        untried = [name for name in MECHANISM_NAMES if name not in self._mechanisms]
        return ", ".join(untried) if untried else "(none left)"

    def _stall_hint(self) -> str:
        host, family, mechanism, _sig = self._last
        where = " / ".join(part for part in (host, family, mechanism) if part)
        return (
            f"\n\n[NO PROGRESS] {self.streak} probes in a row produced no new "
            f"observation {'at ' + where if where else 'anywhere'}. "
            f"Marked and switching to a focused dive: {self.deep_left} attempts "
            "left before this run stops.\n"
            "Rules for those attempts: do not repeat the marked probe or its "
            "siblings; pick a different attack class. "
            f"Classes not tried yet: {self._untried()}. "
            "Name the one concrete fact you already have and take the class it "
            "points at."
        )

    def _deep_hint(self) -> str:
        return (
            f"\n\n[NO PROGRESS] still no new observation; {self.deep_left} focused "
            f"attempt(s) left before this run stops. Untried classes: {self._untried()}."
        )


_GUARD: ProgressGuard | None = None
_GUARD_LOCK = threading.Lock()

_MARK: Final[str] = "_ctf_progress_guarded"


def current() -> ProgressGuard:
    """Return the process-wide guard, creating it on first use."""
    global _GUARD  # noqa: PLW0603 - one guard per run
    with _GUARD_LOCK:
        if _GUARD is None:
            _GUARD = ProgressGuard()
        return _GUARD


def reset_for_tests() -> None:
    """Drop the singleton so a test starts from a clean run state."""
    global _GUARD  # noqa: PLW0603 - test hook
    with _GUARD_LOCK:
        _GUARD = None


def install() -> ProgressGuard:
    """Wrap every tool on the same mount seam as the other guards.

    Install it **immediately after** ``guard_mount.install_mount_hook()`` and
    before ``negative_guard``: the observation signature must be computed on
    the bounded result alone, and every later guard appends advice text that
    would otherwise turn one observation into two.

    Returns:
        The installed guard, for the event sink and the run summary.
    """
    from strix.agents import factory

    guard = ProgressGuard()
    global _GUARD  # noqa: PLW0603 - the singleton shares the installed state
    with _GUARD_LOCK:
        _GUARD = guard

    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                hint = guard.observe(tool.name, raw_input, result)
            except Exception:  # noqa: BLE001 - a guard fault must not break tools
                logger.warning("progress guard failed", exc_info=True)
                return result
            if hint:
                return append_note(result, hint)
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard