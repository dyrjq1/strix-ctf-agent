"""Engagement（GAUNTLET）模式的报告投递。

## 为什么单开一个模块

engagement 题**没有 flag**。交付物是一份渗透报告，通过
``PUT /api/v1/competitions/{competition_id}/challenges/{challenge_id}/report``
覆盖保存。平台在**每次保存时**从正文里抽证据计分，所以：

1. 报告必须**边做边存**——跑完才攒一份，中途的发现一分也拿不到；
2. 存失败不能拖垮 run——网络抖动、字段名变更都不该让 agent 停止工作；
3. 报告正文要带**具体证据**（路径、请求、响应、数据），含糊的结论不计分。

## 为什么请求体要试多个字段名

协议原文（``docs/08``）不在交付包里，字段名从未被实测确认。硬编码
``{"content": ...}`` 一旦猜错，平台回 400，而我们只会在日志里留一行错误、
整个 engagement 记 0 分。所以这里按 ``content`` → ``markdown`` → ``body``
→ ``report`` 依次重试，**只对 400/415/422 重试**（字段名/媒体类型不匹配），
对 401/403/404/5xx 直接放弃——那些再换字段也没用。首个成功的字段会被记住，
后续保存不再重复试错。

## 节流

``publish()`` 会按正文 hash 去重，并保证两次真实请求之间至少间隔
``min_interval`` 秒。周期性自动保存在每个工具结果上触发，没有节流会把
平台打爆，也会把 run 拖慢。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Final

#: 单次 PUT 的超时。报告保存是旁路动作，不能像提交 flag 那样等 45 秒。
_TIMEOUT: Final = 20

#: 请求体候选字段，按优先级排序。见模块 docstring。
_BODY_KEYS: Final[tuple[str, ...]] = ("content", "markdown", "body", "report")

#: 这些状态码说明"请求体形状不对"，值得换一个字段名重试。
_SCHEMA_STATUS: Final[frozenset[int]] = frozenset({400, 413, 415, 422})

#: 会被平台保存、可能被他人看到的凭据形态。报告是**提交物**，任何密钥进正文
#: 都等于泄漏；自动摘要又是从工具输出里拼的，agent 跑一次 `env` 就能带进来。
#:
#: ⚠️ 不能按"长度 >= 32 的串"一刀切：报告里最值钱的证据恰恰是长文档 id、
#: MD5、session 片段，掩掉它们等于把计分点删了。这里只认两种确定是凭据的
#: 形态——JWT（``eyJ...``）与显式 ``Bearer xxx``。
_SECRET_RE: Final = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}"
    r"|(?i:bearer)\s+[A-Za-z0-9._~+/=-]{16,}"
)


def redact(text: str, secrets: list[str] | None = None) -> str:
    """去掉正文里的凭据。

    先用**已知的**环境变量值做精确替换（token、API key），再对形似长密钥的
    串做兜底掩码。两层的顺序不能反：先掩码会把已知 token 切碎，导致精确
    替换匹配不到。

    Args:
        text: 原始正文。
        secrets: 额外需要抹掉的精确值（通常来自环境变量）。

    Returns:
        脱敏后的正文。
    """
    out = text or ""
    candidates = [s for s in (secrets or []) if s and len(s) >= 8]
    for value in sorted(candidates, key=len, reverse=True):
        out = out.replace(value, "[REDACTED]")
    return _SECRET_RE.sub("[REDACTED]", out)


def platform_of(task: dict[str, Any]) -> str:
    """解析平台根地址。

    Args:
        task: 已解析的 task.json。

    Returns:
        去掉末尾斜杠的根地址；没有任何线索时返回空串（调用方据此跳过投递）。
    """
    raw = (
        os.environ.get("CTFY_PLATFORM_URL")
        or task.get("platform_url")
        or task.get("platform")
        or ""
    )
    return str(raw).strip().rstrip("/")


def competition_id_of(task: dict[str, Any]) -> str:
    """取比赛 id，环境变量优先于 task.json。"""
    raw = (
        os.environ.get("CTFY_EVAL_COMPETITION_ID")
        or task.get("competition_id")
        or (task.get("competition") or {}).get("id")
        or ""
    )
    return str(raw).strip()


def challenge_id_of(task: dict[str, Any]) -> str:
    """取题目 id，环境变量优先于 task.json。"""
    raw = (
        os.environ.get("CTFY_EVAL_CHALLENGE_ID")
        or task.get("challenge_id")
        or (task.get("challenge") or {}).get("id")
        or ""
    )
    return str(raw).strip()


def is_engagement(task: dict[str, Any]) -> bool:
    """是否是 engagement 题型。

    判据是 ``run_mode == "engagement"``。不拿 ``questions`` 是否为空当判据：
    instance 题也可能暂时没有 questions，而 engagement 的 questions 为空是
    协议里写明的**刻意设计**，不是识别依据。
    """
    return str(task.get("run_mode") or "").strip().lower() == "engagement"


def report_url(platform: str, competition_id: str, challenge_id: str) -> str:
    """拼报告端点。

    Args:
        platform: 平台根地址。
        competition_id: 比赛 id。
        challenge_id: 题目 id。

    Returns:
        完整 URL。id 为空时仍拼出来，由调用方判断是否可发——这样测试能锁住
        拼接格式，而不是把一个静默的空串当成"没有端点"。
    """
    return (
        f"{platform.rstrip('/')}/api/v1/competitions/{competition_id}"
        f"/challenges/{challenge_id}/report"
    )


@dataclass
class ReportPublisher:
    """把报告覆盖保存到平台，永不抛异常。

    Attributes:
        platform: 平台根地址。
        token: 队伍 bearer token。
        competition_id: 比赛 id。
        challenge_id: 题目 id。
        min_interval: 两次真实请求之间的最小间隔（秒）。
    """

    platform: str
    token: str
    competition_id: str
    challenge_id: str
    min_interval: float = 10.0

    attempts: int = 0
    successes: int = 0
    last_error: str | None = None
    last_ok: bool = False
    #: 已经确认可用的请求体字段名。空串表示还没成功过。
    body_key: str = ""
    published: list[str] = field(default_factory=list)
    #: 模型是否自己写过报告。写过之后自动保存不再覆盖它的正文——自动摘要
    #: 只能拼出"做了什么"，拼不出"影响是什么"，而后者才是计分点。
    authored: bool = False
    #: 最近一次写出去（或被模型写）的正文，供收工时再保存一次。
    last_text: str = ""

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _last_hash: str = ""
    _last_at: float = 0.0

    def configured(self) -> bool:
        """三个必填项都在才可能投递成功。"""
        return bool(self.platform and self.token and self.competition_id and self.challenge_id)

    # -------------------------------------------------------------- HTTP
    def _put(self, body: dict[str, Any]) -> tuple[int, str]:
        """发一次 PUT，返回 ``(状态码, 响应文本)``。0 表示连接层失败。

        不抛异常：报告投递失败只应记日志。
        """
        req = urllib.request.Request(
            report_url(self.platform, self.competition_id, self.challenge_id),
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.token}",
            },
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
                return resp.status, resp.read()[:400].decode(errors="replace")
        except urllib.error.HTTPError as exc:
            # HTTPError 也是一条活着的连接。不 close 的话，字段名重试（最多 4 次）
            # 每次漏一个 socket，长 run 里会一直攒着，直到 GC 才回收。
            try:
                return exc.code, exc.read()[:400].decode(errors="replace")
            finally:
                exc.close()
        except Exception as exc:  # noqa: BLE001 — 投递失败不能拖垮 run
            return 0, f"{type(exc).__name__}: {exc}"

    def _candidates(self) -> list[str]:
        """待试的字段名：已确认的排第一，其余按默认顺序补齐。"""
        if self.body_key:
            return [self.body_key]
        return list(_BODY_KEYS)

    def publish(
        self,
        markdown: str,
        *,
        force: bool = False,
        source: str = "agent",
    ) -> tuple[bool, str]:
        """保存一份报告，覆盖上一版。

        Args:
            markdown: 报告正文（markdown）。
            force: 忽略"内容没变"的去重，强制发一次。收工时的最终保存要用。
            source: ``agent``（模型显式调用）或 ``auto``（周期性兜底）。

        Returns:
            ``(成功与否, 说明)``。任何失败都折算成 ``(False, 原因)``。
        """
        text = redact((markdown or "").strip(), [self.token])
        if not text:
            return False, "empty report"
        if not self.configured():
            return False, "report endpoint not configured (platform/competition/challenge/token)"

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        with self._lock:
            if source == "auto" and self.authored:
                # 自动摘要可能比模型手写的正文**晚**落地（后台线程先启动、
                # 后完成）。它只能拼出「做了什么」，拼不出「影响是什么」，
                # 覆盖手写版等于把计分点删掉。判断必须在锁内，否则并发下
                # 会读到过期的 authored。
                return True, "authored report takes precedence"
            now = time.time()
            self.last_text = text
            if source == "agent":
                self.authored = True
            if not force and digest == self._last_hash:
                return True, "unchanged, skipped"
            wait = self.min_interval - (now - self._last_at)
            if not force and wait > 0:
                return True, f"throttled ({wait:.0f}s)"
            self._last_at = now
            self.attempts += 1

        last = ""
        last_status = 0
        for key in self._candidates():
            status, body = self._put({key: text})
            last_status, last = status, body
            if 200 <= status < 300:
                with self._lock:
                    self.successes += 1
                    self.last_ok = True
                    self.last_error = None
                    self.body_key = key
                    self._last_hash = digest
                    self.published.append(digest)
                return True, f"HTTP {status} saved ({len(text)}B via {key!r})"
            if status not in _SCHEMA_STATUS:
                break

        with self._lock:
            self.last_ok = False
            self.last_error = (
                f"HTTP {last_status}: {last[:160]}" if last_status else last[:160]
            )
        return False, self.last_error

    # -------------------------------------------------------------- 摘要
    def snapshot(self) -> dict[str, Any]:
        """投递状态，写进 result.json 的 ``writeup``/诊断字段。"""
        with self._lock:
            return {
                "attempts": self.attempts,
                "successes": self.successes,
                "last_ok": self.last_ok,
                "last_error": self.last_error,
                "body_key": self.body_key,
            }


def build_report(
    task: dict[str, Any],
    *,
    findings: list[str] | None = None,
    activity: list[str] | None = None,
    summary: str = "",
    elapsed: float = 0.0,
) -> str:
    """拼一份可提交的报告正文。

    报告必须**带证据**：只有结论的正文平台抽不出可计分的断言。所以结构上
    优先放 agent 自己写的 findings（含请求/响应），其次放由工具输出提炼的
    活动记录，最后是收工摘要。

    Args:
        task: task.json。
        findings: agent 主动写下的发现（每条形如一段 markdown）。
        activity: 自动收集的「命令 -> 输出摘要」条目。
        summary: 收工摘要。
        elapsed: 已运行秒数。

    Returns:
        markdown 正文；没有任何素材时返回只含元信息的最小报告。
    """
    challenge = task.get("challenge") or {}
    name = str(challenge.get("name") or challenge.get("id") or "<engagement>")
    lines = [
        f"# Penetration test report — {name}",
        "",
        f"- Scope: {', '.join(str(s) for s in (task.get('scope') or [])) or '(unspecified)'}",
        f"- Elapsed: {elapsed:.0f}s",
        "",
        "## Findings",
        "",
    ]
    body = [f for f in (findings or []) if f and f.strip()]
    if body:
        lines.extend(body)
    else:
        lines.append("_No finding has been written yet._")

    acts = [a for a in (activity or []) if a and a.strip()]
    if acts:
        lines.extend(["", "## Activity log", ""])
        lines.extend(acts)

    if summary.strip():
        lines.extend(["", "## Summary", "", summary.strip()])
    return "\n".join(lines) + "\n"


#: 当前生效的投递器。``save_report`` 工具对象只注册一次——注册同名工具两次会让
#: ``register_agent_tools`` 抛 ``ValueError``——所以正文不能靠闭包捕获某一次 run
#: 的 publisher，而要靠这个模块级引用重新绑定。
_ACTIVE_PUBLISHER: ReportPublisher | None = None

#: 工具名。注册幂等检查按它匹配。
_TOOL_NAME: Final = "save_report"


def install_tool(publisher: ReportPublisher) -> list[str]:
    """把 ``save_report`` 注册成 agent 工具（engagement 专用）。

    为什么给模型一个显式工具，而不是只靠自动保存：自动保存只能拼出
    「做了什么」，拼不出「影响是什么」；而平台按证据计分，写得具体才有分。
    让模型自己决定每条发现的 Where/How/Evidence/Impact，比事后从工具输出里
    猜要准得多。自动保存仍然兜底，两者写同一份报告。

    Args:
        publisher: 报告投递器。

    Returns:
        已注册的工具名列表；注册失败返回空列表（不能拖垮整题）。
    """
    global _ACTIVE_PUBLISHER
    _ACTIVE_PUBLISHER = publisher

    try:
        from agents import function_tool
        from strix.agents import factory
    except Exception:  # noqa: BLE001 — 没有运行时就没有工具
        return []

    # 同一个进程里重跑（评测脚本一进程多题）时不能重复注册：SDK 要求工具名
    # 唯一，第二次注册同名工具会抛 ValueError，然后本函数返回空列表——
    # 最糟的失败形态是"报告工具静默消失"。
    try:
        existing = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
    except Exception:  # noqa: BLE001 — 老版本运行时没有这个查询接口
        existing = set()
    if _TOOL_NAME in existing:
        return [_TOOL_NAME]

    # 与 `aisec/tools.py` 同一写法：async、不声明 ctx。把 ctx 注解成 Any 会让
    # SDK 把它当成一个"模型必须填"的工具参数（正确类型是 RunContextWrapper，
    # 而那个类只有装了 agents 才 import 得到），是本模块唯一会静默出错的地方。
    @function_tool
    async def save_report(markdown: str) -> str:
        """Save (overwrite) the penetration-test report on the platform.

        Call this as soon as you have a finding with real evidence, and again
        whenever you add findings. Each save replaces the previous version, so
        always pass the complete report. The platform grades the last saved
        version and extracts evidence on every save.

        Args:
            markdown: The complete report, in markdown. For each finding include
                where it is (host + exact endpoint), how it was done (the
                request), what came back (the response or data you read), and
                the impact.

        Returns:
            A confirmation with the HTTP status, or the error to fix.
        """
        active = _ACTIVE_PUBLISHER
        if active is None:
            return "NOT saved: report delivery is not configured"
        # urllib 的 PUT 是阻塞 IO。直接在 async 里调用会卡住整个事件循环，
        # 一次慢请求（最坏 4 个候选字段 × 20s）能把其余工具调用一起冻住。
        ok, note = await asyncio.to_thread(
            active.publish, markdown, force=True, source="agent"
        )
        return f"saved: {note}" if ok else f"NOT saved: {note}"

    try:
        factory.register_agent_tools(save_report)
    except Exception:  # noqa: BLE001 — 注册失败只损失一个工具
        return []
    return [getattr(save_report, "name", _TOOL_NAME)]


def compact_activity(entries: list[str], limit: int = 30) -> list[str]:
    """把原始「命令/输出」条目压成紧凑的 markdown 列表。

    只在自动保存时使用。保留最近 ``limit`` 条，单条截断到 600 字符——报告是
    给平台抽证据用的，不是完整日志；过长正文会挤掉前面真正有价值的发现。

    Args:
        entries: 形如 ``"$ <cmd>\\n<output>"`` 的条目。
        limit: 保留条数。

    Returns:
        markdown 列表项。
    """
    out: list[str] = []
    for raw in entries[-limit:]:
        text = raw.strip()
        if not text:
            continue
        if len(text) > 600:
            text = text[:600] + " …"
        out.append("- " + text.replace("\n", "\n  "))
    return out


def install_finish_hook(callback: Any) -> bool:
    """在 ``finish_scan`` 执行**之前**跑一次 ``callback``。

    为什么挂在收工工具上而不是等 run 返回：``finish_scan`` 一返回，运行时
    就开始销毁 sandbox 与实例；一次"想说但没来得及发"的保存等于没保存。
    这个钩子装得比收工守卫更晚，所以它在最外层——先保存报告，再由收工守卫
    决定是否放行。

    Args:
        callback: 无参可调用对象。必须自行吞掉异常。

    Returns:
        是否安装成功。内部结构变更时返回 False，调用方会退回"run 结束后保存"。
    """
    try:
        from strix.agents import factory
    except Exception:  # noqa: BLE001 — 没有运行时就没有钩子
        return False

    original = factory._with_bounded_result

    def patched(tool: Any) -> Any:
        tool = original(tool)
        if getattr(tool, "name", "") != "finish_scan":
            return tool
        if getattr(tool, "_ctf_report_hooked", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            import asyncio

            try:
                await asyncio.to_thread(callback)
            except Exception:  # noqa: BLE001 — 保存失败不能挡住收工
                pass
            return await inner(ctx, raw_input)

        tool.on_invoke_tool = invoke
        tool._ctf_report_hooked = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return True
