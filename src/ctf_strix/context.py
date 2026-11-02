"""CTF 上下文管理：**幂等的内容封顶**（唯一保留的一层压缩）。

## 结论先行（2026-11-01 两次真实 A/B 实测）

同一道 043、同模型 DeepSeek-V4.1-Flash-1017、同 40 轮预算：

| 配置 | 调用 | raw input | cache hit | 命中率 | 等效成本(miss=1) | 墙钟 |
|---|---:|---:|---:|---:|---:|---:|
| 不压缩 | 42 | 2,239,568 | 1,660,416 | **95.7%** | **108,678** | 342s |
| 按龄裁剪 v3 | 43 | 1,580,500 | 914,048 | **57.8%** | **684,733** | 595s |

**按龄裁剪是负优化：raw token 只降 9%，等效成本涨 6.3 倍，墙钟涨 74%。**

价格依据（DeepSeek 官方 pricing 页，2026-11-01 抓取）：
cache hit ``$0.006/M``，cache miss ``$0.3/M`` —— **差 50 倍**。

## 为什么按龄裁剪会打崩缓存（根因）

DeepSeek 的磁盘缓存按**完整前缀单元**匹配（官方 Context Caching 文档）：
"``A+C`` 不能命中 ``A+B`` 这个缓存单元"。正常多轮对话里第 N+1 轮请求是
第 N 轮的**严格前缀扩展**，所以每轮只有新增的那几条要重新计费。

而按龄裁剪（"最近 N 条原文、更早的压掉"）意味着：随着轮次推进，
**同一条历史在第 10 轮是原文、第 11 轮被截断、第 21 轮被折成存根**。
每跨过一个档位，前缀就整体改变一次，缓存全部作废。
逐请求实测（命中率）：

```
不裁剪: 88 94 80 92 97 97 97 98 96 97 ... 97 95 92 98 99 98 99 98 99 97
v3裁剪: 88 94 77 89 95 96 96 49 48 91 43 52 58 53 60 93 40 40 42 41 ...
                     ^^^^ 第一个档位切换，此后长期在 40-50% 徘徊
```

## 所以这里只做一件事：按内容封顶，且与位置无关

对**每一条**工具输出单独判断：超过 ``CTF_CTX_CAP_CHARS`` 就保留
头 + 尾 + 其中出现过的 flag 原文。

不变量（这是能用它的唯一理由）：

1. **幂等**：``f(f(x)) == f(x)``，同一段内容无论何时进来输出都一样；
2. **位置无关**：第 5 条和第 50 条的处理规则完全相同，不看"还有几条比它新"；
3. **只依赖内容**：不依赖轮次、不依赖历史长度、不依赖预算余量。

于是第 N+1 轮请求 = 第 N 轮请求 + 新增条目，**前缀严格不变**，缓存照常命中。

## 为什么这仍然值得做

043 的 42 条工具输出里，2 条超过 8k 字符（16k / 14k），它们每一轮都会被
重新发送。封顶 8k 只影响这两条，却让后续 30 多轮每轮少发 ~14k 字符。
这不是"省一次"，是"省每一次"。

## 为什么不设总预算阈值

DeepSeek-V4.1-Flash 的上下文是 **1M**（官方 Models & Pricing 页），
整个 40 轮会话峰值实测只有 **74,263** token。**不存在溢出风险**，
所以任何"接近上限才压缩"的触发条件永远为假，等于没装。

## 合规

* 纯本地计算，不联网（``agent_internet=deny`` 不受影响）；
* 单实例、单模型不变；
* 不修改 vendor，升级 strix 无需 rebase。
"""

from __future__ import annotations

import logging
import os
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

#: flag 形态（与 finish_guard / flag_extract 同口径）。被截断的输出里若出现
#: flag，必须原样留下——否则压缩会把答案压没，这是最不可接受的失败模式。
_FLAG_RE = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


#: 单条工具输出允许保留的最大字符数。超过就头尾保留、中间折叠。
#:
#: 为什么是 8000：043 的 42 条输出里只有 2 条超过这个值（16188 / 14213），
#: 其余 40 条全部原样通过。也就是说这个阈值**精准打击那两条大块头**，
#: 不会误伤正常的 curl / 扫描输出。
CAP_CHARS = _env_int("CTF_CTX_CAP_CHARS", 8_000)

#: 头 / 尾各保留多少字符（在 CAP_CHARS 之内分配）。
HEAD_CHARS = _env_int("CTF_CTX_HEAD_CHARS", 4_800)
TAIL_CHARS = _env_int("CTF_CTX_TAIL_CHARS", 2_400)

#: 工具**调用参数**的封顶。参数里的脚本源码通常前 3k 就够看懂意图，
#: 而且它同样每轮重发。设 0 表示不处理参数。
ARG_CAP_CHARS = _env_int("CTF_CTX_ARG_CAP_CHARS", 4_000)


def _text_of(item: Any) -> str:
    """取一个 item 的可计费文本，用于统计与封顶。"""
    if isinstance(item, str):
        return item
    if not isinstance(item, dict):
        return str(item)
    kind = item.get("type")
    if kind == "function_call_output":
        output = item.get("output")
        if isinstance(output, str):
            return output
        if isinstance(output, list):
            parts = []
            for block in output:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
            return "\n".join(parts)
        return ""
    if kind == "function_call":
        args = item.get("arguments")
        return args if isinstance(args, str) else ""
    content = item.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
        return "\n".join(parts)
    return str(content or "")


def _cap_text(text: str, *, limit: int, head: int, tail: int) -> str:
    """把一段超长文本压成"头 + 折叠说明 + 尾 + 其中的 flag 原文"。

    幂等性是硬要求：已经压过的文本再进来必须原样返回。判据是
    ``len(text) <= limit`` —— 折叠后的长度必然 <= limit，所以第二次调用
    一定短路返回，输出与第一次完全一致。

    这也顺带保证了"压缩后长度仍可能超限"的边界不会造成来回抖动。
    """
    if limit <= 0 or len(text) <= limit:
        return text

    # 已经是我们压过的（含折叠标记）就不再二次处理，避免套娃与长度漂移。
    if _ELISION_MARK in text:
        return text

    flags = sorted(set(_FLAG_RE.findall(text)))
    keep_flags = ("\n[flags seen in capped output] " + " ".join(flags)) if flags else ""

    # 头尾之和不能超过 limit，否则压完反而更长。
    budget = max(limit - len(keep_flags) - 120, 200)
    head = min(head, budget * 2 // 3)
    tail = min(tail, budget - head)
    removed = len(text) - head - tail
    return (
        text[:head]
        + f"\n\n[... {removed} chars capped by CTF context manager ...]\n\n"
        + (text[-tail:] if tail > 0 else "")
        + keep_flags
    )


#: ?????**????**??????????????????????????
_ELISION_MARK = "chars capped by CTF context manager"


def _cap_item(item: Any, *, cap: int, head: int, tail: int, arg_cap: int) -> tuple[Any, int]:
    """对单条 item 做内容封顶，返回 ``(新 item, 省下的字符数)``。

    只看内容、不看位置：调用方传入的 items 列表里，任何一条都走同一条路径。
    结构（``type`` / ``call_id`` / ``name``）一律原样保留，只换文本字段。
    """
    if not isinstance(item, dict):
        return item, 0

    kind = item.get("type")

    if kind == "function_call_output":
        output = item.get("output")
        if isinstance(output, str):
            new = _cap_text(output, limit=cap, head=head, tail=tail)
            return ({**item, "output": new}, len(output) - len(new)) if new != output else (item, 0)
        if isinstance(output, list):
            blocks: list[Any] = []
            saved = 0
            changed = False
            for block in output:
                if isinstance(block, dict) and block.get("type") == "input_image":
                    blocks.append(block)  # 图片由 strix 自己的 image budget 管
                    continue
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    new = _cap_text(block["text"], limit=cap, head=head, tail=tail)
                    if new != block["text"]:
                        saved += len(block["text"]) - len(new)
                        changed = True
                        block = {**block, "text": new}
                blocks.append(block)
            return ({**item, "output": blocks}, saved) if changed else (item, 0)
        return item, 0

    if kind == "function_call" and arg_cap > 0:
        args = item.get("arguments")
        if isinstance(args, str):
            new = _cap_text(
                args, limit=arg_cap, head=arg_cap * 2 // 3, tail=arg_cap // 3
            )
            return ({**item, "arguments": new}, len(args) - len(new)) if new != args else (item, 0)
        return item, 0

    return item, 0


class HistoryCapper:
    """对历史做**幂等内容封顶**，保留前缀缓存的全部收益。

    public API 与旧版 ``HistoryElider`` 保持同名同形（``apply(items)`` ->
    ``(items, saved)``），装配点不用改；但语义完全不同：
    **不再有"最近 N 条"这种位置相关规则**。
    """

    def __init__(
        self,
        cap_chars: int = CAP_CHARS,
        head: int = HEAD_CHARS,
        tail: int = TAIL_CHARS,
        arg_cap: int = ARG_CAP_CHARS,
    ) -> None:
        self.cap_chars = cap_chars
        self.head = head
        self.tail = tail
        self.arg_cap = arg_cap
        self.requests = 0
        self.capped_requests = 0
        self.saved_chars = 0
        self.last_request_chars = 0
        # 兼容装配点的日志/统计字段（旧版叫 budget / keep_recent）。
        self.budget = cap_chars
        self.keep_recent = 0

    def apply(self, items: list[Any]) -> tuple[list[Any], int]:
        self.requests += 1
        self.last_request_chars = sum(len(_text_of(item)) for item in items)

        out: list[Any] = []
        saved = 0
        for item in items:
            new_item, delta = _cap_item(
                item, cap=self.cap_chars, head=self.head, tail=self.tail, arg_cap=self.arg_cap
            )
            out.append(new_item)
            saved += delta

        if saved:
            self.capped_requests += 1
            self.saved_chars += saved
            logger.debug("ctf-ctx: capped %d chars on request %d", saved, self.requests)
        return out, saved


#: 兼容旧名（有测试/脚本按这个符号导入）。
HistoryElider = HistoryCapper

_CAPPER = HistoryCapper()


def _rewrite(input_: Any) -> Any:
    """对一次请求的 input 做封顶；字符串输入（单条 prompt）不动。"""
    if not isinstance(input_, list):
        return input_
    rewritten, _ = _CAPPER.apply(input_)
    return rewritten


class _CappingProxy:
    """透明代理：只改 ``input``，其余一律转发给内层 Model。

    为什么包在这里而不是改 ``maybe_compact``：后者每个 cycle 只调一次，
    而 ``Runner.run_streamed`` 内部会把几十轮全部跑完。包在
    ``get_model`` 上才是"每次 LLM 请求都过一遍"。
    """

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def close(self) -> None:
        await self._inner.close()

    async def _cleanup_on_run_end(self, owner: object) -> None:
        await self._inner._cleanup_on_run_end(owner)

    def get_retry_advice(self, request: Any) -> Any:
        return self._inner.get_retry_advice(request)

    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        if "input" in kwargs:
            kwargs["input"] = _rewrite(kwargs["input"])
        elif len(args) > 1:
            args = (args[0], _rewrite(args[1]), *args[2:])
        return await self._inner.get_response(*args, **kwargs)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        if "input" in kwargs:
            kwargs["input"] = _rewrite(kwargs["input"])
        elif len(args) > 1:
            args = (args[0], _rewrite(args[1]), *args[2:])

        async def _gen() -> AsyncIterator[Any]:
            async for event in self._inner.stream_response(*args, **kwargs):
                yield event

        return _gen()


# 旧名兼容
_ElidingProxy = _CappingProxy


def disabled() -> bool:
    """``CTF_CTX_OFF=1`` 时完全关闭封顶（回滚 / A/B 对照臂）。"""
    return os.environ.get("CTF_CTX_OFF", "").strip().lower() in ("1", "true", "yes")


def install() -> HistoryCapper:
    """安装内容封顶；返回封顶器（测试与统计用）。"""
    from strix.config.models import StrixProvider

    if disabled():
        logger.info("ctf-ctx: content capping disabled by CTF_CTX_OFF")
        return _CAPPER

    if getattr(StrixProvider, "_ctf_ctx_patched", False):
        return _CAPPER

    original = StrixProvider.get_model

    def patched(self: Any, model_name: str | None) -> Any:
        return _CappingProxy(original(self, model_name))

    StrixProvider.get_model = patched  # type: ignore[method-assign]
    StrixProvider._ctf_ctx_patched = True  # type: ignore[attr-defined]
    logger.info(
        "ctf-ctx: content capping installed (cap=%d chars/entry, args=%d)",
        _CAPPER.cap_chars,
        _CAPPER.arg_cap,
    )
    return _CAPPER


# 旧名兼容（装配点按 install_history_elision 调用）。
install_history_elision = install


def stats() -> dict[str, int]:
    return {
        "requests": _CAPPER.requests,
        "capped_requests": _CAPPER.capped_requests,
        "saved_chars": _CAPPER.saved_chars,
        "cap_chars": _CAPPER.cap_chars,
        "arg_cap_chars": _CAPPER.arg_cap,
        "last_request_chars": _CAPPER.last_request_chars,
    }