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

import hashlib
import json
import logging
import os
import re
from contextvars import ContextVar
from itertools import count
from typing import TYPE_CHECKING, Any

from ctf_strix.flag_extract import CANDIDATE_RE

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)

#: 最近一次 apply 的观测值，供 :mod:`ctf_strix.llm_telemetry` 读取。
#: 只写不改请求，``seq`` 让调用方区分本次请求与残留值。
#: ``first_capped_index`` / ``capped_hash`` 记录「第一条被改写的 item」——
#: prefix_hash 只看 system + 首条 item，看不见历史中段的改写。
LAST_CAP_STATS: ContextVar[dict[str, Any] | None] = ContextVar(
    "ctf_ctx_last_cap_stats", default=None
)

#: 全局单调序号。用实例自增会让新封顶器从 1 重数，跨测试/跨实例时
#: 遥测无法区分"本次新值"与"上一实例的残留"。
_CAP_SEQ = count(1)

#: flag 形态（与 finish_guard / flag_extract 同口径，直接取唯一真值）。
#: 被截断的输出里若出现 flag，必须原样留下——否则压缩会把答案压没，
#: 这是最不可接受的失败模式。用宽集（``CANDIDATE_RE``）而不是窄集：
#: 压缩层宁可多留一小段，也不能因为体里有 ``!`` 之类的字符把答案丢掉。
_FLAG_RE = CANDIDATE_RE

#: 证据抽取的硬上限（字符）。证据块只装「结构性证据」，不装正文。
_EVIDENCE_MAX_CHARS = 800
#: 低优先级证据（hex / 带前缀 ID）的总长上限。它们量大且单项价值低：
#: ``sha256sum`` / ``md5sum`` 一类输出会瞬间吃满整块，把中段的 Set-Cookie 挤掉。
_EVIDENCE_LOW_PRIORITY_CHARS = 200
#: 证据块标题。必须与 ``_ELISION_MARK`` 不同：后者是「已经压过、别再压」
#: 的判据，前者只是本函数的输出标记。
_EVIDENCE_MARK = "[evidence block]"

#: HTTP 头：整行保留（值截 200）。cookie / 跳转 / 认证挑战全靠这些字段传递。
_EVIDENCE_HEADER_RE = re.compile(
    r"(?im)^[ \t]*(set-cookie|location|allow|www-authenticate|content-type)"
    r"[ \t]*:[ \t]*(.+?)[ \t]*$"
)
#: HTTP 状态行：``HTTP/1.1 302 Found``。只认 ``HTTP/x.y NNN`` 形态。
_EVIDENCE_STATUS_RE = re.compile(r"(?im)^[ \t]*(HTTP/\d\.\d[ \t]+\d{3}(?:[ \t]+[^\r\n]*)?)")

#: 命名标识符：session id / token / key 一类。只认**字段名形态**，不认具体值。
#: 左边界用 ``(?<![A-Za-z0-9])`` 而非 ``\b``：``session_token=`` / ``PHPSESSID=``
#: 的前一个字符是下划线或字母，``\b`` 在那里不成立；``mytoken=`` 仍被挡住。
_EVIDENCE_KV_RE = re.compile(
    r"(?ix)"
    r"(?<![A-Za-z0-9])(session[_-]?id|session[_-]?token|sessionid|phpsessid|session"
    r"|access[_-]?token|auth[_-]?token"
    r"|refresh[_-]?token|csrf[_-]?token|xsrf[_-]?token|token|jwt|api[_-]?key"
    r"|secret|password|sid)\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._~+/%=-]{6,512})"
)

#: JWT 形态：三段 base64url，头部固定以 eyJ 开头（``{"`` 的 base64 前缀）。
_EVIDENCE_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,512}\.[A-Za-z0-9_-]{5,512}\.[A-Za-z0-9_-]{0,512}"
    r"(?=[\s\"'<>;,)\]}]|$)"
)
_EVIDENCE_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
#: hex64 / hex32。64 在前，避免 32 位模式把 64 位值切成两半。
_EVIDENCE_HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{32})\b")
#: 带前缀的十六进制标识符（``<name>_<hex>`` 形态），与 traffic.py 的 ID 口径一致。
_EVIDENCE_PREFIXED_ID_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]{1,20}_[0-9a-fA-F]{6,40}\b")
#: 可点击 / 可提交的路径：href / action / src 的值。
_EVIDENCE_PATH_ATTR_RE = re.compile(
    r"(?i)\b(?:href|action|src)\s*=\s*[\"']([^\"'\s<>]{1,200})[\"']"
)
_EVIDENCE_PAGE_RE = re.compile(
    r"[\w\-.~%]+\.(?:php\d?|phtml|html?|aspx?|jsp|jspx|json|xml)", re.I
)


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



def _path_like(value: str) -> bool:
    """路径形态判定：绝对/相对路径、完整 URL、或带扩展名的页面名。"""
    if not value:
        return False
    if value.startswith(("/", "./", "../")) or "://" in value:
        return True
    return bool(_EVIDENCE_PAGE_RE.fullmatch(value))


def _evidence_lines(
    text: str,
    max_chars: int = _EVIDENCE_MAX_CHARS,
    *,
    skip_head: int = 0,
    skip_tail: int = 0,
) -> list[str]:
    """抽取结构性证据，按**首次出现位置**排序、去重、总长封顶。

    纯确定性：同一段文本无论放在历史第几条、被调用几次，输出逐字节一致。
    只认形态与字段名，不认任何具体样例值（命名测试红线）。

    两级优先：状态行 / HTTP 头 / 命名标识符 / JWT / UUID / 路径为高优先级，
    先按位置占用预算；hex 与带前缀 ID 为低优先级，只吃剩余预算，且总长不超过
    ``_EVIDENCE_LOW_PRIORITY_CHARS``。否则 ``sha256sum`` 一类输出会把整块塞满
    hex，把同一段里的 Set-Cookie / Location 全部挤掉。

    ``skip_head`` / ``skip_tail`` 是**请求的**头/尾保留窗口（不是最终实际截取
    的字符数）：窗口内的内容本来就会原样留在输出里，再抽进块只是重复占预算。
    窗口按整行对齐，避免半行截断被当成行首而误匹配 ``^`` 锚点。
    """
    if not text or max_chars <= 0:
        return []

    start = 0
    if skip_head > 0:
        newline = text.find("\n", skip_head)
        start = len(text) if newline < 0 else newline + 1
    end = len(text)
    if skip_tail > 0:
        cut = len(text) - skip_tail
        newline = text.rfind("\n", 0, cut)
        end = 0 if newline < 0 else newline + 1
    if end <= start:
        return []
    window = text[start:end]

    high: list[tuple[int, str]] = []
    low: list[tuple[int, str]] = []

    for match in _EVIDENCE_STATUS_RE.finditer(window):
        value = " ".join(match.group(1).split())
        high.append((match.start(), f"status: {value[:200]}"))
    for match in _EVIDENCE_HEADER_RE.finditer(window):
        value = " ".join(match.group(2).split())
        if value:
            high.append((match.start(), f"{match.group(1).lower()}: {value[:200]}"))
    for match in _EVIDENCE_KV_RE.finditer(window):
        high.append((match.start(2), f"{match.group(1).lower()}: {match.group(2)[:200]}"))
    for match in _EVIDENCE_JWT_RE.finditer(window):
        high.append((match.start(), f"jwt: {match.group(0)[:200]}"))
    for match in _EVIDENCE_UUID_RE.finditer(window):
        high.append((match.start(), f"uuid: {match.group(0)}"))
    for match in _EVIDENCE_PATH_ATTR_RE.finditer(window):
        value = match.group(1)
        if _path_like(value):
            high.append((match.start(1), f"path: {value[:200]}"))
    for match in _EVIDENCE_HEX_RE.finditer(window):
        low.append((match.start(), f"hex: {match.group(0)}"))
    for match in _EVIDENCE_PREFIXED_ID_RE.finditer(window):
        low.append((match.start(), f"id: {match.group(0)}"))

    high.sort(key=lambda pair: pair[0])  # 稳定排序：起点相同时保留抽取顺序
    low.sort(key=lambda pair: pair[0])

    lines: list[str] = []
    seen: set[str] = set()
    accepted: list[str] = []
    used = 0

    def _accept(candidate: str, cap: int) -> None:
        """接受一行，占用 ``used`` 预算。

        值级去重：候选行的值若已完整出现在某条已接受行里就跳过——
        ``sid: <hex>`` / ``hex: <hex>`` 会被 ``set-cookie: sid=<hex>; ...``
        吸收，一个 cookie 只占一行。长度 <6 的值不做包含判断，避免 ``/``
        这种极短值误伤后续所有路径。
        """
        nonlocal used
        if candidate in seen:
            return
        value = candidate.split(": ", 1)[1] if ": " in candidate else candidate
        if len(value) >= 6 and any(value in existing for existing in accepted):
            return
        cost = len(candidate) + 1
        if used + cost > cap:
            return  # 后面更短的行仍有机会进来，顺序不变
        seen.add(candidate)
        accepted.append(value)
        lines.append(candidate)
        used += cost

    for _, line in high:
        _accept(line, max_chars)
    low_cap = max(0, min(_EVIDENCE_LOW_PRIORITY_CHARS, max_chars - used))
    low_absolute = used + low_cap
    for _, line in low:
        _accept(line, low_absolute)
    return lines


def _evidence_block(
    text: str,
    max_chars: int = _EVIDENCE_MAX_CHARS,
    *,
    skip_head: int = 0,
    skip_tail: int = 0,
) -> str:
    """把证据行装成块；没有证据就返回空串（纯文本响应零行为变化）。

    ``skip_head`` / ``skip_tail`` 见 :func:`_evidence_lines`：请求的头/尾窗口
    里的内容本来就原样保留，不再重复抽进块。

    为什么追加在**尾部**而不是头部：前缀缓存按 token 前缀匹配。证据块是
    整段原文的纯函数，追加在已保留的头/尾之后，不移动任何已有 token，
    所以同一 item 在任何一轮里都是同一串字节，历史前缀逐字节稳定（运行期
    零漂移；部署这次改动的首轮会让旧缓存一次性失效，见台账 §4.84）；
    若插在头部或中间，item 内所有后续 token 都会位移，跨请求 / 跨 agent
    复用同一段观测时前缀命中直接归零。
    """
    lines = _evidence_lines(
        text,
        max_chars=max(0, max_chars - len(_EVIDENCE_MARK) - 1),
        skip_head=skip_head,
        skip_tail=skip_tail,
    )
    if not lines:
        return ""
    return "\n" + _EVIDENCE_MARK + "\n" + "\n".join(lines)


def _cap_text(
    text: str, *, limit: int, head: int, tail: int, evidence: bool = False
) -> str:
    """把超长文本压成「头 + 折叠说明 + 尾 + 证据块 + flag 原文」。

    幂等性是硬要求：已经压过的文本再进来必须原样返回。判据是
    ``len(text) <= limit`` —— 折叠后的长度必然 <= limit（预算推导见
    :func:`_cap_text_ex`），所以第二次调用一定短路返回，输出与第一次完全一致。

    证据块只从**中段**（头/尾保留窗口之外的部分）抽取，追加在尾部：它是原文的
    纯函数，且不移动已保留的头/尾，所以历史条目的字节序列跨轮不变，运行期
    零漂移（前缀缓存的推导见 :func:`_evidence_block`）。

    返回值保持为字符串（公共 API 稳定）。需要知道证据块是否真的追加时，
    内部调用方用 :func:`_cap_text_ex`，不要在输出里搜 ``_EVIDENCE_MARK``——
    输入本身就可能以该标记开头，会造成子串误计。
    """
    return _cap_text_ex(text, limit=limit, head=head, tail=tail, evidence=evidence)[0]


def _cap_text_ex(
    text: str, *, limit: int, head: int, tail: int, evidence: bool = False
) -> tuple[str, bool]:
    """``_cap_text`` 的实现，额外返回「本次是否真的追加了证据块」。

    证据预算 ``min(800, max(0, (limit - 320) // 2))``：最多吃掉 limit 的一半
    再减 160，同时给头/尾留至少 200、折叠说明约 54 字符，因此 ``limit >= ~320``
    时 ``len(out) <= limit`` 恒成立。旧公式 ``min(800, limit - 200)`` 在
    limit=500 时会输出 555，不变量失效。
    """
    if limit <= 0 or len(text) <= limit:
        return text, False

    # 已经是压过的文本（含折叠标记）就整体放弃压缩：含 mark 的文本不再做
    # 证据抽取，保证二次调用逐字节稳定（fail-open：不压缩，不是数据损坏）。
    if _ELISION_MARK in text:
        return text, False

    flags = sorted(set(_FLAG_RE.findall(text)))
    keep_flags = ("\n[flags seen in capped output] " + " ".join(flags)) if flags else ""

    block = ""
    if evidence:
        evidence_budget = min(_EVIDENCE_MAX_CHARS, max(0, (limit - 320) // 2))
        block = _evidence_block(
            text, max_chars=evidence_budget, skip_head=head, skip_tail=tail
        )

    # 头尾之和不能超过 limit，否则压完反而更长。
    budget = max(limit - len(keep_flags) - len(block) - 120, 200)
    head = min(head, budget * 2 // 3)
    tail = min(tail, budget - head)
    # RISK 10：头/尾窗口按行边界收口——字符硬切会把一条完整判据切成两截
    # （crypto 实测切在半行上），模型看到的是半条信息。只保「整行」，
    # 且只在损失不超过窗口一半时收口：单行大 blob（JSON、base64）没有
    # 行结构可保，强行找换行会把窗口缩成零头，保行反而丢内容
    # （对照 skillpack._cap_hint 的同款取舍）。
    if head > 0 and "\n" in text[:head]:
        cut = text.rfind("\n", 0, head + 1)
        if cut > head // 2:
            head = cut  # 不含换行本身：text[:cut] 以整行结尾
    if tail > 0 and "\n" in text[-tail:]:
        start = len(text) - tail + text[-tail:].find("\n") + 1
        new_tail = len(text) - start
        if new_tail > tail // 2:
            tail = new_tail
    removed = len(text) - head - tail
    out = (
        text[:head]
        + f"\n\n[... {removed} chars capped by CTF context manager ...]\n\n"
        + (text[-tail:] if tail > 0 else "")
        + block
        + keep_flags
    )
    return out, bool(block)


#: 折叠标记（重写自乱码注释，§5.3）：出现在文本里说明已被本模块压过——
#: 二次压缩整体放弃（见 :func:`_cap_text_ex` 开头的 fail-open 判定），
#: 保证幂等。
_ELISION_MARK = "chars capped by CTF context manager"


def _cap_item(
    item: Any, *, cap: int, head: int, tail: int, arg_cap: int, evidence: bool = False
) -> tuple[Any, int, bool]:
    """对单条 item 做内容封顶，返回 ``(新 item, 省下的字符数, 是否加证据块)``。

    只看内容、不看位置：调用方传入的 items 列表里，任何一条都走同一条路径。
    结构（``type`` / ``call_id`` / ``name``）一律原样保留，只换文本字段。
    第三个返回值来自 :func:`_cap_text_ex`——在输出里搜 ``_EVIDENCE_MARK`` 会
    误计（输入本身就可能以该标记开头）。
    """
    if not isinstance(item, dict):
        return item, 0, False

    kind = item.get("type")

    if kind == "function_call_output":
        output = item.get("output")
        if isinstance(output, str):
            new, block_added = _cap_text_ex(
                output, limit=cap, head=head, tail=tail, evidence=evidence
            )
            if new != output:
                return {**item, "output": new}, len(output) - len(new), block_added
            return item, 0, False
        if isinstance(output, list):
            blocks: list[Any] = []
            saved = 0
            changed = False
            block_added = False
            for block in output:
                if isinstance(block, dict) and block.get("type") == "input_image":
                    blocks.append(block)  # 图片由 strix 自己的 image budget 管
                    continue
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    new, added = _cap_text_ex(
                        block["text"], limit=cap, head=head, tail=tail, evidence=evidence
                    )
                    if new != block["text"]:
                        saved += len(block["text"]) - len(new)
                        changed = True
                        block_added = block_added or added
                        block = {**block, "text": new}
                blocks.append(block)
            if changed:
                return {**item, "output": blocks}, saved, block_added
            return item, 0, False
        return item, 0, False

    if kind == "function_call" and arg_cap > 0:
        args = item.get("arguments")
        if isinstance(args, str):
            new, _ = _cap_text_ex(
                args, limit=arg_cap, head=arg_cap * 2 // 3, tail=arg_cap // 3
            )
            if new != args:
                return {**item, "arguments": new}, len(args) - len(new), False
        return item, 0, False

    return item, 0, False


def _item_hash(item: Any) -> str:
    """SHA-256 (first 16 hex) of an item *before* capping.  Pure, no IO."""
    try:
        seed = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        seed = str(item)
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:16]


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
        evidence: bool = True,
    ) -> None:
        self.cap_chars = cap_chars
        self.head = head
        self.tail = tail
        self.arg_cap = arg_cap
        self.evidence = evidence
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
        capped_items = 0
        evidence_items = 0
        first_capped_index = -1
        capped_hash = ""
        for position, item in enumerate(items):
            new_item, delta, block_added = _cap_item(
                item,
                cap=self.cap_chars,
                head=self.head,
                tail=self.tail,
                arg_cap=self.arg_cap,
                evidence=self.evidence,
            )
            out.append(new_item)
            saved += delta
            if delta:
                capped_items += 1
                if block_added:
                    evidence_items += 1
                if first_capped_index < 0:
                    first_capped_index = position
                    capped_hash = _item_hash(item)

        LAST_CAP_STATS.set(
            {
                "seq": next(_CAP_SEQ),
                "item_count": len(items),
                "capped_items": capped_items,
                "evidence_items": evidence_items,
                "first_capped_index": first_capped_index,
                "capped_hash": capped_hash,
                "input_chars": self.last_request_chars,
            }
        )
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