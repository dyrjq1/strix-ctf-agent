"""单次工具调用内部的"参数扫描"检测（P20-c）。

## 为什么必须做在这一层

`enum_guard` 按**调用**去重，判据是"同族 + 同响应指纹"。它在 018 那种
"一条命令打一个路径、连打四次"的形态上有效，但对 043 完全失效：

```
[guard] enum_keys: 4, enum_hits: 0
```

043 的实测做法是把几千个候选名塞进**一条** `exec_command`：

```python
words = ["private","admin","briefing", ...]        # 40 个种子
for w in words:
    for n in range(1,6): cands.add(f"{w}_{n}")
for a,b in itertools.product(words,words):          # 40x40 笛卡尔积
    cands.add(f"{a}_{b}")
```

在调用层看，这是**一次**探测；在语义层看，这是**同一个假设重试 3320 次**。
按调用计数永远够不到阈值，所以守卫一次都没触发。

⚠️ 因此本模块必须同时认两种形态，缺一不可：

1. **字面量扫描**——参数里直接出现大量不同取值（`?id=1..50`、一长串
   `@@INCLUDE:x`、一个几百项的字符串列表）；
2. **生成式扫描**——取值由程序在运行时算出来，参数里只有几十个种子词，
   但出现了 `itertools.product` / 双层 `for ... in range` / `cands.add`
   这类**组合构造**特征。043 就是这一种，只写字面量检测会 100% 漏判。

## 判据

不改 `enum_guard` 的响应指纹逻辑，只补这一个维度。命中即在结果尾部追加提示。

## 为什么只在结果里追加提示，不拒绝

拒绝会让模型重发同一条命令（`enum_guard` 已有的教训）。追加提示保留全部
观测，只把"你正在原地打转"推到它眼前——这是纠正行为最有效的位置。

## 阈值依据

043 里那 40 个种子词本身是合理的（词表小了没法枚举），病态的是**组合放大**。
所以生成式判据不看种子多少，看是否同时出现"组合 + 批量发送"。
字面量判据取 24 起步、80 硬警告：正常题里一次枚举 24 个以上同类取值极少见，
而真正的爆破动辄上千。
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ctf_strix.probe_surface import PROBE_TOOLS

if TYPE_CHECKING:
    from agents import FunctionTool

#: 起步警告：同一次调用里出现这么多**不同**取值，就该提醒换机制。
SWEEP_WARN = 24
#: 硬警告：到这个量级，几乎可以确定是病态爆破。
SWEEP_HARD = 80

#: `@@INCLUDE:<key>` —— 指令式包含。
_INCLUDE_RE = re.compile(r"@@INCLUDE:\s*([A-Za-z0-9_./:-]+)")
#: `?name=value` / `&name=value` —— 查询参数。
_QUERY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,40})=([^&\s\"'`<>]{1,80})")
#: JSON / Python 里的 `"name": "value"`。
_JSON_KV_RE = re.compile(r"[\"']([A-Za-z_][A-Za-z0-9_\-]{0,40})[\"']\s*:\s*[\"']([^\"'\n]{1,80})[\"']")
#: 列表字面量里的一串短字符串——字典式爆破的典型形态。
_STR_LITERAL_RE = re.compile(r"[\"']([A-Za-z0-9_./:-]{1,40})[\"']")
#: 形如 `note_d6e7380c` / `user_1a2b3c` 的不透明标识符。
_OPAQUE_ID_RE = re.compile(r"\b([a-z][a-z0-9]{1,12}_[0-9a-f]{6,32})\b")

#: 组合构造：两个以上取值来源相乘。任一条命中即视为"生成式枚举"。
#:
#: 2026-11-01 补：原版只认 `itertools.product` / 嵌套 for / `cands.add`。
#: 一次复跑时的真实写法是**列表推导 + 线程池**：
#:
#: ```python
#: paths = [f"/{x}" for x in a] + [f"/api/{x}" for x in a]
#: with ThreadPoolExecutor(20) as ex: ex.map(go, paths)
#: ```
#:
#: 一条都不匹配，于是 1440 次请求被判成"正常调用"。推导式是同一件事的
#: 另一种写法，必须认。
_COMBINE_RE = re.compile(
    r"itertools\.(?:product|chain|combinations)"
    r"|product\(\s*\w+\s*,\s*\w+"   # from itertools import product
    r"|cands\.add|keys\.add|candidates\.add|paths?\.append"
    r"|\bfor\s+\w+\s+in\s+\w+\s*:\s*\n?\s*for\s+\w+\s+in\s+"  # 嵌套 for
    r"|\[[^\]\n]{0,120}?\bfor\s+\w+\s+in\s+\w+"                  # 列表推导
    r"|\{[^}\n]{0,120}?\bfor\s+\w+\s+in\s+\w+"                   # 集合/字典推导
    r"|\brange\s*\("                                              # 计数循环
)

#: 批量发送：把枚举结果一次性推到目标。只有组合没有发送不算扫描。
#:
#: `ThreadPoolExecutor` 是"一次调用里打几千个请求"的最快写法，比 for 循环
#: 更该被认出来——它同时也是**最贵的**形态（并发把预算烧成平方）。
_SEND_RE = re.compile(
    r"for\s+\w+\s+in\s+(?:cands|keys|candidates|words|paths?|chunk)"
    r"|requests\.(?:post|get|put|patch|head|options)\("
    r"|urllib\.request|http\.client|socket\.socket"
    r"|ThreadPoolExecutor|ProcessPoolExecutor|\.map\s*\("
    r"|curl\s"
    r"|/api/|/playground|@@INCLUDE:",
)

#: 列表/集合/字典推导式。单独拎出来是为了**计数**——推导式个数决定
#: "一组种子要乘几遍"，与 `_COMBINE_RE` 里的检测用途不同。
_COMP_RE = re.compile(r"\[[^\]\n]{0,120}?\bfor\s+\w+\s+in\s+\w+|\{[^}\n]{0,120}?\bfor\s+\w+\s+in\s+\w+")

#: `itertools.product(x, x)` —— 同一个变量乘自己，规模是平方而不是线性。
#: 050 的真实形态（6 个种子词做笛卡尔积）只有 6 个字面量，但它是 36 次请求。
_PRODUCT_SAME_RE = re.compile(r"product\(\s*(\w+)\s*,\s*\1\s*\)")

#: 计数循环的规模：``range(500)`` / ``for i in range(1, 500)``。
#: 只取上界，不解析变量——估的是量级，不是精确值。
_RANGE_RE = re.compile(r"range\(\s*\d*\s*,?\s*(\d{2,7})\s*\)")

#: JSON 参数里的转义。`on_invoke_tool` 拿到的是**序列化后**的字符串：
#: 真实参数 `{"cmd": "a=[\"api\"]"}` 到手时字面量是 `a=[\"api\"]`。
#:
#: ⚠️ 这是 2026-11-01 定位到的第二个"守卫装了等于没装"：字面量正则写的是
#: `["']([\w./:-]+)["']`，遇到 `\"api\"` 时左引号能匹配、右引号前多了个
#: 反斜杠就匹配不上，于是**整条调用的所有字面量都被静默丢弃**。真实运行里
#: 1440 个候选路径的扫描返回 `None`，守卫一次都不触发。
_UNESCAPE = (
    ("\\/", "/"),
    ('\\"', '"'),
    ("\\'", "'"),
    ("\\n", "\n"),
    ("\\t", "\t"),
)


def _normalise(args: str) -> str:
    """把 JSON 转义还原成可读文本，让判定看到**真实**的参数内容。

    只做替换，不解析 JSON：参数可能是半截的、非法的、或被截断的，用
    ``json.loads`` 会抛异常并让守卫在整个 run 里静默失效。

    Args:
        args: 工具调用的原始参数串。

    Returns:
        反转义后的文本；输入为空时原样返回。
    """
    if not args:
        return ""
    out = args
    for escaped, plain in _UNESCAPE:
        out = out.replace(escaped, plain)
    return out


def _distinct(patterns: list[tuple[str, re.Pattern[str]]], args: str) -> dict[str, set[str]]:
    """按族收集参数里出现过的不同取值。"""
    families: dict[str, set[str]] = {}
    for name, pattern in patterns:
        for match in pattern.finditer(args or ""):
            value = match.group(match.lastindex or 0)
            if value:
                families.setdefault(name, set()).add(value)
    return families


def _kv_families(args: str) -> dict[str, set[str]]:
    """把 `?k=v` 和 `"k": "v"` 折叠成 ``{参数名: {取值...}}``。"""
    out: dict[str, set[str]] = {}
    for pattern in (_QUERY_RE, _JSON_KV_RE):
        for match in pattern.finditer(args or ""):
            key, value = match.group(1), match.group(2)
            if key and value:
                out.setdefault(key, set()).add(value)
    return out


def _generated_sweep(args: str) -> tuple[str, int] | None:
    """检测"取值由程序算出"的扫描，返回 ``(族名, 估算规模)``。

    043 的真实形态：40 个种子词 + `itertools.product` + 分块 POST。
    参数里没有 3320 个字面量，但有**组合放大**的结构。
    """
    if not args:
        return None
    if not _COMBINE_RE.search(args):
        return None
    if not _SEND_RE.search(args):
        return None

    # 粗略估规模：种子里不同字符串个数 x 组合层数。
    # 规模估算必须反映**请求数**，不能只数字面量。
    #
    # 旧版是 ``max(estimate, SWEEP_HARD)``：下限直接顶到硬阈值，于是
    # "两个正则都命中"就等于硬命中，估算形同虚设；``for i in 1 2 3; do
    # curl ...; done`` 会被判成 8000 次爆破（实测误伤 1/10）。提示一旦恒亮，
    # 模型就学会忽略它，比不装还差。
    #
    # 现在的四条线索各算各的，取最大：
    #   1. 不同字面量个数（字典规模本身）；
    #   2. `itertools.product(x, x)` 同变量 → 平方（050 的 6 个词是 36 次）；
    #   3. 推导式个数 → 种子 × (推导式数 + 1)（050 的 `[/{x}] + [/api/{x}]` 是 2 遍）；
    #   4. `range(N)` 的上界。
    seeds = {m.group(1) for m in _STR_LITERAL_RE.finditer(args)}
    scale = len(seeds)

    if _PRODUCT_SAME_RE.search(args):
        scale = max(scale, len(seeds) ** 2)

    comps = len(_COMP_RE.findall(args))
    if comps:
        scale = max(scale, len(seeds) * (comps + 1))

    for m in _RANGE_RE.finditer(args):
        try:
            scale = max(scale, int(m.group(1)))
        except (TypeError, ValueError):
            continue

    if scale < SWEEP_WARN:
        return None
    return "generated", scale


def sweep_summary(args: str) -> tuple[str, int] | None:
    """返回 ``(族名, 不同取值个数)``；不构成扫描时返回 None。

    只报告**最严重**的那一族。

    Args:
        args: 工具调用参数的原始字符串。

    Returns:
        ``(family, count)``，或 None。
    """
    # 必须先反转义：`on_invoke_tool` 交来的是序列化后的 JSON，真实形态是
    # `a=[\"api\",\"v1\"]`。直接在原串上跑正则会因为引号前的反斜杠
    # 而**一个都匹配不到**——050 复跑时 1440 个候选路径判成 None 就是这个原因。
    args = _normalise(args)
    if not args:
        return None

    best: tuple[str, int] | None = _generated_sweep(args)

    includes = {m.group(1) for m in _INCLUDE_RE.finditer(args)}
    if includes and (best is None or len(includes) > best[1]):
        best = ("@@INCLUDE", len(includes))

    for name, values in _kv_families(args).items():
        if best is None or len(values) > best[1]:
            best = (f"param:{name}", len(values))

    literals = {m.group(1) for m in _STR_LITERAL_RE.finditer(args)}
    if len(literals) >= SWEEP_WARN and (best is None or len(literals) > best[1]):
        best = ("wordlist", len(literals))

    opaque = {m.group(1) for m in _OPAQUE_ID_RE.finditer(args)}
    if len(opaque) >= SWEEP_WARN and (best is None or len(opaque) > best[1]):
        best = ("identifier", len(opaque))

    if best is None or best[1] < SWEEP_WARN:
        return None
    return best


def hint_for(family: str, count: int) -> str | None:
    """按扫描规模生成提示；不足阈值返回 None。"""
    if count < SWEEP_WARN:
        return None

    if family == "generated":
        return (
            "\n\n[SWEEP GUARD] This tool call ENUMERATES a name space in code "
            "(the candidates are computed at runtime, so this is not one probe — "
            "it is thousands of retries of one assumption). "
            "The response pattern has already told you the space is wrong.\n"
            "Stop generating names. Instead:\n"
            "  1. List the identifiers the app itself has ALREADY returned to you "
            "(ids, note keys, usernames, paths). Those are ground truth.\n"
            "  2. Read the CONTENT of each known identifier — GET its detail "
            "endpoint, or follow the reference the app hands you.\n"
            "  3. If the content is still not the answer, change mechanism: the "
            "scheduled/background path, auth boundary, or the data the app "
            "discloses about itself."
        )

    hard = count >= SWEEP_HARD
    head = (
        f"\n\n[SWEEP GUARD] This ONE tool call swept {count} distinct values of "
        f"'{family}'. In call-level terms that is a single probe; in hypothesis "
        f"terms it is the same assumption retried {count} times — and the "
        "response already told you it does not vary."
    )
    if hard:
        tail = (
            "\nThis is brute force against a name space, not a mechanism. Stop it.\n"
            "Do this instead, in order:\n"
            "  1. List the identifiers you have ALREADY seen in this run's responses "
            "(ids, note keys, usernames, file paths). Those are ground truth; a "
            "guessed name is not.\n"
            "  2. Fetch each known identifier's CONTENT directly (GET the detail "
            "endpoint, or follow the reference the app gives you).\n"
            "  3. Only if that yields nothing, switch mechanism: auth bypass, "
            "parameter pollution, file read, or the scheduled/background path the "
            "app itself uses."
        )
    else:
        tail = (
            "\nBefore the next call, answer: do I already have a list of real "
            "identifiers from the responses? If yes, read their contents instead of "
            "guessing more names. If no, this sweep is the wrong tool — pick a "
            "different mechanism."
        )
    return head + tail

#: 施加过本守卫的工具会带上这个标记，避免与其它守卫套娃。
_MARK = "_ctf_sweep_guarded"

#: 只对"能把请求发出去"的工具做扫描判定。单一来源见 ``probe_surface``。
_PROBE_TOOLS = PROBE_TOOLS


class SweepGuard:
    """单次调用内部的扫描检测器。

    只保留计数字段，判定逻辑全部走模块级纯函数（`sweep_summary` /
    `hint_for`），这样"判定对不对"可以脱离 agent 单独测。
    """

    def __init__(self) -> None:
        self.hits = 0
        self.warn = 0
        self.hard = 0
        self.worst = 0

    def check(self, tool_name: str, args: str) -> str | None:
        """检查一次工具调用的参数，命中就返回要追加到结果尾部的提示。

        Args:
            tool_name: 工具名。
            args: 原始参数串。

        Returns:
            提示文本；未命中返回 None。
        """
        if tool_name not in _PROBE_TOOLS:
            return None
        summary = sweep_summary(args)
        if summary is None:
            return None
        family, count = summary
        hint = hint_for(family, count)
        if hint is None:
            return None
        self.hits += 1
        self.worst = max(self.worst, count)
        if count >= SWEEP_HARD:
            self.hard += 1
        else:
            self.warn += 1
        return hint

    def stats(self) -> dict[str, int]:
        """计数快照：命中数、警告数、硬拦数、单次最大扫描规模。"""
        return {
            "hits": self.hits,
            "warn": self.warn,
            "hard": self.hard,
            "worst": self.worst,
        }


def install() -> SweepGuard:
    """把扫描守卫挂到所有工具调用入口上。

    ⚠️ **必须在 `guard_mount.install_mount_hook()` 之后调用**，理由与
    `enum_guard.install()` 完全一致：`exec_command` 走 Shell capability 的
    配置路径，绕开 `factory._with_bounded_result`，光替换那个函数挂不到它。

    这个 `install()` 本身是 2026-11-01 才补的。在此之前 `sweep_guard` 只有
    两个纯函数，模块文档写得很完整、单测式的逻辑推演也对，但**没有任何
    地方 import 它**——一次 run 用一条 `exec_command` 打了约 36,000 个
    路径变体，`enum_hits` 与 `sweep` 计数双双为 0，577 秒后失败。
    这是"守卫装了但等于没装"的第二次复现，所以这里同时把标记登记进
    `guard_mount.verify_mount()` 的期望集合，让没挂上在启动时就出声。

    Returns:
        已安装的守卫实例，供统计读取。
    """
    from strix.agents import factory

    guard = SweepGuard()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":  # noqa: F821
        tool = original(tool)
        if getattr(tool, _MARK, False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:  # noqa: ANN401, F821
            # 提示只依赖参数，可以在调用**之前**算出来：先拿到结果再提示，
            # 对"这次调用已经烧掉 36,000 次请求"没有任何补救作用。
            # 但顺序上仍要保留原结果——不拒绝，理由见模块文档。
            hint = guard.check(tool.name, raw_input)
            result = await inner(ctx, raw_input)
            if hint:
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        setattr(tool, _MARK, True)
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
