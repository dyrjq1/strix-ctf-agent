"""运行时枚举守卫：把"别刷端点"从建议变成硬约束。

## 为什么需要它

`config/ctf_goal.txt` 里写过两版枚举收敛规则（"最多 6 次后必须转向假设"、
"重复探测不算进展"），**实测都没生效**：CTFARENA-018 在新规则下仍然把
`robots.txt / sitemap.xml / favicon.ico / api` 这一族路径刷了 4 遍，直到撞墙钟。

原因不难理解——模型在第 5 次调用时，历史里那 4 次探测已经被后来的工具输出
埋掉了，它对"我重复了"没有感知。**上下文里的自我约束会随轮次衰减，程序里的
计数器不会。**

所以把计数搬进代码：包装每个工具的 `on_invoke_tool`，对命令类调用做
归一化指纹，统计同一族命令的重复次数，超限就在**工具返回结果里**追加一条
警告。工具结果一定会回到模型上下文，且紧挨着下一步决策——这是纠正行为
最有效的位置。

## 为什么用"结果注入"而不是"直接拒绝"

直接拒绝会让 agent 反复重试同一个调用，反而烧更多轮次。注入警告保留了原
结果，模型能继续干活，只是被明确告知"这条路重复了，该换机制"。
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool


#: 计为"探测目标"的工具。其余（读本地文件、记账）不计入。
#:
#: ⚠️ 这份名单必须对着 strix 的真实工具面写。早先写的是
#: ``("exec_command", "write_stdin", "browser_", "http_request")``——
#: ``browser_*`` 和 ``http_request`` 在 strix 里**根本不存在**（核对
#: ``factory._BASE_TOOLS`` 与 ``Shell`` capability 得到的实际名单是
#: ``exec_command`` / ``write_stdin`` / ``repeat_request`` / ``apply_patch`` /
#: ``view_image`` 等）。不存在的名字不会报错，只会让守卫永远不匹配，
#: 属于最难查的一类失效。
_PROBE_TOOLS = ("exec_command", "write_stdin", "repeat_request", "http_probe")
#: ``http_probe`` 是 P1 新增的结构化原语。不加进这份名单，它就绕过了
#: 所有枚举计数——新工具最典型的失效方式不是报错，是"守卫根本不认识它"。

#: 超过这个次数就开始警告。取 4 而不是 5，留一次给"确实需要补一枪"的情况。
_WARN_AFTER = 4
#: 到这个次数警告升级为强指令。
_HARD_AFTER = 7

#: 从命令里提取"被探测的路径族"。抽不出来就不计——宁可漏抓，不可误伤。
_PATH_RE = re.compile(r"[A-Za-z0-9_\-./]*(?:api|admin|flag|config|debug|static|assets)[A-Za-z0-9_\-./]*")
_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
#: 爆破扫描的特征：占位符出现在 URL 里，或调用了常见字典扫描器。
_BRUTE_MARK_RE = re.compile(
    r"\bFUZZ\b|\bffuf\b|\bdirsearch\b|\bgobuster\b|\bferoxbuster\b|\bwfuzz\b|\bnuclei\b"
)


def _host_of(args: str) -> str | None:
    """取命令里第一个目标 host。

    ⚠️ 正则必须只吃合法主机名字符。早先写成 ``[^/\\s"']+`` 时，shell 里的
    ``B=https://host; for p in ...`` 会把分号当成 host 的一部分，于是同一个
    靶机被算成四个不同的族，计数彻底失效——真实日志重放时 46 次调用只触发
    了 2 次警告，全是这个原因。
    """
    m = _HOST_RE.search(args)
    return m.group(1).rstrip(".;:") if m else None


def _fingerprint(tool_name: str, args: str) -> str | None:
    """把一次探测归一化成指纹，用于判断"是不是同一族"。

    只保留：工具名 + 目标 host + 命中的业务路径词。丢掉具体的 URL 参数、
    文件名、随机串——那些正是模型用来"换个参数重试"的空间。

    Args:
        tool_name: 工具名。
        args: 调用参数的原始字符串。

    Returns:
        指纹；无意义的调用（如纯 `ls`、`pwd`）返回 None。
    """
    if not any(tool_name.startswith(p) or tool_name == p for p in _PROBE_TOOLS):
        return None

    host = _host_of(args)
    if not host:
        return None  # 没打目标，不算探测

    # 只看 host 之后的路径部分，取其中**倒数第二段**作为族名。
    # ⚠️ 三种写法都踩过坑：
    #   · 直接在整条命令里找路径 → 把 host 本身也算进去，`/api/coins/stats`
    #     和 `/api/coins/tiers` 变成两个不同族，同族刷新反而逃过计数；
    #   · 命中关键词后整条丢弃 → 真实命令里的路径段常以 host 开头，全被过滤光；
    #   · host 正则吃进 shell 分隔符 → 同一靶机被算成四个族，实测 46 次调用
    #     只触发 2 次警告。
    # 正确做法是先用严格的 host 正则切一刀，只在右边找关键词。
    tail = args[args.find(host) + len(host) :]
    families = set()
    for m in _PATH_RE.finditer(tail):
        segs = [s for s in m.group(0).strip("/").split("/") if s]
        # 丢掉大写开头的 shell 变量名（`B=/api/...` 里的 B 会粘在路径前面）。
        segs = [s for s in segs if not s[:1].isupper()]
        if not segs:
            continue
        families.add(segs[-2] if len(segs) >= 2 else segs[-1])

    # 爆破工具本身就是在枚举，即使 URL 里没有业务关键词也要计。
    # 它们的特征是把占位符放在路径里，或用字典文件扫。
    if _BRUTE_MARK_RE.search(args):
        families.add("bruteforce")

    if not families:
        return None

    return f"{tool_name}|{host}|{sorted(families)[0]}"


class EnumerationGuard:
    """统计探测重复度，并在工具结果里注入纠正提示。"""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.warned: set[str] = set()
        #: `observe` 被调用过多少次（含没有指纹、不计数的情况）。
        #: 用途同 `JourneyState.observe_calls`：区分"规则没命中"和"根本没接线"。
        self.observe_calls: int = 0

    def observe(self, tool_name: str, args: str) -> str | None:
        """记一次调用，返回要追加到结果后面的提示（或 None）。

        Args:
            tool_name: 工具名。
            args: 调用参数。

        Returns:
            提示文本；不需要提示时返回 None。
        """
        self.observe_calls += 1
        key = _fingerprint(tool_name, args)
        if key is None:
            return None

        self.counts[key] += 1
        n = self.counts[key]

        if n >= _HARD_AFTER:
            return (
                f"\n\n[ENUMERATION GUARD] You have now probed this same path family "
                f"{n} times ('{key.split('|')[-1]}'). This is not progress. "
                "You MUST NOT send another request against this family. "
                "Switch to a different mechanism now: parameter injection, auth bypass, "
                "file read, SSTI, SSRF pivot, or read whatever access you already have. "
                "If you already have code execution or DB read, USE IT to find the flag file."
            )
        if n >= _WARN_AFTER and key not in self.warned:
            self.warned.add(key)
            return (
                f"\n\n[ENUMERATION GUARD] This is attempt {n} against the same path family "
                f"('{key.split('|')[-1]}'). Stop enumerating names. State one concrete "
                "exploitation hypothesis (mechanism + exact request + expected response) "
                "and send it instead."
            )
        return None


def install() -> EnumerationGuard:
    """包装所有工具的调用入口，装上枚举守卫。

    照抄 strix 自己在 ``agents/factory.py:149`` 的包装手法（改
    ``on_invoke_tool``），这样不用改 vendor 代码，升级 strix 也不需要 rebase。

    ⚠️ **调用前必须先执行 `guard_mount.install_mount_hook()`**。仅替换
    ``_with_bounded_result`` 只能覆盖常规工具列表，``exec_command`` 走的是
    ``Shell`` capability 的配置路径，绕开了这个函数——详见 guard_mount 模块
    开头的实测记录。

    Returns:
        已安装的守卫实例，供测试或统计读取。
    """
    from strix.agents import factory

    guard = EnumerationGuard()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, "_ctf_guarded", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            # 工具名从 tool 闭包取，多 agent 共用同一个守卫，计数是全局的。
            hint = guard.observe(tool.name, raw_input)
            result = await inner(ctx, raw_input)
            if hint:
                # 结果体量不确定（可能不是 str），统一转成字符串追加。
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_guarded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
