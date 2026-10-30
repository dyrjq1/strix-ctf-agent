"""运行时旅程守卫：把"先走通正常用户旅程"从 prompt 建议变成硬约束。

## 为什么需要它（和 `enum_guard` 是同一个教训）

`config/ctf_goal.txt` 里已经写了一段 ``COMPLETE THE NORMAL USER JOURNEY``，
并且**实测有效**：CTFARENA-012 从未注册账号（39 次调用失败），改完之后
CTFARENA-002、016 都走了登录流程并解出（11 次、10 次）。

但有效的证据只有 2 个样本，而且它和枚举规则一样**只是 prompt**。枚举规则的
下场是写了两版都没生效——模型在第 5 次调用时，历史里那 4 次探测已经被后来的
工具输出埋掉了，对"我重复了/我还没登录"没有感知。

所以这里把判定搬进代码：跟踪"是否见过认证墙"、"是否认证成功"、"是否成功创建过
资源"，在模型仍处于未认证状态却开始灌攻击载荷时，**在工具结果尾部注入提示**。

## 判定设计：为什么必须先见到 401/403 才介入

不能一上来就要求"去注册账号"。纯注入题（命令注入、SSTI、文件读取）根本没有
账号体系，强制要求注册会把模型推向错误方向——比原来的问题更糟。

所以守卫的**激活条件**是"探测过认证端点且被拒绝"，即目标确实竖了一道认证墙。
从这一刻起，未认证就意味着拿不到应用的核心数据，攻击载荷打在墙上只是浪费。

解除条件有两条：认证成功（拿到 cookie/token），或成功创建过资源。任一满足即
永久静默——之后的判断交还给模型，程序不再干预。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents import FunctionTool


#: 计为"与目标交互"的工具。其余（读本地文件、记账）不计入。
#: 名单与 `enum_guard._PROBE_TOOLS` 保持一致，理由见那里的注释——
#: `browser_*` / `http_request` 在 strix 里不存在，写了等于没写。
_PROBE_TOOLS = ("exec_command", "write_stdin", "repeat_request")

#: 表示"这是认证端点"的线索，出现在调用参数里。
_AUTH_HINT_RE = re.compile(
    r"/login|/signin|/auth|/session|/register|/signup|/api/users|/token|/oauth",
    re.IGNORECASE,
)

#: 表示"被拒绝"的线索，出现在输出里。
_DENIED_RE = re.compile(
    r"\b401\b|\b403\b|unauthoriz|forbidden|invalid credential|not authenticated"
    r"|login required|请先登录|未登录",
    re.IGNORECASE,
)

#: 表示"认证成功"的线索，出现在输出里。Set-Cookie 是最硬的信号。
_AUTH_OK_RE = re.compile(
    r"set-cookie:|access_token|\"token\"\s*:|session=|Bearer\s+[A-Za-z0-9._\-]{10,}",
    re.IGNORECASE,
)

#: 表示"成功写入/创建"的线索。匹配响应体里的自增 id 或 201。
_CREATE_OK_RE = re.compile(r"\b201\b|\"id\"\s*:\s*\d+|\"id\"\s*:\s*\"[^\"]{4,}\"")

#: 写请求的迹象，出现在参数里。
_WRITE_RE = re.compile(r"-X\s*(POST|PUT|PATCH)|--data|--json|-d\s+['\"]?\{|method=[\"']?(POST|PUT)")

#: 攻击载荷特征。命中说明模型已经在打洞，而不是在走业务流程。
#:
#: ⚠️ 这里踩过两次同一个坑，都是"正则写太紧 → 守卫静默失效"：
#:   1. 早先写成 `'\s*or\s+1=1`（强制带引号），`?id=1 or 1=1` 完全不命中；
#:   2. 改成引号可选之后，`?id=1%20or%201=1` 这种 **URL 编码**写法又漏掉了——
#:      实测 `wall=9 payloads=0`，认证墙识别正常，载荷一发都没数到。
#: 结论：判定"是不是在灌载荷"宁可宽松，漏数一个载荷比漏判一次干预代价小得多。
#: 允许 `%20` / `+` 出现在运算符之间，并容忍等号两侧无空格。
_SQL_SPACE = r"(?:\s|%20|\+|/\*.*?\*/|\*\*/)"
_PAYLOAD_RE = re.compile(
    # or 1=1 / or '1'='1 / 'or'1'='1 —— 引号可能紧贴关键字，逐个允许
    rf"['\"]?{_SQL_SPACE}*or{_SQL_SPACE}*['\"]?{_SQL_SPACE}*1{_SQL_SPACE}*['\"]?{_SQL_SPACE}*="
    rf"|union{_SQL_SPACE}*(all{_SQL_SPACE}+)?select"
    rf"|sqlmap|'{_SQL_SPACE}*and{_SQL_SPACE}+sleep|\bsleep\(\d"
    rf"|\{{\{{.*?\}}\}}|\$\{{.*?\}}|__class__|__subclasses__"
    rf"|\$ne|\$gt|\$where|\$regex"
    rf"|\.\./|%2e%2e"
    rf"|;\s*(id|whoami|cat|ls)\b|\|\s*(id|whoami|cat)\b|\$\(|`"
    rf"|<script|onerror=|javascript:",
    re.IGNORECASE,
)

#: 见到认证墙之后，打了几发载荷开始提醒。
_WARN_AFTER = 3
#: 到这个次数升级为强指令。
_HARD_AFTER = 6
#: 两次提示之间至少隔几次载荷，避免每轮都刷屏（刷屏会挤占上下文预算）。
_QUIET_GAP = 3

_JOURNEY_WARN = (
    "\n\n[USER JOURNEY GUARD] You are firing attack payloads at a target that has "
    "already told you {why}. That is the wrong move: an authorization bug lives in a "
    "feature you have authenticated access to, not behind a 401 you keep hammering.\n"
    "Before your next payload, do these in order:\n"
    "  1. Find the register/signup endpoint — try /api/register, /api/signup, "
    "/api/users, POST /register. It is almost never the one that returned 401.\n"
    "  2. Log in and keep the session cookie (`curl -c cj.txt -b cj.txt`).\n"
    "  3. As that user, CREATE the resource the app is about (a pin, note, order, memo).\n"
    "  4. Read it back, then walk IDs around yours while authenticated — the flag is "
    "usually another user's object."
)

_JOURNEY_HARD = (
    "\n\n[USER JOURNEY GUARD — HARD STOP] {n} payloads sent, still unauthenticated, "
    "still no flag. Stop payload work entirely.\n"
    "You MUST NOT send another injection/payload request until one of these is true:\n"
    "  · you hold a session cookie or token from a successful login, OR\n"
    "  · you have sent a 2xx write request that created a resource as an authenticated user.\n"
    "If registration genuinely does not exist, say so explicitly and name the exact "
    "endpoint you checked before falling back to payloads."
)


@dataclass
class JourneyState:
    """守卫的运行时状态。

    单独抽出来是为了能在测试里直接构造和断言，不必跑一次真实 agent。
    """

    #: 见过几次"认证端点被拒"。大于 0 说明目标有认证墙，守卫激活。
    wall_hit: int = 0
    #: 是否拿到过会话（Set-Cookie / token）。
    authed: bool = False
    #: 是否成功创建过资源（认证后的写入）。
    created: bool = False
    #: 激活之后打出的载荷数。
    payloads: int = 0
    #: 上次提示时的载荷计数，用于控制间隔。
    last_prompt_at: int = field(default=-999)
    #: 累计提示次数，便于运行后统计守卫是否真的介入了。
    prompts: int = 0
    #: `observe` 被调用过多少次（含不干预的）。
    #:
    #: 这个字段是本轮加的关键观测点。守卫失效有两种形态：
    #:   · 逻辑错 → 调用次数正常，counter 全是 0，能看出"规则不对"；
    #:   · 接线错 → 调用次数**也是 0**，日志却打印了 "guard installed"。
    #: 第二种在旧统计里和"今天运气好没触发"完全无法区分。CTFARENA-012 就是这样
    #: 白跑一轮：45 次调用、16 次 401、守卫全 0，真实原因是 exec_command 根本没
    #: 经过守卫挂载点。有了这个字段，`reach=0` 会直接指出是接线问题。
    observe_calls: int = 0

    @property
    def released(self) -> bool:
        """是否已进入正常旅程（守卫永久静默）。"""
        return self.authed or self.created


class JourneyGuard:
    """检测"未认证就灌载荷"，并在工具结果里注入纠正提示。"""

    def __init__(self) -> None:
        self.state = JourneyState()

    def observe(self, tool_name: str, args: str, output: str) -> str | None:
        """记一次调用，返回要追加到结果后面的提示（或 None）。

        Args:
            tool_name: 工具名。
            args: 调用参数。
            output: 工具返回的原始结果（字符串化）。

        Returns:
            需要追加的提示文本；不需要干预时返回 None。
        """
        if not any(tool_name.startswith(p) for p in _PROBE_TOOLS):
            return None

        st = self.state
        st.observe_calls += 1

        # ① 先看解除条件。Set-Cookie / token 是硬信号，看到就永久放行。
        if _AUTH_OK_RE.search(output):
            st.authed = True
        if _WRITE_RE.search(args) and _CREATE_OK_RE.search(output):
            st.created = True
        if st.released:
            return None

        # ② 识别认证墙：参数指向认证端点，且输出显示被拒。
        # ⚠️ 这里**不能** return——最典型的场景就是"一边打认证端点一边灌载荷"，
        # 比如 `curl '.../api/login?id=1 or 1=1'`。早先写成识别到墙就 return，
        # 结果载荷永远数不到：实测 9 次调用后 `wall=9 payloads=0 prompts=0`，
        # 守卫看着在跑，其实一次也不会介入。识别墙和数载荷要分开算，
        # 同一发调用可以既是"确认有墙"又是"一发载荷"。
        denied = bool(_DENIED_RE.search(output))
        if _AUTH_HINT_RE.search(args) and denied:
            st.wall_hit += 1

        # ③ 未激活就什么都不做——纯注入题不该被这个守卫干扰。
        if st.wall_hit == 0:
            return None

        # 注意：这里**不再**排除"打认证端点且被拒"的调用。同一个 `curl` 里
        # 既有 `/api/login` 又有 `or 1=1`，它就是一枚载荷——加一层排除会把
        # 真实运行里最常见的那种调用全吞掉（试过一次，`wall` 涨到 8、`payloads`
        # 还是 0）。判定只看"有没有载荷特征"，不看它打的是哪个路径。
        if not _PAYLOAD_RE.search(args):
            return None

        st.payloads += 1
        n = st.payloads

        if n >= _HARD_AFTER and n - st.last_prompt_at >= _QUIET_GAP:
            st.last_prompt_at = n
            st.prompts += 1
            return _JOURNEY_HARD.format(n=n)

        if n >= _WARN_AFTER and n - st.last_prompt_at >= _QUIET_GAP:
            st.last_prompt_at = n
            st.prompts += 1
            why = "401/403 on its authentication endpoint"
            return _JOURNEY_WARN.format(why=why)

        return None


def install() -> JourneyGuard:
    """包装工具调用入口，装上旅程守卫。

    与 `enum_guard.install` 用同一手法：改 ``on_invoke_tool``，不动 vendor 代码，
    strix 升级不需要 rebase。两个守卫可以叠加安装，顺序无关。

    ⚠️ **调用前必须先执行 `guard_mount.install_mount_hook()`**，否则
    ``exec_command``（唯一能把请求打到靶机上的工具）根本走不到这里。
    本轮 CTFARENA-012 守卫零触发的根因就是这个，详见 guard_mount 模块。

    Returns:
        已安装的守卫实例，供运行后统计。
    """
    from strix.agents import factory

    guard = JourneyGuard()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, "_ctf_journey_guarded", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            # 与枚举守卫不同，这里必须拿到 output——认证成功与否只体现在响应里。
            hint = guard.observe(tool.name, raw_input, str(result))
            if hint:
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_journey_guarded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
