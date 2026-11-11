"""运行时旅程守卫：把"先走通正常用户旅程"从 prompt 建议变成硬约束。

## 为什么需要它（和 `enum_guard` 是同一个教训）

`config/ctf_goal.txt` 里已经写了一段 ``COMPLETE THE NORMAL USER JOURNEY``，
并且**实测有效**：一次 run 从未注册账号（39 次调用失败），改完之后
另外两道题都走了登录流程并解出（11 次、10 次）。

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

from ctf_strix.command_tokens import command_text as _shared_command_text
from ctf_strix.command_tokens import segments as _command_segments
from ctf_strix.probe_surface import PROBE_TOOLS

if TYPE_CHECKING:
    from agents import FunctionTool


#: 计为"与目标交互"的工具。单一来源见 ``probe_surface``：此前这里是 3 个
#: 名字的副本，``http_probe`` 等 4 个原语因此从不进入认证墙判定。
_PROBE_TOOLS = PROBE_TOOLS

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
#: output 侧五模式保持原样：它们盯的是"服务端把会话发回来了"。
_AUTH_OK_RE = re.compile(
    r"set-cookie:|access_token|\"token\"\s*:|session=|Bearer\s+[A-Za-z0-9._\-]{10,}",
    re.IGNORECASE,
)

#: curl / wget 必须是**一条 shell 命令的第一个词**（允许带路径与 ``.exe``）。
#: 这样 ``pycurl``、``python -c 'print("curl -b jar")'`` 都不会被当成发起了
#: HTTP 请求——参数里出现字符串不等于执行了那个命令。args 侧信号先过这道闸。
_SHELL_CURL_WGET_RE = re.compile(r"(?:[^\s;&|]*/)?(?:curl|wget)(?:\.exe)?(?=\s|$)", re.IGNORECASE)

#: curl 的 cookie 选项：``-b/--cookie`` 表示"带会话去请求"，``-c/--cookie-jar``
#: 表示"把响应里的会话存下来"。**只在 curl 段内判定**：``-c`` 在 wget 里是
#: 断点续传，在 grep 里是计数，全文扫描会把它们误当成会话证据。
_CURL_COOKIE_OPTIONS = frozenset({"-b", "--cookie", "-c", "--cookie-jar"})

#: wget 的 cookie 选项：``--load-cookies`` / ``--save-cookies`` 需要文件名，
#: ``--keep-session-cookies`` 是独立开关。wget 的 ``-c`` 不属于这一类。
_WGET_COOKIE_OPTIONS = frozenset(
    {"--load-cookies", "--save-cookies", "--keep-session-cookies"}
)

#: 显式 Cookie 请求头：``-H 'Cookie: sid=abc'`` / ``--header "Cookie: a=b"``。
#: 只认 curl/wget 段里的 ``-H``：别条命令里的同名字符串不是会话证据。
_HEADER_COOKIE_VALUE_RE = re.compile(
    r"\\?[\"']?Cookie:\s*[^\\\"'\s=;]+=\S+",
    re.IGNORECASE,
)


def _command_text(args: str) -> str:
    """从工具参数里取出真正会被 shell 执行的文本。

    工具参数是 JSON（``{"command": "curl ..."}``）。先解码再判断，才能区分
    "执行了 curl" 和 "在 python 脚本里打印了字符串 curl"，也能把 JSON 转义
    的引号还原成正常引号供 Cookie 头匹配。
    """
    return _shared_command_text(args)


def _shell_client(token: str) -> str | None:
    """Return ``curl``/``wget`` when ``token`` is that executable, else None."""
    if not _SHELL_CURL_WGET_RE.match(token):
        return None
    base = token.rsplit("/", 1)[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base if base in ("curl", "wget") else None


def _heredoc_delimiter(line: str) -> tuple[str, bool] | None:
    """Delimiter of a here-document opened on this line, plus its ``<<-`` flag.

    The body of a here-document is data, not a command: a line inside it that
    starts with ``curl`` must not release the guard.  Only an unquoted ``<<``
    followed by a word opens a document; ``$((1<<2))`` and here-strings are
    ignored.

    Returns:
        ``(delimiter, strip_tabs)``.  ``strip_tabs`` is true for ``<<-``, the
        only form whose terminator bash accepts with leading tabs.
    """
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if line.startswith("<<", index):
            cursor = index + 2
            strip_tabs = cursor < len(line) and line[cursor] == "-"
            if strip_tabs:
                cursor += 1
            while cursor < len(line) and line[cursor] in " \t":
                cursor += 1
            if cursor < len(line) and line[cursor] in "\"'":
                mark = line[cursor]
                cursor += 1
                end = line.find(mark, cursor)
                word = line[cursor:end] if end >= 0 else ""
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word):
                    return word, strip_tabs
                index = cursor
                continue
            match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", line[cursor:])
            if match:
                return match.group(0), strip_tabs
        index += 1
    return None


def _is_heredoc_terminator(line: str, delimiter: str, strip_tabs: bool) -> bool:
    """Is ``line`` the terminator that closes this here-document?

    The terminator must match the whole line, allowing only the trailing ``\r``
    of CRLF input.  A space-indented ``  EOF`` is *not* a terminator: bash keeps
    it as body text, so accepting it would hand the remaining lines to the
    command scanner——and a following ``curl -H 'Cookie: ...'`` would re-open
    the authentication false positive this guard exists to prevent.  ``<<-``
    additionally allows leading tabs (POSIX), which is the only indentation
    bash accepts for a terminator.
    """
    candidate = line[:-1] if line.endswith("\r") else line
    if strip_tabs:
        candidate = candidate.lstrip("\t")
    return candidate == delimiter


def _strip_heredoc_bodies(text: str) -> str:
    """Drop here-document bodies so their text is never read as a command."""
    lines = text.split("\n")
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        kept.append(line)
        opened = _heredoc_delimiter(line)
        index += 1
        if opened is None:
            continue
        delimiter, strip_tabs = opened
        while index < len(lines) and not _is_heredoc_terminator(
            lines[index], delimiter, strip_tabs
        ):
            index += 1
        index += 1
    return "\n".join(kept)


def _cookie_option_in_segment(tokens: list[str], client: str) -> bool:
    """Does this curl/wget segment carry a cookie-jar style option?"""
    options = _CURL_COOKIE_OPTIONS if client == "curl" else _WGET_COOKIE_OPTIONS
    for token in tokens[1:]:
        name, _, _ = token.partition("=")
        if name in options:
            return True
        if (
            client == "curl"
            and not token.startswith("--")
            and len(token) > 2
            and token[:2] in ("-b", "-c")
        ):
            return True
    return False


def _header_cookie_in_segment(tokens: list[str]) -> bool:
    """Does this curl/wget segment set a literal Cookie request header?"""
    for index, token in enumerate(tokens[1:], 1):
        if token in ("-H", "--header"):
            if index + 1 < len(tokens) and _HEADER_COOKIE_VALUE_RE.match(tokens[index + 1]):
                return True
            continue
        if token.startswith("--header="):
            if _HEADER_COOKIE_VALUE_RE.match(token[len("--header="):]):
                return True
            continue
        if token.startswith("-H") and len(token) > 2:
            candidate = token[2:]
            if candidate.startswith("="):
                candidate = candidate[1:]
            if _HEADER_COOKIE_VALUE_RE.match(candidate):
                return True
    return False


def _args_session_signal(args: str) -> bool:
    """参数里是否出现"正在使用会话"的通用信号。

    会话证据只认 curl/wget 段内的 cookie 选项与显式 ``Cookie:`` 请求头——
    ``-H`` 头也走同一道 token 级门控。三类误报因此被排除：

    1. ``-b`` / ``-c`` 在别的命令里另有含义（``grep -c`` 计数、``sort -b``
       忽略前导空白、``python -c`` 执行代码），只按命令首词判断是不是 curl/wget；
    2. ``echo`` / ``printf`` / ``python -c`` 里出现的 ``-H 'Cookie: ...'``
       只是被打印或写进文件的字符串，命令本身没有发出带会话的请求；
    3. here-document 正文是数据不是命令，先剥离正文再切命令段，
       ``cat > notes.sh <<'EOF'`` 里的 curl 行不算会话证据。
    """
    if not args:
        return False
    text = _strip_heredoc_bodies(_command_text(args))
    for tokens in _command_segments(text):
        client = _shell_client(tokens[0])
        if client is None:
            continue
        if _cookie_option_in_segment(tokens, client) or _header_cookie_in_segment(tokens):
            return True
    return False


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
    #: 第二种在旧统计里和"今天运气好没触发"完全无法区分。一次 run 就是这样
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
        if tool_name not in _PROBE_TOOLS:
            return None

        st = self.state
        st.observe_calls += 1

        # ① 先看解除条件。Set-Cookie / token 是硬信号，看到就永久放行。
        # 输出侧看不到会话时，再看**参数侧**的 curl/wget cookie jar 与 Cookie 头：
        # `curl -b jar -c jar ...` 登录成功后，output 往往只有一行菜品列表，
        # 一个认证标记都不出现，而命令本身已经证明会话在工作流里流转。
        if _AUTH_OK_RE.search(output) or _args_session_signal(args):
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
    此前一次 run 的守卫零触发的根因就是这个，详见 guard_mount 模块。

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
