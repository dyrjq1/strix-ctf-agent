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

import hashlib
import re
from collections import Counter
from typing import TYPE_CHECKING, Any, Final

from ctf_strix.probe_surface import PROBE_TOOLS

if TYPE_CHECKING:
    from agents import FunctionTool


#: 计为"探测目标"的工具。单一来源在 ``probe_surface``——四个守卫共用同一份
#: 名单，避免出现"三个名字的副本永远匹配不到 http_probe"那类静默失效。
_PROBE_TOOLS = PROBE_TOOLS

#: 同一族连续 N 次拿到**完全相同**的响应就警告。计的是"第一次之后的重复次数"：
#: 2 表示第 3 次同响应。两次可能只是抖动，三次已经能断定这条路没有新信息。
_WARN_REPEATS = 2
#: 到这里升级成硬指令（禁止继续打这一族）。
_HARD_REPEATS = 4
#: 跨族连续零新信息的警告阈值，以及之后每隔多少次重复提醒。
_STALL_AFTER = 6
_STALL_REPEAT = 4
#: How many probes may pass without discovering a *new mechanism class* before
#: naming the untried classes.  Same cap as ``_STALL_AFTER`` on purpose: this is
#: another way of saying "six calls, no new ground", so it should not be a new
#: budget.  Only the *class* is new here, not the threshold.
_CLASS_STREAK_AFTER = _STALL_AFTER
_CLASS_STREAK_REPEAT = _STALL_REPEAT

#: 从命令里提取"被探测的路径族"。抽不出来就不计——宁可漏抓，不可误伤。
_PATH_RE = re.compile(r"[A-Za-z0-9_\-./]*(?:api|admin|flag|config|debug|static|assets)[A-Za-z0-9_\-./]*")
_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
#: 爆破扫描的特征：占位符出现在 URL 里，或调用了常见字典扫描器。
_BRUTE_MARK_RE = re.compile(
    r"\bFUZZ\b|\bffuf\b|\bdirsearch\b|\bgobuster\b|\bferoxbuster\b|\bwfuzz\b|\bnuclei\b"
)


#: CAPEC-1000 "Mechanisms of Attack" categories, in the vocabulary of a CTF.
#:
#: Why a taxonomy at all: the per-family counter above answers "did I send the
#: same request twice", but the costlier failure is *six different requests that
#: are the same hypothesis*.  CTFARENA-043 enumerated 52 names, then probed
#: ``/api/notes`` variants, ``?id=`` variants and ``/admin`` -- all of it inside
#: one mechanism (information collection), so every fingerprint was new, every
#: counter reset, and no guard said "you have not left this room".
#:
#: The nine categories are not invented here: they are the top level of MITRE
#: CAPEC view 1000 (https://capec.mitre.org/data/definitions/1000.html,
#: retrieved 2026-11-03), which groups attack patterns by mechanism rather than
#: by goal.  Mapping them onto request syntax is ours; the partition is theirs.
_MECHANISM_RULES: Final[tuple[tuple[str, str, str], ...]] = (
    # Order matters: first match wins, so narrow markers (``/admin``) come
    # before broad collectors (``.js``), and spoofing headers come before the
    # information-collection rule that would otherwise swallow them.
    (
        "225",
        "access-control",
        r"/admin\b|\brole\b|is_admin|\bjwt\b|authorization\s*:"
        r"|x-forwarded-for|x-forwarded-host|x-original-url|\bsession\b\s*=|\bcsrf\b",
    ),
    (
        "210",
        "abuse-functionality",
        r"\bupload\b|\bexport\b|\bimport\b|\bpreview\b|\brender\b"
        r"|\bwebhook\b|\bredirect\b|\bproxy\b|\bfetch\b|\bdownload\b"
        r'|(?:url|uri|target|dest)\s*[=:]\s*(?:\x27|")?(?:https?:|//)',
    ),
    (
        "255",
        "data-structures",
        r"__proto__|\bconstructor\b|\bprototype\b|\bpickle\b|\byaml\b|!!"
        r"|\bdeserial|O:\d+:|\bunserialize\b|\bjson\s*parse",
    ),
    (
        "152",
        "injection",
        r"union\s+select|\bor\s+1\s*=\s*1|\bsleep\s*\(|<script|javascript:"
        r"|\{\{|\$\{|%\{|\beval\s*\(|os\.system|\bcat\s+/etc/"
        r"|\|\s*(?:id|whoami|ls)\b|;\s*(?:id|whoami|ls)\b",
    ),
    (
        "262",
        "system-resources",
        r"/proc/|/dev/|\.\./|%2e%2e|file://|/etc/(?:passwd|shadow)|symlink"
        r"|\bchmod\b|\bchown\b|/flag|/root/|/tmp/",
    ),
    (
        "156",
        "deception",
        r"\b(?:origin|referer|host)\\?[\"\x27]?\s*:|%00|%0d%0a|\\r\\n"
        r"|@[a-z0-9.-]+\.[a-z]{2,}|xn--|\bunicode\b|\bhomograph",
    ),
    (
        "172",
        "timing-state",
        r"\brace\b|\bsleep\b|\btoctou\b|\breplay\b|\bcoupon\b|\bnonce\b"
        r"|\btimestamp\b|\bretry\b|\bconcurren",
    ),
    (
        "223",
        "probabilistic",
        r"\bfuzz\b|\bbrute|\bwordlist\b|\bdictionary\b|FUZZ|\bguess\b"
        r"|\brandom\b|\bpin\b|\botp\b",
    ),
    (
        "118",
        "information-collection",
        r"robots\.txt|sitemap|/\.git|\.env\b|swagger|openapi|\.well-known"
        r"|favicon|/static/|/bundle|\.js\b|\benumerat|\blisting\b",
    ),
)

#: Compiled once; ``.search`` on the raw argument blob.
_MECHANISM_RES: Final = tuple(
    (cid, name, re.compile(pattern, re.I)) for cid, name, pattern in _MECHANISM_RULES
)

#: Human-facing class names, in CAPEC order.  Used to tell the model which
#: classes it has *not* tried -- the actionable half of the hint.
MECHANISM_NAMES: Final[tuple[str, ...]] = (
    "access-control",
    "abuse-functionality",
    "data-structures",
    "injection",
    "system-resources",
    "deception",
    "timing-state",
    "probabilistic",
    "information-collection",
)


#: The rule table and the public order must describe the same set.  A class
#: missing from one side would silently vanish from the "untried" hint.
assert {name for _cid, name, _re in _MECHANISM_RES} == set(MECHANISM_NAMES)


#: A URL's "family" is everything but the last path segment, with the query
#: dropped.  ``/api/notes/note_a`` and ``/api/notes/note_b`` are one family.
_FAMILY_RE: Final = re.compile(r"https?://[^\s\"'<>]+")


def _path_family(args: str) -> str | None:
    """Return the request's path family, or ``None`` when there is no URL.

    Enumeration has no syntax marker: ``/api/notes/note_ab12`` and
    ``/api/notes/note_cd34`` are the same request with a different leaf.  The
    only way to see that is to compare the *shape* of consecutive URLs, which
    is what this helper extracts.

    Args:
        args: the raw tool-argument blob.

    Returns:
        ``scheme://host/dir/dir`` with the last segment and query removed.
    """
    match = _FAMILY_RE.search(args or "")
    if match is None:
        return None
    url = match.group(0).split("?", 1)[0].split("#", 1)[0].rstrip("/")
    tail = url.split("://", 1)[-1]
    if "/" not in tail:
        return url
    _host, path = tail.split("/", 1)
    if "/" not in path:
        return url.rsplit("/", 1)[0]
    return url.rsplit("/", 1)[0]


def _mechanism_of(args: str) -> str | None:
    """Classify one probe into a CAPEC mechanism class.

    Args:
        args: the raw tool-argument blob.

    Returns:
        A class name, or ``None`` when the request carries no mechanism marker
        (a plain ``GET /``, an ``ls``, a file read).  ``None`` is deliberate:
        guessing a class for an unclassifiable call would make the counter fire
        on ordinary work.
    """
    if not args:
        return None
    for _cid, name, pattern in _MECHANISM_RES:
        if pattern.search(args):
            return name
    return None


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


#: "又在读前端 bundle" 的特征：curl/wget 一个 .js、cat 一个 .js、或 read_file 到 .js。
#: 这不是浪费一次调用的问题——009/018 实测各花 4-6 次调用把 chunk 逐段 cat 出来，
#: 而 route_map 一次就能给路径表。工具已经给出答案时，旧习惯仍会覆盖它。
_BUNDLE_RE = re.compile(
    r"(?:curl|wget)\s[^\n]*?\.js\b"
    r"|\bcat\s+[^\n;|&>]*?\.js\b"
    r"|\bread_file\b[^\n]*?\.js\b"
    r"|\bhead\s[^\n;|&>]*?\.js\b"
)

#: ``cat >/tmp/x.py``、``cat <<'EOF'`` 这类是**写**文件，不是读 bundle。
#: 实测（traces/094 第 16 步、traces/096 第 15 步）：脚本正文里出现 ``.js`` 字样
#: 就会命中 _BUNDLE_RE，BUNDLE GUARD 把"写脚本"误判成"又在读前端产物"。
_WRITE_REDIRECT_RE = re.compile(r"\b(?:cat|tee)\b[^\n]*?(?:>>?|<<)")

#: head 里逐次变化的只有"耗时"和"字节数"。**不能**把 head 里的所有数字都归一化：
#: 状态码就在 head 里（``[HTTP 403]`` / ``Process exited with code 1``），
#: 一起洗掉的话 403 和 500 会变成同一个指纹 —— 那是把真实的状态变化当成重复，
#: 比原来的漏报更危险（测试 test_different_status_codes_* 锁住这一点）。
_HEAD_DURATION_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:ms|s|seconds?|sec)\b", re.I)
_HEAD_SIZE_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:B|KB|MB|bytes?)\b", re.I)


def _norm_head(head: str) -> str:
    """归一化状态行里逐次变化的部分，保留状态码等语义数字。

    Args:
        head: 结果的第一行。

    Returns:
        归一化后的状态行。
    """
    out = _HEAD_DURATION_RE.sub("<t>", head)
    out = _HEAD_SIZE_RE.sub("<n>", out)
    return re.sub(r"\s+", " ", out).strip()


def _is_bundle_read(args: str) -> bool:
    """判断这次调用是不是在**读**前端 bundle，而不是在写脚本。

    ``cat > /tmp/x.py <<'EOF'`` 和 ``cat <<'EOF'`` 都是写文件；脚本正文里随手
    出现一个 ``.js`` 就让旧的 _BUNDLE_RE 命中，BUNDLE GUARD 于是对着"写脚本"
    喊"别再看前端产物了"。两条真实轨迹（094 第 16 步、096 第 15 步）都是这样
    假阳性的。先剥掉写重定向，再匹配读的模式。

    Args:
        args: 工具调用的原始参数串。

    Returns:
        是否是一次 bundle 读取。
    """
    if not args:
        return False
    stripped = _WRITE_REDIRECT_RE.sub(" ", args)
    return bool(_BUNDLE_RE.search(stripped))


_URL_RE = re.compile(r"https?://[^\s\"'<>|)}\]]+")


def _obs_signature(result: Any, args: str) -> str:
    """把一次工具结果压成"观测指纹"，用来判断这次调用有没有带来新信息。

    归一化三件事，都是实测里会把同一个页面变成不同指纹的噪声：

    1. 参数里出现过的 URL 及其路径——404 页常把请求路径原样回显；
    2. 所有数字——时间戳、长度、端口、耗时每次都不同；
    3. 空白——换行与缩进不稳定。

    只保留状态行（第一行，含 ``[HTTP 404]`` / ``phase=CONNECT`` 这类归因）
    加上归一化后的正文前 1500 字符。

    Args:
        result: 工具返回值（通常是 str，也可能是结构化对象）。
        args: 本次调用的原始参数串。

    Returns:
        12 位十六进制指纹。相同指纹 == 相同观测 == 零信息增益。
    """
    text = result if isinstance(result, str) else str(result)
    for url in set(_URL_RE.findall(args or "")):
        text = text.replace(url, "<url>")
        parts = url.split("://", 1)[-1].split("/", 1)
        if len(parts) == 2 and len(parts[1]) > 2:
            text = text.replace("/" + parts[1], "<path>")
    head, _, body = text.partition("\n")
    # ⚠️ 必须先洗掉逐次随机的"传输层噪声"，否则同一个响应永远算新信息。
    # 实测（traces/094.json）：16 次 exec_command 的响应指纹 16 个全不同，
    # 逐个查下去发现差别只有 ``Chunk ID: 6b2fbc`` 和 ``Wall time: 2.5237``
    # ——hash 就建在这两个随机串上。后果是 ENUMERATION GUARD 与 stall 判据
    # 在这批题上一次都没触发（只有 BUNDLE GUARD 响了两声），7 道失败题全部
    # 无干预地烧完预算。洗掉之后同一条轨迹的 16 个指纹收敛成 15 个，
    # 真正重复的两步（22、23）才显形。
    noise = (
        (r"Chunk ID: \S+", "Chunk ID: <id>"),
        (r"Wall time: [0-9.]+ ?(?:seconds|s)\b", "Wall time: <t>"),
        (r"/tmp/sandbox-\d+-\d+", "/tmp/sandbox"),
    )
    for pattern, repl in noise:
        text = re.sub(pattern, repl, text)
    head, _, body = text.partition("\n")
    # ⚠️ head 也必须归一化。���验（traces/094.json 第 5/6 步）：两次探测的响应体逐字相同，
    # 只有状态行里的 ``0.11s`` vs ``0.10s`` 不同 —— 守卫因此判成"两个新观测"，
    # 同一族永远凑不满 3 次，ENUMERATION GUARD 一次都没响。
    head = _norm_head(head)
    body = re.sub(r"\d+", "#", body.lower())
    body = re.sub(r"\s+", " ", body).strip()
    payload = head + "|" + body[:1500]
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:12]


class EnumerationGuard:
    """统计"信息增益为零"的重复探测，并在工具结果里注入纠正提示。

    ## 为什么 v1 的计数没生效

    v1 按"同 host + 同路径族"计数，完全不看响应。2026-10-30 009 复跑里 agent
    对同一个 ``/api/plugins/preview`` 连打 4 次，每次换一个 body 字段名——
    族名一样，但那是**有**信息增益的探测；反过来 018 那种
    ``robots/sitemap/favicon/api`` 每换一个词就换一个族，一次都没触发。
    只数动作，数不出"有没有学到东西"。

    ## 现在的判据（AFL 式覆盖率思维）

    一次探测只有在**观测指纹与之前完全相同**时才算重复。新指纹 = 新信息 =
    这次调用有进展，计数清零。这就是模糊测试的语料库规则：只有产生新覆盖率的
    输入才值得留下（AFL），也是 novelty search 的核心——奖励行为上的新奇，
    而不是奖励动作次数。

    另外维护**全局停滞**计数：连续 N 次调用（跨所有族）都没产生新指纹，
    说明模型在原地打转，不管它换没换路径。

    Attributes:
        counts: 族 → 连续同响应次数。
        stall: 连续零新信息的调用数（跨族）。
    """

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.warned: set[str] = set()
        #: `begin` 被调用过多少次（含没有路径指纹、不计数的调用）。
        self.observe_calls: int = 0
        self._seen: dict[str, set[str]] = {}
        self._global: set[tuple[str | None, str]] = set()
        self.stall: int = 0
        self.stall_hits: int = 0
        #: Probes per CAPEC mechanism class, for the "same hypothesis" hint.
        self.mechanisms: Counter[str] = Counter()
        #: Probes sent since the last *new* class was discovered.
        self.class_streak: int = 0
        self.class_hits: int = 0
        #: How many distinct leaves each path family has been asked for.
        self.leaves: dict[str, set[str]] = {}
        #: 读 bundle 原文的次数（含 curl/wget/cat .js）。
        self.bundle_hits: int = 0

    def mechanism_counts(self) -> dict[str, int]:
        """Return a read-only snapshot of the per-CAPEC-class probe counts.

        The live ``Counter`` is mutated by :meth:`finish`; handing it out would
        let logging code (or a test) alter the guard's state while measuring it.

        Returns:
            Class name → number of classified probes so far.
        """
        return dict(self.mechanisms)

    def begin(self, tool_name: str, args: str) -> tuple[str | None, str]:
        """调用前登记。

        Args:
            tool_name: 工具名。
            args: 原始参数串。

        Returns:
            ``(族指纹, 参数串)``，交给 :meth:`finish` 结算。
        """
        self.observe_calls += 1
        return _fingerprint(tool_name, args), args

    def finish(self, token: tuple[str | None, str], result: Any) -> str | None:
        """调用后结算，返回要追加到结果末尾的提示（或 None）。

        Args:
            token: :meth:`begin` 的返回值。
            result: 工具返回值。

        Returns:
            提示文本；无需提示时返回 None。
        """
        key, args = token
        if _is_bundle_read(args):
            self.bundle_hits += 1
            if self.bundle_hits in (2, 4):
                return (
                    "\n\n[BUNDLE GUARD] You are reading front-end bundle source again. "
                    "route_map already listed the API paths (and its '?' candidates). "
                    "Stop downloading/cat-ing .js: feed those paths to method_sweep, "
                    "then POST to the most plausible one."
                )
        sig = _obs_signature(result, args)
        fresh = (key, sig) not in self._global
        self._global.add((key, sig))
        self.stall = 0 if fresh else self.stall + 1

        if key is None:
            return self._stall_hint()

        seen = self._seen.setdefault(key, set())
        if sig in seen:
            self.counts[key] += 1
        else:
            seen.add(sig)
            self.counts[key] = 0

        # ---- mechanism-class coverage -------------------------------------
        # ``key`` exists only for a call that reached the target, so this never
        # counts a local ``ls`` or a file read.  A request with no mechanism
        # marker is skipped rather than assigned a class: an invented class is
        # worse than a missing one.
        mechanism = _mechanism_of(args)
        if mechanism is None:
            # No syntax marker: enumeration is a *shape*, not a payload.  The
            # same path family asked for a second distinct leaf is the 043
            # behaviour -- many new names, one hypothesis.  One leaf alone is
            # ordinary navigation and is left unclassified.
            family = _path_family(args)
            if family is not None:
                leaf = args.rsplit("/", 1)[-1]
                leaves = self.leaves.setdefault(family, set())
                leaves.add(leaf)
                if len(leaves) >= 2:
                    mechanism = "information-collection"
        class_hint = None
        if mechanism is not None:
            if mechanism not in self.mechanisms:
                self.class_streak = 0
            else:
                self.class_streak += 1
            self.mechanisms[mechanism] += 1
            class_hint = self._class_hint(mechanism)

        n = self.counts[key]
        family = key.split("|")[-1]
        if n >= _HARD_REPEATS and (n - _HARD_REPEATS) % 3 == 0:
            return (
                f"\n\n[ENUMERATION GUARD] {n + 1} probes of '{family}' returned the "
                "IDENTICAL response. Re-sending cannot produce new information. Stop now.\n"
                "Switch mechanism: parameter injection, auth bypass, file read, SSTI, "
                "SSRF pivot, or use the access you already have (code execution / DB "
                "read) to locate the flag file."
            )
        if n >= _WARN_REPEATS and f"{key}|{sig}" not in self.warned:
            self.warned.add(f"{key}|{sig}")
            return (
                f"\n\n[ENUMERATION GUARD] The last {n + 1} probes of '{family}' returned "
                "the SAME response — zero new information. Name one concrete hypothesis "
                "(mechanism + exact request + expected response) that differs in "
                "structure from everything you already sent, then send that."
            )
        # The class hint is *less* urgent than "identical response, stop": a
        # blind extraction can legitimately repeat one mechanism, but it cannot
        # legitimately repeat one identical response.  So the hard signals go
        # first and this one only fills the gap they leave.
        if class_hint:
            return class_hint
        return self._stall_hint()

    def _class_hint(self, mechanism: str) -> str | None:
        """Name the untried mechanism classes once a class run gets long.

        This is the anti-"direction lock" hint.  It is deliberately about
        *mechanism*, not about payload: every probe inside one CAPEC class can
        look new (a different name, a different parameter) while the hypothesis
        never changes, so the fingerprint counters above stay quiet.  It does
        not block -- a blind extraction legitimately sends many probes of one
        kind -- it asks the model to say what it is extracting and, if it cannot
        name one, lists the classes it has not touched.

        Args:
            mechanism: the class of the probe that just returned.

        Returns:
            The hint text, or ``None`` while the class run is still short or on
            a non-repeat cadence.
        """
        streak = self.class_streak
        if streak < _CLASS_STREAK_AFTER:
            return None
        if (streak - _CLASS_STREAK_AFTER) % _CLASS_STREAK_REPEAT:
            return None
        self.class_hits += 1
        untried = [name for name in MECHANISM_NAMES if name not in self.mechanisms]
        untried_text = ", ".join(untried) if untried else "(none left)"
        return (
            f"\n\n[MECHANISM GUARD] {streak} probes in a row stayed inside "
            f"'{mechanism}' and no new attack class was found. "
            "If you cannot name the exact value this run is extracting, the "
            "mechanism is wrong: parameter count is not a hypothesis. "
            f"Untried classes: {untried_text}. "
            "Pick the one the evidence you already have points at."
        )

    def _stall_hint(self) -> str | None:
        if self.stall < _STALL_AFTER:
            return None
        if (self.stall - _STALL_AFTER) % _STALL_REPEAT:
            return None
        self.stall_hits += 1
        return (
            f"\n\n[ENUMERATION GUARD] {self.stall} consecutive calls produced no new "
            "observation (same bodies, same errors). Budget is burning without learning.\n"
            "Before the next request: (1) write down the single most promising fact you "
            "already have; (2) pick the mechanism that fact points at instead of probing "
            "more names."
        )

    def observe(self, tool_name: str, args: str, result: Any = None) -> str | None:
        """兼容旧接口：无 ``result`` 时只登记，有 ``result`` 时等价 begin+finish。

        Args:
            tool_name: 工具名。
            args: 原始参数串。
            result: 工具返回值；为 None 时不做信息增益判断。

        Returns:
            提示文本或 None。
        """
        token = self.begin(tool_name, args)
        if result is None:
            return None
        return self.finish(token, result)


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
            # 工具名从 tool 闭包取；大 agent 共用同一个守卫，计数是全局的
            token = guard.begin(tool.name, raw_input)
            result = await inner(ctx, raw_input)
            hint = guard.finish(token, result)
            if hint:
                # 结果体量不确定（可能不是 str），统一转成字符串追加。
                return f"{result}{hint}"
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_guarded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return guard
