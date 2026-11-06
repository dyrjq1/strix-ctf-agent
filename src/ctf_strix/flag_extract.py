"""从一次运行的日志里抽取可信的 flag。

为什么不能简单 ``grep -oE 'FLAG\\{...\\}'``：

实测踩过三次，每一次都会让结果失真：

1. **跨题污染**——strix 的工作目录 ``/tmp/sandbox-local-*`` 跨 run 复用，
   上一题留下的 ``ctf_recon.md`` 会被这一题的 agent 读进上下文。日志里于是
   出现**别的题**的 flag，提交上去顶多是 ``correct: false``，更糟的是被记成
   "解出"而实际没解。
2. **诱饵**——agent 自己会往日志里写 ``FLAG{...}`` 模板或占位符。
3. **截断**——``event_sink`` 只保留前 N 个字符，flag 可能正好跨在边界上
   被劈成两半，抽出 ``FLAG{b9`` 这种残片。

所以抽取必须带证据：flag 的来源上下文要指向**本题靶机**，且形态完整。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: flag 形态。不设长度下限——CTFY 的 flag 是 32 位 hex，但别的平台可能更短，
#: 卡长度会漏掉合法 flag。改用"排除模板"来挡 ``FLAG{...}`` 这类占位符。
#:
#: ⚠️ 前缀必须覆盖平台真实出现的形态。HANDOFF 的交付示例写的是 ``ctfy{…}``，
#: 而这里原来只认大写 ``FLAG``——同一个包里三个模块（本模块、``deadline_guard``、
#: ``autosubmit``）对"什么算答案"各有一套正则，收工守卫认不出的答案会被判成
#: "没拿到 flag"。现在统一成同一组前缀。
FLAG_RE = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[0-9a-zA-Z_\-]{2,}\}")

#: 「提交层认的答案形态」——**唯一真相**。``autosubmit`` 的候选抽取、
#: ``skillpack.mask_flags`` 的装载遮蔽、``scripts/scrub_flags.py`` 的磁盘清理
#: 都从这里取，不要再各写一份。
#:
#: 与 :data:`FLAG_RE` 只差花括号体内：``FLAG_RE`` 限制为
#: ``[0-9a-zA-Z_-]``（防止把自由文本里的乱码当答案），这里放宽到
#: ``[^}\s]{2,}``——writeup 里的历史 flag 常带 ``!``、``'``、``#``、``\``，
#: 窄集抽不到，但 ``read_file`` 会原样喂给模型，被当成"检索到的证据"。
CANDIDATE_RE = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[^}\s]{2,}\}")

#: 判为"模板/占位符"的形态（大小写不敏感）：
#:
#: - 内容是纯点，或纯 x/X；
#: - 内容被尖括号包住（形如 ``<value>``，``<abc>`` 这种也算）；
#: - 内容被双花括号包住（形如 ``{{flag}}``，未渲染的模板）；
#: - 内容是三个以上星号。
#:
#: ⚠️ 2026-11-06 v6 冒烟：镜像自带源码的注释里就留着一个「全 x 的示例 flag」，
#: agent 读自己的源码时把「示例」当成「检索到的证据」交了上去，一道不可能
#: 解出的题被判 ``solved``。镜像源码里现在一律不写完整的模板字面量：
#: 要么用 ``FLAG{…}``（Unicode 省略号），要么只描述花括号里面的形状。
#:
#: ⚠️ 只此一处定义，服务两个调用方，两边的字符集不同：
#:   1. ``extract_flags`` / ``fallback_flag`` / ``finish_guard`` /
#:      ``parallel`` / ``evidence``——输入来自 ``FLAG_RE``，字符集是
#:      ``[0-9a-zA-Z_-]``，只可能出现纯点、纯 x 两种形态；
#:   2. ``autosubmit.AutoSubmitter.candidates``——输入来自
#:      :data:`CANDIDATE_RE`，比 ``FLAG_RE`` 宽，还会产出尖括号、纯星号、
#:      纯点这类 ``FLAG_RE`` 抽不出的形态，所以下面这组形态必须按宽集写。
#:      不要再为宽集另起一份正则。
_PLACEHOLDER_BODY = re.compile(r"(?:\.{2,}|[xX]{2,}|<[^<>]*>|\*{3,})")

#: 前缀单独拿出来：双花括号要按"整个花括号部分"判断，先切前缀更好写。
#: 长前缀必须排在前面：``re`` 的交替是最左优先，``CTF`` 会先吃掉 ``CTFY``
#: 的三个字符，``rest`` 变成 ``Y{...}``，占位符判定直接失效（CodeBuddy P0）。
_PREFIX_RE = re.compile(r"^(?:CTFY|FLAG|CTF)(?=\{)", re.IGNORECASE)

def is_placeholder(flag: str) -> bool:
    """这个字符串是不是模板占位符（纯点 / 纯 x / 尖括号 / 双花括号 / 纯星号）。

    Args:
        flag: 一个候选答案。不要求它匹配 ``FLAG_RE``——``autosubmit`` 的宽集
            会传进尖括号包裹这类 ``FLAG_RE`` 认不出的形态。

    Returns:
        是占位符返回 True。真实 flag 一律 False；已知误杀风险只有两处：
        「内容全是 x/X 的真 flag」和「只有两个字符的体」（例如 FLAG 后接
        两个 x）。CTFY 的 32 位 hex 不可能长这样。
    """
    text = (flag or "").strip()
    match = _PREFIX_RE.match(text)
    if not match:
        return False
    rest = text[match.end():].strip()
    if not rest.startswith("{"):
        return False
    # 双花括号包住的整体，以及宽正则截出的半截（少一个右花括号）：都是未渲染模板。
    if rest.startswith("{{") and rest.endswith("}"):
        return True
    inner = rest[1:].strip()
    # 宽正则可能少截一个右花括号，补两个规范化变体再判。
    for variant in (inner, inner.rstrip("}").strip(), inner.strip("{}").strip()):
        if not variant:
            continue
        if _PLACEHOLDER_BODY.fullmatch(variant):
            return True
        # 体内的字符全是符号（``…`` / ``???`` / ``***`` / ``...``）：
        # 真实 flag 至少有一个字母数字，这类只能当占位符。
        # 用 ``str.isalnum()`` 而不是 ASCII 正则：中文等非 ASCII 字母数字
        # 也算"有内容"，不能把「前缀 + 中文」这种真实答案误杀。
        if not any(ch.isalnum() for ch in variant):
            return True
    return False


#: 花括号体以这些字符开头 = 代码里的模板或格式串：f-string 的双花括号、
#: shell 的 ``${x}``、printf 的 ``%s``、正则的 ``[a-z]+``。它们本来就不是
#: 答案；抹掉反而会把技能包里的示例代码改坏（少一个花括号就不再是能跑的代码）。
#:
#: ⚠️ 判据必须收窄到「一眼能看出是代码」：裸 ``$`` 不算——花括号体以 ``$``
#: 开头的（例如 ``$`` 加 ``3cr3t``）是真实 flag 的常见写法，放进来等于给
#: 假阳性开后门（2026-11-06 CodeBuddy P1）。
_CODE_BODY_PATTERNS = (
    re.compile(r"^\{"),                       # f-string 转义 FLAG{{{x}}}
    re.compile(r"^\$\{"),                     # shell ${x}
    re.compile(r"^%[-0-9.]*[sdrxufeEgG]"),    # printf %s / %08x
    re.compile(r"^\[[^\]]*\]"),               # 正则字符类 [a-z]+
)


def is_code_template(flag: str) -> bool:
    """花括号体是不是代码里的模板/格式串。

    与 :func:`is_placeholder` 分开放：那个判的是"读到的答案算不算占位符"，
    这个判的是"这段文本本来就不是答案"。技能包里有大量可执行示例，
    ``CANDIDATE_RE`` 会在 f-string 的 ``flag{`` 之后截出一段不完整的花括号体，
    按占位符抹掉就会少一个花括号、把示例改坏。

    Args:
        flag: 一个候选答案。

    Returns:
        花括号体以 ``{`` / ``$`` / ``%`` / ``[`` 开头时返回 True。
    """
    text = (flag or "").strip()
    brace = text.find("{")
    if brace < 0:
        return False
    body = text[brace + 1 :]
    return any(pat.match(body) for pat in _CODE_BODY_PATTERNS)


#: ``ctf_recon.md`` 头里的靶机 URL，形如 ``# CTF Recon — https://host/``。
_RECON_HEADER_RE = re.compile(r"CTF Recon\s*[—-]+\s*https?://([^/\s]+)")


@dataclass(frozen=True)
class FlagEvidence:
    """一个候选 flag 及它为什么可信。"""

    flag: str
    score: int
    reason: str


def extract_flags(log_text: str, own_host: str) -> list[str]:
    """抽出可信 flag，按可信度降序。

    Args:
        log_text: 本次运行的完整日志。
        own_host: 本题靶机 host（不含 scheme 和端口），例如
            ``abc123.node1.ctfy.run``。用来区分"本题证据"与"别题残留"。
            **为空时**（附件题、纯 TCP 题没有 web host）不做距离判定，
            退化为"排除残留后按出现次数取最可信的一个"——比直接返回空好，
            否则这两类题的 flag 永远抽不出来。

    Returns:
        可信 flag 列表，按分数降序、已去重。空列表表示没找到可信 flag。

    评分规则（每条都对应一次实测的误判）：

    - flag 出现在**本题 host 附近**（前后 800 字符内）→ +10
    - flag 出现在 ``ctf_recon.md`` 这类跨 run 残留文件里 → **直接排除**
    - flag 出现在本题 host **不在场**的一大段输出里 → -5（疑似别题残留）
    - 同一次运行重复出现 → +1/次（上限 +3）
    """
    if not log_text:
        return []

    # 先归并同一 flag 的所有出现位置。只用首次位置会系统性低估"多次出现"
    # 的 flag：首次可能离靶机远，后面某次可能紧邻。
    positions: dict[str, list[int]] = {}
    for m in FLAG_RE.finditer(log_text):
        flag = m.group(0)
        if is_placeholder(flag):
            continue
        positions.setdefault(flag, []).append(m.start())

    candidates: list[tuple[int, int, str]] = []
    for flag, hits in positions.items():
        # ⚠️ 判据不能用固定距离阈值。200 字符这个阈值在实测里失效过：
        # 别题 flag 距本题 host 50 字符、本题 flag 距 23 字符，两个都被判成
        # "紧邻"，于是出现次数多的别题 flag 反而胜出。
        # 改成**相对名次**：谁离本题靶机最近，谁就是第一。名次不受文本长度、
        # 日志排版影响，比任何绝对阈值都稳。
        dists = [
            d for d in (_nearest_host_distance(log_text, own_host, p) for p in hits) if d is not None
        ]
        near_host = min(dists) if dists else None

        # 跨 run 残留：strix 在本机留的 ctf_recon.md，内容是**上一题靶机**的
        # 侦察记录。判据不是"靠近 ctf_recon.md"——实测那条失效过：本题 host
        # 在日志里出现 43 次，残留位置附近也有，距离 525 落在阈值内。
        # 可靠的做法是读 recon 文件自称的 target，与本题不符就直接排除。
        stale_target = _recon_target_before(log_text, hits)
        if stale_target and own_host and stale_target != own_host:
            continue

        if not own_host:
            # 没有可对照的 host：保留候选，但分数只看重复次数（越负越靠前，
            # 与下面的距离升序保持同一方向）。单次出现的诱饵仍然可能中招，
            # 但这是"没有证据可依"时唯一可用的排序，比返回空更能交付。
            candidates.append((0, len(hits), flag))
            continue

        # 靶机从没在附近出现过 → 这条没有本题证据，直接淘汰（不参与排序）
        if near_host is None:
            continue
        candidates.append((near_host, len(hits), flag))

    if not candidates:
        return []

    # 排序键：距离升序 → 出现次数降序。
    # ⚠️ 但相对名次必须配一个**绝对上限**兜底：只剩一个候选时它必然"最近"，
    # 哪怕它其实来自别的题。实测 CTFARENA-010 就是这样——日志里唯一一个
    # flag 是残留，距离本题 host 1088 字符，仍会被判成答案。
    # 上限取 800：真实证据（URL 回显、flag 文件内容）都在几百字符内，
    # 而跨 run 残留通常隔着整段别的题的侦察记录。
    _MAX_EVIDENCE_DISTANCE = 800
    if own_host:
        candidates = [c for c in candidates if c[0] <= _MAX_EVIDENCE_DISTANCE]
    if not candidates:
        return []

    candidates.sort(key=lambda c: (c[0], -c[1]))
    return [c[2] for c in candidates]


def fallback_flag(log_text: str, own_host: str) -> str | None:
    """主判据一个都挑不出来时的兜底：日志里**恰好只有一个** flag 就交它。

    为什么需要这条：``extract_flags`` 要求 flag 距本题 host ≤800 字符，这在
    "把请求脚本写进文件、下一轮再执行"的流程里会失效。2026-10-30 009 复跑
    实测：agent 先用 heredoc 写了 ``/tmp/ev.py``（host 在里面），后面几轮
    ``python3 /tmp/ev.py`` 才拿到 flag——host 与 flag 隔着上千字符，于是
    主判据判"无证据"，**解出来的题被记成 FAIL**。

    为什么这样兜底是安全的：
    - 只有在"本该提交 0 个"的时候才走这条路，不会覆盖主判据的任何判断；
    - 只在**唯一**一个 flag 时生效，多 flag 场景（诱饵/残留并存）仍然交给
      主判据，不会把别题的 flag 顶上来；
    - 仍然排除 ``ctf_recon.md`` 里自称是**别的**靶机的那一段。
    最坏情况是把诱饵交上去——那与今天"什么都不交"得分相同，但能救回真实解。

    Args:
        log_text: 本次运行日志。
        own_host: 本题靶机 host。

    Returns:
        唯一候选 flag；不唯一或明确是残留时返回 None。
    """
    if not log_text:
        return None
    seen: dict[str, list[int]] = {}
    for m in FLAG_RE.finditer(log_text):
        flag = m.group(0)
        if is_placeholder(flag):
            continue
        seen.setdefault(flag, []).append(m.start())
    if len(seen) != 1:
        return None
    flag, hits = next(iter(seen.items()))
    stale = _recon_target_before(log_text, hits)
    if stale and own_host and stale != own_host:
        return None
    return flag


#: 日志里每次工具调用的行头：``  [194ca1f8] TOOL http_probe {...}``。
_TOOL_LINE = re.compile(r"\[[0-9a-f]{8}\] TOOL (\S+)(.*)")


def _tool_before(text: str, pos: int, window: int = 6000) -> tuple[str | None, str]:
    """找出 ``pos`` 之前最近一次工具调用。

    Args:
        text: 全文。
        pos: flag 出现位置。
        window: 往前找的最大跨度。

    Returns:
        ``(工具名, 参数串前 200 字符)``；窗口内没有调用时返回 ``(None, "")``。
    """
    lo = max(0, pos - window)
    head = text[lo:pos]
    picked = (None, "")
    for m in _TOOL_LINE.finditer(head):
        picked = (m.group(1), m.group(2).strip()[:200])
    return picked


def provenance(log_text: str, flag: str, own_host: str = "") -> dict:
    """记录 flag **第一次**出现时的证据来源，供台账与污染判定使用。

    为什么必须记：CTF-ABACUS 对 1435 次尝试的审计里，只有 62–87% 的 flag
    能被轨迹证明是"真的打出来的"。剩下的从哪来？上一题的残留、writeup 里的
    示例、别人的战绩。只看"日志里有 flag"分不清这些，必须记下它是**哪次调用**
    吐出来的、离本题靶机多远。

    Args:
        log_text: 本次运行日志。
        flag: 已选定的 flag。
        own_host: 本题靶机 host。

    Returns:
        含 ``offset`` / ``tool`` / ``args`` / ``distance`` / ``repeats`` /
        ``doc_source`` 的字典。``doc_source`` 为真表示 flag 出自本地文档
        （技能包、docs、reports），基本可以断定是污染而不是解出。
    """
    pos = log_text.find(flag)
    if pos < 0:
        return {}
    tool, args = _tool_before(log_text, pos)
    dist = _nearest_host_distance(log_text, own_host, pos) if own_host else None
    doc_hint = bool(re.search(r"skills_strix|/docs/|/reports/|ctf_recon\.md|writeup", args or "", re.I))
    return {
        "offset": pos,
        "tool": tool,
        "args": args,
        "distance": dist,
        "repeats": log_text.count(flag),
        "doc_source": doc_hint,
    }


def best_flag(log_text: str, own_host: str) -> str | None:
    """取最可信的一个 flag；没有则 None。"""
    flags = extract_flags(log_text, own_host)
    return flags[0] if flags else None


def host_of(url: str) -> str:
    """从 URL 里剥出 host（去掉 scheme、端口、路径）。"""
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0].split(":", 1)[0]


def _recon_target_before(text: str, hits: list[int], window: int = 4000) -> str | None:
    """找到 flag 之前最近的 ``ctf_recon.md`` 段，读它自称的靶机 host。

    strix 在工作目录留的 ``ctf_recon.md`` 第一行形如
    ``# CTF Recon — https://<host>/``。这个 host 是**写这份文件时**的靶机，
    也就是上一题。用它做黑名单比任何距离阈值都准。

    Args:
        text: 全文。
        hits: 某个 flag 的全部出现位置。
        window: 往前找 recon 头的最大跨度。

    Returns:
        该 recon 段自称的 host；找不到返回 None。
    """
    for pos in hits:
        # ⚠️ 取窗口内**最靠前**的 ctf_recon.md，不是最近的。实测踩过：
        # flag 前面有 3 处 "ctf_recon.md"——前两处是 `cat ctf_recon.md` 这种
        # 命令串，最近的那处（距 flag 仅 82 字符）只是命令回显，真正的文件头
        # 在更早的位置。用 rfind 拿最近一处就读不到 `# CTF Recon — <host>`。
        seg_start = text.find("ctf_recon.md", max(0, pos - window), pos)
        if seg_start == -1:
            continue
        # 从该处往后找第一个 URL 型 recon 头，跨过命令回显里的文件名。
        chunk = text[seg_start : pos]
        m = _RECON_HEADER_RE.search(chunk)
        if m:
            return m.group(1)
    return None


def _nearest_host_distance(text: str, host: str, pos: int, span: int = 2000) -> int | None:
    """``pos`` 处到最近一次 ``host`` 出现的字符距离；span 内没有则 None。

    Args:
        text: 全文。
        host: 本题靶机 host。
        pos: flag 的位置。
        span: 搜索半径。超出这个距离的 host 出现不能算"就在 flag 身边"。

    Returns:
        最小距离，或 None。
    """
    if not host:
        return None
    lo = max(0, pos - span)
    best: int | None = None
    idx = text.find(host, lo, pos + span)
    while idx != -1:
        dist = abs(idx - pos)
        if best is None or dist < best:
            best = dist
        idx = text.find(host, idx + 1, pos + span)
    return best
