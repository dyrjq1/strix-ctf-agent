"""发现层：把 009 里"靠运气撞到"的两个动作变成固定原语。

## 背景

一次第一跑的 12 次调用里，有 4 次花在**肉眼看压缩后的 JS**：

```
cat BbkGSyGJ.js        # 3.7KB
head -c 8000 NXz3x3fk.js
tail -c 7000 NXz3x3fk.js
```

196KB 的 bundle 逐段读，**从头到尾没有 grep 过一次 `"/api/"`**。而真正需要
的信息只有一行：客户端调用了哪些后端路径。

第二跑换了个走法就通了：先把所有 chunk 抓下来，正则提路径，然后**对每条
路径换方法发一遍**——`POST /api/plugins/preview` 就是这么浮出来的，服务端
还直接回了 `{"error":"code_b64 required"}`，等于把参数名告诉了 agent。

这两个动作都不需要判断力，只需要"记得做"。凡是"记得做"的事，都应该做成
一次调用，而不是写进 prompt（本仓库已两次验证 prompt 会衰减）。

## 两个原语的边界

- ``route_map``：从首页出发，抓 HTML 里引用的 chunk，提路径字面量，按出现
  次数排序。**只读 GET，不改目标状态。**
- ``method_sweep``：给一批路径，换方法打一遍，只回报"有信息量"的组合。
  默认跳过 404，405 只在带 ``Allow`` 时保留——否则一屏全是噪音。

两者都刻意**不做**全字典爆破：字典爆破的收益在 CTF 里很低（路径通常是业务
语义的，不是通用词），成本却很高（每多一条就多一次往返 + 一次上下文占用）。
"""

from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Final
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from ctf_strix import traffic
from ctf_strix.http_probe import session_cookies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: 一次最多抓多少个 chunk。超过这个数说明是巨型 SPA，收益递减。
_MAX_CHUNKS: Final = 12
#: route_map 最多回报多少条路径。
_MAX_ROUTES: Final = 30
#: method_sweep 最多回报多少行。
_MAX_ROWS: Final = 40
#: 单次请求超时。发现阶段要快，慢的端点留给 http_probe 单独打。
_TIMEOUT: Final = 8.0
#: route_map 往台账里存的前缀长度。默认 16 KB 只能存下 bundle 的头几十行，
#: 而"从 bundle 里读路由"这件事的全部价值在中后段——存半截等于没存。
#: 12 个 chunk × 64 KB ≈ 768 KB，是这个工具能接受的上限。
_BUNDLE_KEEP: Final = 64 * 1024

#: HTML 里三种引用脚本的写法。Nuxt 用 modulepreload，Vite 用 script type=module，
#: 老站点用 <script src>。三种都要吃。
_SCRIPT_RE: Final = re.compile(
    r"""(?:<script[^>]+src=["']([^"']+)["'])"""
    r"""|(?:<link[^>]+rel=["'](?:modulepreload|preload)["'][^>]+href=["']([^"']+)["'])"""
    r"""|(?:<link[^>]+href=["']([^"']+\.m?js)["'])""",
    re.IGNORECASE,
)

#: 代码里的路径字面量。只认以单个 / 开头、不跨引号的短串——
#: 太长的多半是内联数据，不是路由。
_ROUTE_RE: Final = re.compile(r"""["'`](/(?!/)[A-Za-z0-9_\-./{}:$]{1,80})["'`]""")

#: 明显不是路由的路径（静态资源、构建产物）。
_NOT_ROUTE: Final = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp|avif)$"
    r"|^/(?:_nuxt|_next|assets|static|build|@vite|node_modules)/",
    re.IGNORECASE,
)

#: 优先级权重。**不按"出现了几次"排**：前端页面路由（/admin/users 这类）
#: 在 bundle 里天然出现得多，但它们只是 Vue/React 的页面表，不是后端入口。
#: 实测在平台自己的 SPA 上，纯按词频排序时前 30 条全是 /admin/* 页面路由，
#: 真正的 /api/* 一条都进不来——排序错了等于没做。
_WEIGHT_RULES: Final = (
    (3, ("/api", "graphql", "internal", "preview", "webhook", "callback")),
    (2, ("auth", "login", "user", "upload", "plugin", "file", "download", "export")),
    (1, ("admin",)),
)


def _weight(path: str) -> int:
    """给一条候选路径打"值不值得先打"的分。"""
    low = path.lower()
    for weight, needles in _WEIGHT_RULES:
        if any(n in low for n in needles):
            return weight
    return 0


def _same_origin(base: str, url: str) -> bool:
    """只抓同源脚本。跨域脚本是 CDN，里面没有本题的路由。"""
    try:
        a, b = urlparse(base), urlparse(url)
    except ValueError:
        return False
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _get(url: str, timeout: float = _TIMEOUT):
    return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)


#: 常见 API 动词。用途不是"扫字典"，而是把**页面自己的词汇**拼到已发现的前缀上。
#: 009 两次运行的差异就在这里：13 次调用那次模型自己猜中了 ``/api/plugins/preview``，
#: 33 次调用那次 route_map 只给出 stats/featured/categories 三条，模型于是去读
#: bundle 原文。前端的按钮文案（"Submit for review"、"Preview"）本来就在首页上，
#: 把它和 ``/api/plugins`` 拼起来就是未文档化入口。
_VERB_HINTS: Final = (
    "preview", "submit", "upload", "review", "approve", "reject", "export", "import",
    "create", "update", "delete", "search", "list", "status", "stats", "config",
    "settings", "admin", "health", "metrics", "logs", "debug", "token", "verify",
    "reset", "refund", "redeem", "claim", "invite", "share", "download", "run",
    "exec", "ping", "proxy", "webhook", "me", "users", "orders", "report",
)

#: 页面文本里出现这些词时，说明它是这个应用的动作词，值得拼进候选。
_WORD_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,20}")


def _derived_candidates(counts: dict[str, int], blob: str, limit: int = 8) -> list[str]:
    """把"已知 API 前缀 × 页面词汇"拼成未验证候选路径。

    Args:
        counts: 已发现的路径 → 出现次数。
        blob: 首页与 chunk 的原文（用于判断某个词是不是这个应用的词汇）。
        limit: 最多给几条。

    Returns:
        候选路径列表（不含已发现的），前缀权重高的排在前面。
    """
    # 前缀要从**已发现的具体路径**里截，不是去匹配整条路径：
    # 计数表里只有 /api/plugins/stats 这种三段路径，直接 fullmatch 会一条都提不出来。
    prefix_set: set[str] = set()
    for path in counts:
        m = re.match(r"^(/api(?:/[a-z0-9_\-]{2,20})?)", path)
        if m:
            prefix_set.add(m.group(1))
    prefixes = sorted(prefix_set, key=lambda p: (-_weight(p), -counts.get(p, 0), p))
    if not prefixes:
        return []
    lowered = blob.lower()
    vocab = {w.lower() for w in _WORD_RE.findall(blob)}
    verbs = [v for v in _VERB_HINTS if v in vocab or v in lowered]
    # 页面词汇不足时退回静态动词表——宁可多给几条可验证的候选，也不要空手。
    if len(verbs) < 4:
        verbs = list(_VERB_HINTS)
    out: list[str] = []
    for prefix in prefixes:
        for verb in verbs:
            path = f"{prefix}/{verb}"
            if path in counts or path in out:
                continue
            out.append(path)
            if len(out) >= limit:
                return out
    return out


#: 结构派生候选的硬上限。三类加起来不超过这个数——20 条已经比一次
#: method_sweep 能舒服打完的量还多，再多只是把预算摊薄到更差的方向上。
_MAX_STRUCTURAL: Final = 20

#: "这一段是个具体 id"的三种形状，都在靶机上见过：纯数字（/api/notes/42）、
#: 带前缀的十六进制（note_d6e7380c）、长十六进制（16-40 位）。
_ID_SEG_RE: Final = re.compile(
    r"^(?:\d{1,12}|[0-9a-fA-F]{16,40}|[A-Za-z][A-Za-z0-9]{1,20}_[0-9a-fA-F]{6,40})$"
)

#: 只说明"这里是 id、但没有具体值"的占位段。它们证明端点属于实例族，
#: 本身却不是可请求的路径，所以只用来截前缀。
_ID_PLACEHOLDER_SEG: Final = frozenset(
    {"id", "{id}", ":id", "$id", "<id>", "${id}", "uid", "{uid}", "slug", ":slug", "{slug}"}
)

#: 页面/JS 里出现过的 id 值。纯数字只从 HTML 属性与 URL 形状取（正文里的
#: 数字全是噪声），带前缀/长十六进制才从全文取。
_ID_TOKEN_RE: Final = re.compile(
    r"\b([A-Za-z][A-Za-z0-9]{1,20}_[0-9a-fA-F]{6,40})\b|\b([0-9a-fA-F]{16,40})\b"
)
_ATTR_ID_RE: Final = re.compile(
    r"""\b(?:data-[\w-]*id|id|value)\s*=\s*["'](\d{1,9})["']""", re.IGNORECASE
)
#: 写在 HTML 链接或 JS 字符串里的实例路径，如 ``/api/notes/43``。
_URL_ID_RE: Final = re.compile(r"/[A-Za-z][A-Za-z0-9_\-]*/(\d{1,9})(?=[\"'/<>\s?#])")

#: HTML form 控件名——参数面最可靠的来源，因为它是应用自己声明的字段。
_FORM_NAME_RE: Final = re.compile(
    r"""<(?:input|select|textarea|button)\b[^>]*\bname\s*=\s*"""
    r"""["']([A-Za-z_][A-Za-z0-9_\-]{0,30})["']""",
    re.IGNORECASE,
)
#: 查询串里出现过的参数名：``fetch("/api/x?limit=10")``、``/search?q=``。
_QUERY_PARAM_RE: Final = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_\-]{0,30})=")
#: JS 对象字面量的键。``{limit: 10}`` 是参数，``{method: "POST"}`` 是 fetch 选项。
_OBJ_KEY_RE: Final = re.compile(r"""([{,]\s*)([A-Za-z_][A-Za-z0-9_]{1,30})\s*:""")
_QUOTED_KEY_RE: Final = re.compile(r"""["']([A-Za-z_][A-Za-z0-9_\-]{1,30})["']\s*:""")

#: fetch/请求选项的键，出现在每个 bundle 里，不是应用字段。
_JS_KEY_NOISE: Final = frozenset(
    {
        "method", "headers", "body", "mode", "credentials", "cache", "redirect",
        "referrer", "referrerpolicy", "signal", "keepalive", "integrity", "window",
        "document", "location", "function", "return", "const", "let", "var",
    }
)

#: 页面词汇里永远不是资源名的词：HTML 标签、框架关键字、HTTP 方法、虚词。
#: 这不是"路径字典"——它只做减法，从不产出候选。
_NOUN_STOPWORDS: Final = frozenset(
    """
    about above across after again against all also and any are because been before
    being below between both but can could did does doing done down during each
    few for from further had has have having here how into its itself just more
    most must not now off once only other our out over own same should some such
    than that the their them then there these they this those through too under
    until very was were what when where which while who will with would you your
    div span class style script src href html head body meta link rel http https
    json charset utf viewport initial scale noscript svg path xmlns aria title
    type name value placeholder button form input select option textarea
    table thead tbody footer header section main nav article strong code img
    true false null none undefined import export default async await fetch
    get post put patch delete options head
    """.split()
)

#: 页面"文字"的两处来源：HTML 文本节点、带空格的 JS 字符串（URL 不带空格）。
_HTML_TEXT_RE: Final = re.compile(r">([^<>]{2,400})<")
_JS_TEXT_RE: Final = re.compile(r"""["'`]([^"'`\n<>]*\s[^"'`\n<>]{2,300})["'`]""")
#: 标签外的成串英文（按钮文案常直接写在模板里）。
_PROSE_RUN_RE: Final = re.compile(
    r"[A-Za-z][A-Za-z0-9_\-]*(?:[ \t,.!?]+[A-Za-z][A-Za-z0-9_\-]*){2,}"
)
#: 出现这些字符的"文字"其实是代码/URL，不是文案。
_PROSE_BAD_CHARS: Final = frozenset("{}[]:=()/<>;@#*+|\\\"`")


def _norm_request(url: str) -> str:
    """URL 或路径 → ``path?query``，用于和流量台账比较"请求过没有"。

    和 ``traffic._normalise_path`` 的区别只有一个，但很关键：那边故意丢掉
    query（它只回答"这个资源问过没有"），这里必须保留——[参数] 候选的全部
    信息就在 query 里，丢掉就等于把它自己判成"已请求"。
    """
    text = (url or "").strip()
    if "://" in text:
        text = text.split("://", 1)[1]
        slash = text.find("/")
        text = text[slash:] if slash >= 0 else "/"
    text = text.split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    path, sep, query = text.partition("?")
    path = path.rstrip("/") or "/"
    return path + (("?" + query) if sep else "")


def _observed_ids(counts: dict[str, int], blob: str) -> list[str]:
    """已观测到的具体 id 值，确定性排序（数字在前、按值；其余按字典序）。"""
    found: list[str] = []

    def add(value: str) -> None:
        if value and value not in found:
            found.append(value)

    for path in sorted(counts):
        for seg in path.split("/"):
            if seg and _ID_SEG_RE.match(seg):
                add(seg)
    for match in _ID_TOKEN_RE.finditer(blob):
        add(match.group(1) or match.group(2))
    for match in _ATTR_ID_RE.finditer(blob):
        add(match.group(1))
    for match in _URL_ID_RE.finditer(blob):
        add(match.group(1))
    return sorted(found, key=lambda v: (0, int(v)) if v.isdigit() else (1, v))


def _instance_parents(counts: dict[str, int]) -> list[str]:
    """已发现路径里"实例族"的父路径，如 /api/notes/42 与 /api/notes/${id}。"""
    parents: list[str] = []
    for path in sorted(counts):
        segs = [seg for seg in path.split("/") if seg]
        if len(segs) < 2:
            continue
        last = segs[-1]
        if not (_ID_SEG_RE.match(last) or last.lower() in _ID_PLACEHOLDER_SEG):
            continue
        parent = "/" + "/".join(segs[:-1])
        if parent not in parents:
            parents.append(parent)
    return parents


def _page_nouns(blob: str, limit: int, exclude: frozenset[str] = frozenset()) -> list[str]:
    """页面/JS 文字里的名词候选，按出现次数降序、同频按字典序。

    只读"文字"（HTML 文本节点、带空格的 JS 字符串），不读 URL、属性名和
    对象键——那些地方的名词（limit、offset、method）是参数，不是子资源。
    ``exclude`` 用来把已识别的参数名再挡一遍。
    """
    freq: dict[str, int] = {}
    texts = [match.group(1) for match in _HTML_TEXT_RE.finditer(blob)]
    texts += [match.group(1) for match in _JS_TEXT_RE.finditer(blob)]
    texts += [match.group(0) for match in _PROSE_RUN_RE.finditer(blob)]
    for text in texts:
        if any(ch in _PROSE_BAD_CHARS for ch in text):
            continue
        for word in _WORD_RE.findall(text):
            low = word.lower()
            if (
                len(low) < 4 or low.isdigit() or _ID_SEG_RE.match(low)
                or low in _NOUN_STOPWORDS or low in exclude
            ):
                continue
            freq[low] = freq.get(low, 0) + 1
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))
    return [word for word, _ in ranked[:limit]]


def _page_params(blob: str) -> list[str]:
    """页面/JS/form 里出现过的参数名，按首次出现顺序（form 优先）。

    只认**原文里出现过**的名字；没有静态参数表，页面没写的名字不会冒出来。
    """
    names: list[str] = []

    def add(value: str) -> None:
        low = value.lower()
        if low in _JS_KEY_NOISE or low in _NOUN_STOPWORDS:
            return
        if value not in names:
            names.append(value)

    for match in _FORM_NAME_RE.finditer(blob):
        add(match.group(1))
    for match in _QUERY_PARAM_RE.finditer(blob):
        add(match.group(1))
    for match in _QUOTED_KEY_RE.finditer(blob):
        add(match.group(1))
    for match in _OBJ_KEY_RE.finditer(blob):
        add(match.group(2))
    return names


def _structural_candidates(
    counts: dict[str, int],
    blob: str,
    requested: set[str] | frozenset[str] = frozenset(),
    limit: int = _MAX_STRUCTURAL,
) -> list[tuple[str, str]]:
    """从已发现端点确定性地派生三类结构候选（不爆破、不随机）。

    阶梯思想取自 ipa-lab/hackingBuddyGPT 的 ``utils/web_api/exploration_steps.py``：
    先沿着已确认存在的资源往下走一步，再横向拼同族的子资源，最后才碰查询参数。
    但这里**不抄** ``random.choice``，也不查字典——每个候选的可变部分都必须
    能在页面原文或已发现路径里找到出处。

    Args:
        counts: 已发现的路径 → 出现次数。
        blob: 首页与 chunk 原文，既是 id 来源，也是词汇/参数名的唯一出处。
        requested: 台账里已经请求过的 URL（或路径）。命中的候选一律不输出。
        limit: 三类合计上限，默认 20。

    Returns:
        ``[(类别, 路径)]``，类别为 ``实例`` / ``子资源`` / ``参数``，
        顺序固定（实例 → 子资源 → 参数），同输入必得同输出。
    """
    seen = {_norm_request(path) for path in counts}
    seen |= {_norm_request(url) for url in requested}

    def fresh(path: str) -> bool:
        key = _norm_request(path)
        if key in seen:
            return False
        seen.add(key)
        return True

    params = _page_params(blob)

    # (a) 实例路径：父路径来自已发现路径里的 id 段/占位段，id 取观测到的具体值。
    instance: list[tuple[str, str]] = []
    ids = _observed_ids(counts, blob)
    if ids:
        parents = sorted(_instance_parents(counts), key=lambda p: (-_weight(p), p))
        for parent in parents:
            for ident in ids:
                path = f"{parent}/{ident}"
                if fresh(path):
                    instance.append(("实例", path))
                    if len(instance) >= 6:
                        break
            if len(instance) >= 6:
                break

    # (b) 子资源：已发现的 /api 前缀 × 页面文字里的名词。
    subresource: list[tuple[str, str]] = []
    prefix_set: set[str] = set()
    for path in counts:
        match = re.match(r"^(/api(?:/[a-z0-9_\-]{2,20})?)", path)
        if match:
            prefix_set.add(match.group(1))
    prefixes = sorted(prefix_set, key=lambda p: (-_weight(p), -counts.get(p, 0), p))
    nouns = _page_nouns(blob, 14, frozenset(p.lower() for p in params))
    # 名词在外、前缀在内轮转：否则排第一的前缀会独吞全部名额。
    for noun in nouns:
        for prefix in prefixes:
            if noun == prefix.rsplit("/", 1)[-1]:
                continue
            path = f"{prefix}/{noun}"
            if fresh(path):
                subresource.append(("子资源", path))
                if len(subresource) >= 7:
                    break
        if len(subresource) >= 7:
            break

    # (c) 查询参数面：已发现端点 × 页面/form/JS 里出现过的参数名。
    # 模板路径（/api/notes/${id}）不能直接请求，先排除。
    query: list[tuple[str, str]] = []
    endpoints = [
        path for path in sorted(counts, key=lambda p: (-_weight(p), -counts[p], p))
        if not any(ch in path for ch in "{}<>$:")
    ][:10]
    for param in params[:10]:
        for endpoint in endpoints:
            path = f"{endpoint}?{param}=1"
            if fresh(path):
                query.append(("参数", path))
                if len(query) >= 7:
                    break
        if len(query) >= 7:
            break

    return (instance[:6] + subresource[:7] + query[:7])[: max(0, limit)]

async def route_map(base_url: str, max_chunks: int = _MAX_CHUNKS) -> str:
    """从首页和它引用的 JS 里提取后端路径候选（只读 GET，一次调用完成）。

    用途：替代"下载 bundle 然后肉眼读"。在 Nuxt/Next/Vite 应用上，前端
    bundle 里一定有它调用的 API 路径，这是**未文档化入口最主要的来源**。

    Args:
        base_url: 站点根地址，如 https://host/ 。
        max_chunks: 最多抓多少个脚本，默认 12。抓太多收益递减且拖慢。

    Returns:
        按出现次数排序的路径候选表（≤30 条），每条注明来源文件；
        末尾给出下一步建议。
    """
    base_url = (base_url or "").strip()
    if not base_url.startswith(("http://", "https://")):
        return "[route_map] base_url 必须带 scheme，如 https://host/"

    # 每一次出网都入台账，和 http_probe / method_sweep 同一口径：id 在发送**前**
    # 预留，失败也记一条（"这个 URL 连不上"本身就是证据）。报告 WEB-9 的直接
    # 要求——route_map 抓回来的 bundle 原文必须能被 traffic_list/traffic_view
    # 看见；否则下面那句"不要再读 bundle"就只是一句没有出路的话。
    home_id = traffic.ledger().next_id()
    started = time.time()
    try:
        home = _get(base_url)
    except Exception as exc:  # noqa: BLE001
        traffic.record(
            request_id=home_id, method="GET", url=base_url,
            phase=type(exc).__name__, elapsed=time.time() - started,
            note=f"{type(exc).__name__}: {exc}"[:300],
        )
        return (
            f"[route_map] 首页取不到：{type(exc).__name__}: {exc}。"
            f"先用 http_probe 确认可达（本条已记台账 {home_id}）。"
        )
    home_text = home.text or ""
    traffic.record(
        request_id=home_id, method="GET", url=base_url,
        status=home.status_code, resp_headers=dict(home.headers),
        resp_body=home_text, size=len(home.content or b""),
        elapsed=time.time() - started, body_keep=_BUNDLE_KEEP,
    )

    html = home_text
    refs: list[str] = []
    for m in _SCRIPT_RE.finditer(html):
        ref = next((g for g in m.groups() if g), "")
        if not ref:
            continue
        full = urljoin(base_url, ref)
        if _same_origin(base_url, full) and full not in refs:
            refs.append(full)
    refs = refs[: max(1, int(max_chunks))]

    counts: dict[str, int] = {}
    origin: dict[str, str] = {}
    blobs: list[str] = []
    #: chunk 名字 -> 台账 id。列表下面要按名字指路，否则模型知道"有这个文件"
    #: 却不知道该读哪一条，最后还是会去重下（WEB-9）。
    chunk_ids: dict[str, str] = {}
    fetched = 0
    for ref in refs:
        request_id = traffic.ledger().next_id()
        started = time.time()
        try:
            resp = _get(ref)
        except Exception as exc:  # noqa: BLE001 — 单个 chunk 失败不该毁掉整张图
            traffic.record(
                request_id=request_id, method="GET", url=ref,
                phase=type(exc).__name__, elapsed=time.time() - started,
                note=f"{type(exc).__name__}: {exc}"[:300],
            )
            continue
        fetched += 1
        name = ref.rsplit("/", 1)[-1]
        text = resp.text or ""
        blobs.append(text[:200_000])
        chunk_ids[name] = request_id
        traffic.record(
            request_id=request_id, method="GET", url=ref,
            status=resp.status_code, resp_headers=dict(resp.headers),
            resp_body=text, size=len(resp.content or b""),
            elapsed=time.time() - started, body_keep=_BUNDLE_KEEP,
        )
        for m in _ROUTE_RE.finditer(text):
            path = m.group(1).rstrip("/")
            if not path or _NOT_ROUTE.search(path):
                continue
            counts[path] = counts.get(path, 0) + 1
            origin.setdefault(path, name)

    # 顺带把 HTML 自身里的路径也算上（有些站把入口写在 window.__INITIAL_STATE__）
    for m in _ROUTE_RE.finditer(html):
        path = m.group(1).rstrip("/")
        if path and not _NOT_ROUTE.search(path):
            counts[path] = counts.get(path, 0) + 1
            origin.setdefault(path, "index.html")

    if not counts:
        return (
            f"[route_map] {base_url} 抓到 {fetched} 个脚本，但没提到路径字面量。\n"
            "next: 说明路由不在前端 bundle 里（服务端渲染或全是动态拼接）。"
            "改用 method_sweep 打已知路径，或直接读首页 HTML 里的表单 action"
            f"（原文在台账 {home_id}，traffic_view(\"{home_id}\") 可取回）。"
        )

    def score(item: tuple[str, int]) -> tuple[int, int, int]:
        path, n = item
        depth = path.count("/")
        # 权重优先，其次出现次数，最后偏好两段式路径（/api/plugins 优于 /api/a/b/c/d）
        return (_weight(path), n, -abs(depth - 2))

    ranked = sorted(counts.items(), key=score, reverse=True)[:_MAX_ROUTES]
    ids_hint = (
        "、".join(f"{name}={rid}" for name, rid in list(chunk_ids.items())[:4])
        or "本次没取到 chunk"
    )
    lines = [
        f"[route_map] {base_url} | html {len(html)}B | chunks {fetched}/{len(refs)} | "
        f"候选 {len(counts)} 条（列前 {len(ranked)} 条）",
        # 这句必须放在**最前面**。009 复跑实测：route_map 第 3 次调用就给出了
        # 含 /api/plugins/preview 的 4 条候选，agent 仍然去下载 5 个 chunk
        # 用 cat/head 逐段读（第 17-21 次调用）。工具给了答案但没拦住旧习惯，
        # 于是答案被自己的"再看看"覆盖掉了。提示语放末尾没有用——模型读完
        # 列表就动手了，不会回头读最后一行。
        #
        # 但"不要读"必须配一条"要读就读这里"：bundle 原文已经随本次调用进了
        # 台账（WEB-9），traffic_view 能按 id 分页读完，不需要再下一次。
        "⚠️ 上面就是全部路由，不要再下载或阅读 bundle 原文。下一步：method_sweep。",
        f"（首页={home_id}；bundle 原文已在台账：{ids_hint}；"
        "用 traffic_view(id, offset=N) 分页读，不要重下）",
        *[f"{i}. {p}  x{n}  ({origin.get(p, '?')})" for i, (p, n) in enumerate(ranked, 1)],
    ]
    if len(counts) > len(ranked):
        lines.append(f"…另有 {len(counts) - len(ranked)} 条低频路径未列")
    derived = _derived_candidates(counts, html + "\n" + "\n".join(blobs))
    if derived:
        lines.append("候选（页面词汇 × API 前缀，未验证，先 method_sweep）：")
        lines.extend(f"  ? {p}" for p in derived)
    lines.append(
        "next: 把这些路径（含上面的 ? 候选）喂给 method_sweep——同一个路径换 POST/PUT "
        "是最容易撞出未文档化入口的动作。不要再去读 bundle 原文："
        f"要看原文用 traffic_view(\"{home_id}\") 或 traffic_list(url_contains=…) 取台账。"
    )
    structural = (
        _structural_candidates(
            counts,
            html + "\n" + "\n".join(blobs),
            {item.url for item in traffic.ledger().items() if item.url},
        )
        if os.environ.get("CTF_STRUCTURAL", "").strip() in ("1", "true", "on")
        else []
    )
    if structural:
        # 新节放在末尾：上面那段路径表保持原样（<= 30 条），这里只追加
        # "从已发现结构确定派生、且台账里从未请求过"的候选。
        lines.append("")
        lines.append(
            f"── 结构派生候选（{len(structural)} 条，均从未请求；"
            "由已发现端点/页面词汇确定性派生，未验证）──"
        )
        lines.extend(f"  [{kind}] {path}" for kind, path in structural)
        lines.append(
            "next: 先挑一条 [实例] 用 http_probe 打——同族端点已存在时，"
            "实例路径通常直接返回那条数据；[参数] 则在同一路径上换方法/"
            "补字段名继续。这些都是台账里没发过的 URL，试完自然去重。"
        )
    return "\n".join(lines)


async def method_sweep(
    urls: str,
    base_url: str = "",
    methods: str = "OPTIONS,GET,POST,PUT,PATCH",
    concurrency: int = 6,
    headers_json: str = "",
    session: str = "auto",
) -> str:
    """对一批路径换方法各打一遍，只回报有信息量的组合。

    Args:
        urls: 待测路径，换行或逗号分隔。相对路径（/api/x）会拼到 base_url 上；
            也可以直接写完整 URL。
        base_url: 相对路径的前缀，如 https://host 。全部路径都是绝对 URL 时可留空。
        methods: 逗号分隔的方法列表，默认 OPTIONS,GET,POST,PUT,PATCH。
        concurrency: 并发数，默认 6。别开太大——目标是比赛靶机，不是压测对象。
        headers_json: 额外请求头，JSON 字符串，写法与 ``http_probe`` 的同名
            参数一致，如 ``{"Authorization": "Bearer x"}``。
        session: 会话选择，与 ``http_probe`` 同口径。默认 ``auto``：把
            ``http_probe`` 在同一靶机上登录得到的 cookie 附到本批每个请求
            （登录态对扫描生效）；``off`` 完全匿名。扫描期间的 Set-Cookie
            不回写会话。

    Returns:
        命中的组合（状态码 + 方法 + 路径 + 长度 + body 片段），按信息量排序；
        404 全部省略，405 只在带 Allow 头时保留。末尾给下一步建议。

    Note:
        默认方法里**不含 DELETE**：PortSwigger 的方法测试指引明确要求"打低价值
        对象，避免产生副作用"。本题靶机可能是共享资源，用 DELETE 扫一遍等于
        在别人的题上删数据。确需 DELETE 时手工单独发。
    """
    base_url = (base_url or "").strip()
    raw = [u.strip() for u in re.split(r"[\s,]+", urls or "") if u.strip()]
    if not raw:
        return "[method_sweep] urls 为空。传换行分隔的路径，如 /api/plugins/stats"

    try:
        extra_headers = json.loads(headers_json) if headers_json.strip() else {}
    except json.JSONDecodeError as exc:
        return f"[method_sweep] headers_json 不是合法 JSON：{exc}"
    if not isinstance(extra_headers, dict):
        return "[method_sweep] headers_json 必须是 JSON 对象（花括号），不能是数组或字符串。"

    targets: list[str] = []
    for u in raw:
        if u.startswith(("http://", "https://")):
            targets.append(u)
        elif u.startswith("/"):
            if not base_url:
                return f"[method_sweep] 相对路径 {u} 需要 base_url（如 https://host）。"
            targets.append(urljoin(base_url.rstrip("/") + "/", u.lstrip("/")))
        else:
            targets.append(urljoin(base_url.rstrip("/") + "/", u) if base_url else u)

    if len(targets) > 40:
        targets = targets[:40]

    mlist = [m.strip().upper() for m in re.split(r"[\s,]+", methods or "") if m.strip()]
    mlist = [m for m in mlist if m in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}][:6]
    if not mlist:
        return "[method_sweep] 没有合法方法。可用：GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD"

    def probe(pair: tuple[str, str]) -> dict[str, object] | None:
        url, method = pair
        wants_body = method in ("POST", "PUT", "PATCH")
        headers = {"Connection": "close"}
        headers.update(extra_headers)
        if wants_body and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json"
        snap = carried.get(url) or {}
        sent_headers = dict(headers)
        if snap:
            sent_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in snap.items())

        # 为什么最多试三次、且最后一次不带 body：
        # 靶机在参数校验失败时常常"不等请求体读完就回包并关连接"，
        # 客户端还没发完 body 就收到 RST（Windows 10053），
        # 连已经到达的 400 响应都会一起丢掉。实测 body 型请求约 5% 概率撞上，
        # 而无 body 请求 0/300 失败。少一个 body 只影响"字段名"这一层信息，
        # 丢掉整行却等于把"这个路径上有这个方法"删了——后者贵得多。
        attempts: list[bytes | None] = [b"{}", b"{}", None] if wants_body else [None, None, None]
        last: Exception | None = None
        r = None
        sent: bytes | None = None
        # 和 http_probe 同一条规则：id 在**发请求前**预留。失败组合也入台账，
        # 因为"这条路上这个方法被拒了"本身就是终止重复尝试的观测。
        request_id = traffic.ledger().next_id()
        started = time.time()
        for index, body in enumerate(attempts):
            try:
                sent = body
                r = requests.request(
                    method, url, timeout=_TIMEOUT, verify=False,
                    allow_redirects=False, headers=headers, cookies=snap or None,
                    data=body,
                )
                break
            except Exception as exc:  # noqa: BLE001
                last = exc
                if index + 1 < len(attempts):
                    time.sleep(0.1 * (index + 1))
        elapsed = time.time() - started
        if r is None:
            note = f"{type(last).__name__} after {len(attempts)} tries"
            traffic.record(
                request_id=request_id, method=method, url=url, req_headers=sent_headers,
                req_body=sent.decode("utf-8", "replace") if sent else "",
                phase=type(last).__name__, elapsed=elapsed, note=note,
            )
            return {
                "method": method, "url": url, "status": 0,
                "note": note, "id": request_id,
            }
        allow = r.headers.get("allow", "")
        try:
            body_text = r.text or ""
        except Exception:  # noqa: BLE001 - 解码失败不影响这条证据本身
            body_text = ""
        traffic.record(
            request_id=request_id, method=method, url=url, req_headers=sent_headers,
            req_body=sent.decode("utf-8", "replace") if sent else "",
            status=r.status_code, resp_headers=dict(r.headers), resp_body=body_text,
            size=len(r.content or b""), elapsed=elapsed,
        )
        text = body_text.replace("\n", " ")[:160]
        return {
            "method": method, "url": url, "status": r.status_code,
            "size": len(r.content or b""), "allow": allow, "body": text,
            "id": request_id,
        }

    # WEB-1：扫描沿用 http_probe 的登录态。Session 不是线程安全的，所以
    # 不共享 Session 对象，只把 jar 里匹配各目标 host 的 cookie 拍快照随请求
    # 附带（扫描只读，Set-Cookie 不回写会话）。
    carried = {t: session_cookies(session, t) for t in targets}
    pairs = [(t, m) for t in targets for m in mlist]
    with ThreadPoolExecutor(max_workers=max(1, min(12, int(concurrency)))) as pool:
        results = [r for r in pool.map(probe, pairs) if r]

    def looks_json(body: object) -> bool:
        head = str(body or "").lstrip()[:1]
        return head in ("{", "[")

    def interesting(r: dict[str, object]) -> bool:
        """哪些组合值得占一行上下文。

        - 404：纯噪音，全丢。
        - 405：只在带 ``Allow`` 时留（Allow 本身就是可用方法清单）。
        - 501：多数是服务器/反向代理的默认错误页（一整屏 HTML），
          只有返回 JSON 时才可能藏着真实信息。
        """
        status = int(r["status"])
        if status == 0:
            return True
        if status == 404:
            return False
        if status == 405:
            return bool(r.get("allow"))
        if status == 501:
            return looks_json(r.get("body"))
        return True

    kept = [r for r in results if interesting(r)]

    def rank(r: dict[str, object]) -> tuple[int, int, int]:
        status = int(r["status"])
        backend = 0 if status == 0 else (1 if 500 <= status < 600 else (2 if 200 <= status < 300 else 3))
        body_signal = 0 if "required" in str(r.get("body", "")).lower() else 1
        return (backend, body_signal, -int(r.get("size", 0)))

    kept.sort(key=rank, reverse=True)
    shown = kept[:_MAX_ROWS]

    lines = [
        f"[method_sweep] {len(targets)} 路径 × {len(mlist)} 方法 = {len(pairs)} 请求 | "
        f"有信息量 {len(kept)} 条（列前 {len(shown)}）"
    ]
    if any(carried.values()):
        n_auth = sum(1 for v in carried.values() if v)
        lines.append(
            f"auth: {n_auth}/{len(targets)} 个目标带上了会话 cookie"
            "（http_probe 的登录态对本批生效；扫描不回写会话）"
        )
    for r in shown:
        status = int(r["status"])
        rid = str(r.get("id", ""))
        if status == 0:
            lines.append(f"{rid:<5} ERR {r['method']:7} {r['url']} | {r.get('note', '')}")
            continue
        extra = f" allow={r['allow']}" if r.get("allow") else ""
        body = str(r.get("body") or "")
        lines.append(
            f"{rid:<5} {status} {str(r['method']):7} {r['url']} | {r.get('size', 0)}B{extra}"
            + (f" | {body}" if body else "")
        )
    if len(kept) > len(shown):
        lines.append(f"…另有 {len(kept) - len(shown)} 条省略")

    # PortSwigger 的 API 测试方法论里，"识别支持的方法"之后的下一步就是
    # "识别支持的内容类型"——同一个端点换成 form/xml 往往走不同的解析分支，
    # XML 分支常直接通向 XXE。这一步不自动做（请求量翻三倍），但必须提示。
    body_methods = [r for r in kept if str(r.get("method")) in ("POST", "PUT", "PATCH")]
    if body_methods:
        lines.append(
            "next: 这些带 body 的端点也值得换 Content-Type 再试一次："
            "application/json / application/x-www-form-urlencoded / application/xml"
            "（XML 分支常能撬出 XXE）。"
        )

    has_param_hint = any(
        "required" in str(r.get("body", "")).lower() or int(r["status"]) in (400, 422) for r in kept
    )
    if has_param_hint:
        lines.append(
            "next: 已经有接口吐出了字段名/校验错误——这是最省力的一条路。"
            "用 http_probe 按它要的字段构造 body 再发一次。"
        )
    elif not kept:
        lines.append(
            "next: 所有组合都是 404/405。别再换方法，换路径族"
            "（这条线上已经没有未文档化入口了）。"
        )

    # 一次批量探索只回摘要：完整响应留在台账里，行首 id 就是取回的 key。
    # 这一行无条件出现——404 组合虽然不占行，但同样在台账里，"我试过它"
    # 这条证据要能被读回来，否则同一批组合会被反复重发。
    example = str(shown[0].get("id", "")) if shown else (
        str(results[0].get("id", "")) if results else ""
    )
    lines.append(
        "next: 上面每一行、以及被省略的组合都已进流量台账（行首 id = request_id）"
        + (f"，例如 traffic_view(\"{example}\") 可重读完整 body" if example else "")
        + "。不要为了再看一眼 body 重发同一个请求；"
        "某个路径到底试过哪些方法，用 traffic_list(url_contains=\"<路径>\") 找回。"
    )
    return "\n".join(lines)


TOOLS: Final = (route_map, method_sweep)


def register(register_fn=None) -> list[str]:
    """把两个发现原语注册进 strix 的扫描 agent。

    Args:
        register_fn: 注入点，默认取 ``factory.register_agent_tools``。

    Returns:
        本次新注册的工具名列表。
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=180)(fn) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]