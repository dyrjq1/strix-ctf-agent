"""发现层：把 009 里"靠运气撞到"的两个动作变成固定原语。

## 背景

CTFARENA-009 第一跑的 12 次调用里，有 4 次花在**肉眼看压缩后的 JS**：

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

import re
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Final
from urllib.parse import urljoin, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: 一次最多抓多少个 chunk。超过这个数说明是巨型 SPA，收益递减。
_MAX_CHUNKS: Final = 12
#: route_map 最多回报多少条路径。
_MAX_ROUTES: Final = 30
#: method_sweep 最多回报多少行。
_MAX_ROWS: Final = 40
#: 单次请求超时。发现阶段要快，慢的端点留给 http_probe 单独打。
_TIMEOUT: Final = 8.0

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

    try:
        home = _get(base_url)
    except Exception as exc:  # noqa: BLE001
        return f"[route_map] 首页取不到：{type(exc).__name__}: {exc}。先用 http_probe 确认可达。"

    html = home.text or ""
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
    fetched = 0
    for ref in refs:
        try:
            resp = _get(ref)
        except Exception:  # noqa: BLE001 — 单个 chunk 失败不该毁掉整张图
            continue
        fetched += 1
        name = ref.rsplit("/", 1)[-1]
        blobs.append((resp.text or "")[:200_000])
        for m in _ROUTE_RE.finditer(resp.text or ""):
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
            "改用 method_sweep 打已知路径，或直接读首页 HTML 里的表单 action。"
        )

    def score(item: tuple[str, int]) -> tuple[int, int, int]:
        path, n = item
        depth = path.count("/")
        # 权重优先，其次出现次数，最后偏好两段式路径（/api/plugins 优于 /api/a/b/c/d）
        return (_weight(path), n, -abs(depth - 2))

    ranked = sorted(counts.items(), key=score, reverse=True)[:_MAX_ROUTES]
    lines = [
        f"[route_map] {base_url} | html {len(html)}B | chunks {fetched}/{len(refs)} | "
        f"候选 {len(counts)} 条（列前 {len(ranked)} 条）",
        # 这句必须放在**最前面**。009 复跑实测：route_map 第 3 次调用就给出了
        # 含 /api/plugins/preview 的 4 条候选，agent 仍然去下载 5 个 chunk
        # 用 cat/head 逐段读（第 17-21 次调用）。工具给了答案但没拦住旧习惯，
        # 于是答案被自己的"再看看"覆盖掉了。提示语放末尾没有用——模型读完
        # 列表就动手了，不会回头读最后一行。
        "⚠️ 上面就是全部路由，不要再下载或阅读 bundle 原文。下一步：method_sweep。",
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
        "是最容易撞出未文档化入口的动作。不要再去读 bundle 原文。"
    )
    return "\n".join(lines)


async def method_sweep(
    urls: str,
    base_url: str = "",
    methods: str = "OPTIONS,GET,POST,PUT,PATCH",
    concurrency: int = 6,
) -> str:
    """对一批路径换方法各打一遍，只回报有信息量的组合。

    Args:
        urls: 待测路径，换行或逗号分隔。相对路径（/api/x）会拼到 base_url 上；
            也可以直接写完整 URL。
        base_url: 相对路径的前缀，如 https://host 。全部路径都是绝对 URL 时可留空。
        methods: 逗号分隔的方法列表，默认 OPTIONS,GET,POST,PUT,PATCH。
        concurrency: 并发数，默认 6。别开太大——目标是比赛靶机，不是压测对象。

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
        if wants_body:
            headers["Content-Type"] = "application/json"

        # 为什么最多试三次、且最后一次不带 body：
        # 靶机在参数校验失败时常常"不等请求体读完就回包并关连接"，
        # 客户端还没发完 body 就收到 RST（Windows 10053），
        # 连已经到达的 400 响应都会一起丢掉。实测 body 型请求约 5% 概率撞上，
        # 而无 body 请求 0/300 失败。少一个 body 只影响"字段名"这一层信息，
        # 丢掉整行却等于把"这个路径上有这个方法"删了——后者贵得多。
        attempts: list[bytes | None] = [b"{}", b"{}", None] if wants_body else [None, None, None]
        last: Exception | None = None
        r = None
        for index, body in enumerate(attempts):
            try:
                r = requests.request(
                    method, url, timeout=_TIMEOUT, verify=False,
                    allow_redirects=False, headers=headers, data=body,
                )
                break
            except Exception as exc:  # noqa: BLE001
                last = exc
                if index + 1 < len(attempts):
                    time.sleep(0.1 * (index + 1))
        if r is None:
            return {
                "method": method, "url": url, "status": 0,
                "note": f"{type(last).__name__} after {len(attempts)} tries",
            }
        allow = r.headers.get("allow", "")
        text = (r.text or "").replace("\n", " ")[:160]
        return {
            "method": method, "url": url, "status": r.status_code,
            "size": len(r.content or b""), "allow": allow, "body": text,
        }

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
    for r in shown:
        status = int(r["status"])
        if status == 0:
            lines.append(f"ERR {r['method']:7} {r['url']} | {r.get('note', '')}")
            continue
        extra = f" allow={r['allow']}" if r.get("allow") else ""
        body = str(r.get("body") or "")
        lines.append(
            f"{status} {str(r['method']):7} {r['url']} | {r.get('size', 0)}B{extra}"
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