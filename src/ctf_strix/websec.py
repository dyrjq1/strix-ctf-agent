"""Web 对照探测：越权三态对照（authdiff）+ JS 静态侦察（jsrecon）。

## 来源与授权

判定逻辑、变体集合、抽取正则与输出结构复用自 ctfy_project 的
``tools_websec.py``（队伍「一只七彩尧狼」，已获该队同意于 2026-11-17
直接复用）。传输层按本仓约定重写：``requests`` + 按宿主只读的 cookie
快照（``http_probe`` 的登录态沿用、扫描不回写）+ ``traffic`` 台账
（每次变体先占 id 再发，失败也落盘）。

## 为什么需要这两个工具

- ``authdiff``：实测瓶颈在「flag 发现 / access-control 面」。手工判定
  「这个端点是否忘鉴权」至少要发 2~4 次请求再肉眼比对，做成一次调用。
  基线（带会话）/ 匿名（去 Cookie 且剥凭据头）/ 代理绕过头 / 路径变形
  四组变体，比对状态码、长度、内容哈希，直接给「匿名可读=疑似未鉴权」
  结论——该结论以基线 2xx 为前提（基线 403/404 时对照无区分度）。
- ``jsrecon``：SPA 题把 bundle 落盘再 grep 要烧 3~4 步；``route_map``
  只抓静态链接/表单，抓不到 JS 里的 API 面。一次调用抽 API 路径、
  参数名、前端路由、硬编码密钥线索、sourceMap 与可疑注释。

## 设计约束（与参考实现一致，与本仓其他扫描工具对齐）

- 变体集合、请求头、路径变形全部白名单化，模型只能「选集合」；
- 每次调用有总墙钟预算（tarpit 目标不该拖死单步）；
- 输出有硬上限且保持合法 JSON（超限先裁列表再硬切）；
- 会话只读沿用：从不把扫描期间的 ``Set-Cookie`` 写回 ``http_probe``
  的会话（与 ``variants`` 同一纪律）。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Final
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from ctf_strix import traffic
from ctf_strix.http_probe import session_cookies

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: 工具输出的硬上限（字符），与参考实现同值。
TOOL_TEXT_MAX: Final = 6000
#: 输出截断时给尾部提示留的空间。
_ADDED_LEN: Final = 40

# ---------- authdiff ----------
AUTHDIFF_MAX_HEADERS: Final = 6
#: anon+bypass+path 全开 = 1+1+4+7 = 13 行，上限要盖住。
AUTHDIFF_MAX_ROWS: Final = 14
#: 总墙钟预算（秒）：tarpit 目标不该拖死单步。
AUTHDIFF_BUDGET: Final = 45.0
#: 单个变体的请求超时。
AUTHDIFF_TIMEOUT: Final = 10.0
#: 常见「信任客户端头」的绕过头：只发这 4 个，不开放任意头名。
AUTHDIFF_BYPASS_HEADERS: Final = (
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-Admin", "true"),
)
AUTHDIFF_VARIANTS: Final = ("anon", "bypass", "path")
#: 只允许幂等/低破坏方法：对照一次会重放 6~13 个变体，PUT/PATCH/DELETE
#: 的重放放大（连删 6 次、触发锁定）比它的对照价值贵得多——写端点的
#: 越权判定用 http_probe 单发一次就够。
_METHODS: Final = ("GET", "POST", "HEAD")
#: anon 变体除 Cookie 外还必须剥掉的凭据头（大小写不敏感）：模型给的
#: ``headers_json`` 里带 Authorization 时，"匿名"请求其实是带凭据的，
#: 对照会得出反向结论（S1，codex 审查 2026-11-17）。
_ANON_STRIP_HEADERS: Final = (
    "authorization", "cookie", "x-api-key", "x-auth-token", "x-session-id",
    "x-token", "proxy-authorization", "x-csrf-token",
)

# ---------- jsrecon ----------
JSRECON_MAX_BUNDLES: Final = 6
#: 单个 bundle 只留前 512KB。
JSRECON_MAX_BUNDLE_CHARS: Final = 512 * 1024
#: 流式读取的硬字节上限（解压后）：gzip 炸弹/超大 bundle 不整段进内存。
JSRECON_MAX_BUNDLE_BYTES: Final = 2 * 1024 * 1024
#: 所有 JS 合计上限（防内存爆）。
JSRECON_MAX_JSON_CHARS: Final = 6 * 1024 * 1024
JSRECON_MAX_PER_KIND: Final = 12
#: 页面 + bundle 抓取的总墙钟预算（秒）。
JSRECON_BUDGET: Final = 60.0
JSRECON_TIMEOUT: Final = 10.0
JSRECON_NOISE_EXT: Final = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".txt",
)

#: 与 ``http_probe`` 相同的 UA：不少靶机/WAF 直接拦 python-requests。
_UA: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def _clip(text: str, limit: int = TOOL_TEXT_MAX) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - _ADDED_LEN] + f"\n...[已截断，原长 {len(text)} 字符]"


def _h8(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:8]


def _fail(msg: str) -> ValueError:
    """参数面错误：调用方捕获后转成可读报错字符串，不发无效请求。"""
    return ValueError(msg)


def _clean_headers(headers) -> dict[str, str]:
    """模型给的头：只留单行、无控制字符的键值（防 CRLF 拆请求）。"""
    if not headers:
        return {}
    if not isinstance(headers, dict):
        raise _fail("headers 必须是 JSON 对象")
    if len(headers) > AUTHDIFF_MAX_HEADERS:
        raise _fail(f"headers 最多 {AUTHDIFF_MAX_HEADERS} 个")
    out: dict[str, str] = {}
    for key, value in headers.items():
        k, v = str(key), str(value)
        if not k or any(c in k + v for c in "\r\n"):
            raise _fail(f"header 非法（空名或含换行）：{k!r}")
        out[k] = v
    return out


def _fetch(
    url: str,
    *,
    method: str = "GET",
    body: str = "",
    extra_headers: dict[str, str] | None = None,
    session: str | None = "auto",
    follow_redirects: bool = False,
    timeout: float = AUTHDIFF_TIMEOUT,
    max_bytes: int | None = None,
) -> tuple[str, str, int, str, str]:
    """发一个请求，返回 (台账 id, 最终 URL, status, content-type, body)。

    本仓约定的传输层：``requests`` 直发 + 按宿主只读 cookie 快照
    （``http_probe`` 的登录态沿用；``Set-Cookie`` 永不回写）+ 台账
    先占 id 再发（失败也落盘，同 ``variants`` 的纪律）。
    ``session=None`` 表示匿名（不带任何 cookie）。

    - 台账 id 回传给调用方：变体行里带上 id，模型才能用
      ``traffic_diff`` 对着具体两条记录做字段级比对（S3）。
    - 最终 URL（跟随重定向之后）：jsrecon 的相对 ``src`` 必须按它解析，
      按原始 target 解析会把 ``/login`` 页面的 ``static/app.js`` 抓错。
    - ``max_bytes``：流式读取的硬字节上限（gzip 炸弹/超大 bundle 不该
      在解压后整段进内存）。
    """
    snap = session_cookies(session, url) if session else {}
    headers = {"Connection": "close", "User-Agent": _UA}
    if extra_headers:
        headers.update(extra_headers)
    sent_headers = dict(headers)
    if snap:
        sent_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in snap.items())
    request_id = traffic.ledger().next_id()
    started = time.time()
    try:
        resp = requests.request(
            method, url, timeout=timeout, verify=False,
            allow_redirects=follow_redirects, headers=headers,
            cookies=snap or None, data=body.encode("utf-8") if body else None,
            stream=max_bytes is not None,
        )
    except Exception as exc:  # noqa: BLE001 — 失败也入台账，死路不该被重试
        traffic.record(
            request_id=request_id, method=method, url=url, req_headers=sent_headers,
            phase=type(exc).__name__, elapsed=time.time() - started,
            note=f"{type(exc).__name__}: {exc}"[:300],
        )
        raise
    size = 0
    if max_bytes is None:
        text = resp.text or ""
        size = len(resp.content or b"")
    else:
        chunks: list[bytes] = []
        for chunk in resp.iter_content(64 * 1024):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= max_bytes:
                break
        resp.close()
        raw = b"".join(chunks)
        text = raw.decode(resp.encoding or "utf-8", "replace")
    traffic.record(
        request_id=request_id, method=method, url=url, req_headers=sent_headers,
        status=resp.status_code, resp_headers=dict(resp.headers), resp_body=text,
        size=size, elapsed=time.time() - started,
        body_keep=64 * 1024,
    )
    return (
        request_id,
        str(resp.url or url),
        resp.status_code,
        (resp.headers.get("content-type") or ""),
        text,
    )


def _parse_variants(variants: str) -> list[str]:
    picked: list[str] = []
    for token in str(variants or "").split(","):
        item = token.strip().lower()
        if not item:
            continue
        if item not in AUTHDIFF_VARIANTS:
            raise _fail(f"未知变体 {item!r}，可选：{', '.join(AUTHDIFF_VARIANTS)}")
        if item not in picked:
            picked.append(item)
    return picked or ["anon", "bypass"]


def _path_variants(url: str) -> list[tuple[str, str]]:
    """常见路径归一化绕过变形（与基线不同的才返回）。"""
    parsed = urlparse(url)
    path = parsed.path or "/"
    qs = parsed.query
    candidates = [
        ("trailing-slash", path + ("/" if not path.endswith("/") else "")),
        ("double-slash", "//" + path.lstrip("/")),
        ("dot-segment", "/./" + path.lstrip("/")),
        ("semicolon", path.rstrip("/") + "/..;/"),
        ("upper", path.upper()),
        ("encoded-dot", "/%2e" + path),
        ("trailing-dot", path.rstrip("/") + "/."),
    ]
    out: list[tuple[str, str]] = []
    seen = {path}
    for label, vpath in candidates:
        if vpath in seen or vpath == path:
            continue
        seen.add(vpath)
        out.append((label, parsed._replace(path=vpath, query=qs).geturl()))
    return out


def _strip_credentials(headers: dict | None) -> dict | None:
    """anon 变体的头：剥掉凭据类头（S1）——否则"匿名"请求其实带凭据。"""
    if not headers:
        return None
    return {k: v for k, v in headers.items()
            if str(k).lower() not in _ANON_STRIP_HEADERS}


def _probe(url: str, *, label: str, method: str, body: str,
           extra_headers: dict | None, session: str | None) -> dict:
    """发一个变体，返回可比较的三元组；失败不抛出，标记 error 继续。"""
    row: dict = {"label": label, "url": url}
    try:
        rid, _final, status, ctype, text = _fetch(
            url, method=method, body=body,
            extra_headers=extra_headers, session=session,
        )
    except Exception as exc:  # noqa: BLE001 — 单个变体失败不该让整次对照作废
        row["error"] = f"{type(exc).__name__}: {exc}"
        return row
    row.update({
        "id": rid,
        "status": status,
        "len": len(text or ""),
        "h": _h8(text or ""),
        "type": (ctype or "").split(";")[0].strip()[:40],
    })
    return row


def _same(a: dict, b: dict) -> bool:
    return (a.get("status") == b.get("status")
            and a.get("len") == b.get("len")
            and a.get("h") == b.get("h"))


def _run_authdiff(*, url: str = "", method: str = "GET", body: str = "",
                  headers: dict | None = None, variants: str = "anon,bypass",
                  session: str = "auto") -> str:
    """越权/鉴权多态对照，返回结论 JSON。"""
    target = (url or "").strip()
    if not target:
        raise _fail("authdiff 需要 url")
    method = (method or "GET").strip().upper()
    if method not in _METHODS:
        raise _fail(f"method 非法：{method!r}（支持 {', '.join(_METHODS)}）")
    hdrs = _clean_headers(headers)
    picked = _parse_variants(variants)
    cookie_present = bool(session_cookies(session, target))

    rows: list[dict] = []
    # 先把全部变体排成计划，再按总墙钟预算逐个执行；基线永远第一个跑。
    started = time.perf_counter()
    plan: list[tuple[str, str, dict | None, str | None]] = [
        ("authed", target, hdrs or None, session)
    ]
    if "anon" in picked:
        # S1：匿名变体必须连模型给的凭据头一起剥掉，只留 Cookie 快照的去除
        # （session=None）不够——Authorization/X-API-Key 照发的话对照是假的。
        plan.append(("anon", target, _strip_credentials(hdrs), None))
    if "bypass" in picked:
        for name, value in AUTHDIFF_BYPASS_HEADERS:
            merged = dict(hdrs)
            merged[name] = value
            plan.append((f"bypass:{name}", target, merged, session))
    if "path" in picked:
        for plabel, vurl in _path_variants(target):
            plan.append((f"path:{plabel}", vurl, hdrs or None, session))

    stopped_early = False
    for label, purl, pheaders, psession in plan:
        if rows and time.perf_counter() - started > AUTHDIFF_BUDGET:
            stopped_early = True
            break
        rows.append(_probe(purl, label=label, method=method, body=body,
                           extra_headers=pheaders, session=psession))
    baseline = rows[0]

    by_label = {r["label"]: r for r in rows}
    for row in rows:
        if row is not baseline and "error" not in row and "error" not in baseline:
            row["same"] = _same(row, baseline)

    verdicts: list[str] = []
    if "error" in baseline:
        verdicts.append("基线请求失败，先确认目标可达与会话有效")
    else:
        # S2：匿名可读/鉴权生效的结论都以「基线本身是 2xx」为前提。基线
        # 403/404/302 时 anon 与基线相同只说明两者都被拒/都不存在，把它判成
        # 「匿名可读=疑似未鉴权」是反向结论。
        base_status = baseline.get("status")
        base_ok = isinstance(base_status, int) and 200 <= base_status < 300
        anon = by_label.get("anon")
        if not base_ok:
            verdicts.append(
                f"基线不可读（HTTP {base_status}）：404=路径不存在、"
                "401/403=会话/凭证无效、302=被重定向——先修基线，对照结论"
                "此刻没有意义"
            )
        elif anon:
            if "error" in anon:
                verdicts.append("匿名请求失败")
            elif anon.get("same"):
                if cookie_present:
                    verdicts.append("匿名可读：去掉 Cookie 后与基线完全一致 → "
                                    "该端点疑似未鉴权（越权线索）")
                else:
                    verdicts.append("该端点不要求会话即可读取（当前 jar 没有该站 "
                                    "Cookie，anon 与基线必然相同，此结论只说明"
                                    "「不需要登录」，先登录拿到会话再跑一次才有"
                                    "越权判定意义）")
            elif anon.get("status") == base_status:
                verdicts.append("匿名可达但内容不同 → 可能只有部分字段受控，"
                                "值得按字段 diff")
            else:
                verdicts.append("鉴权生效：匿名请求被拒（状态码不同）")
        # bypass / path 的"生效"分两档：命中 2xx 才叫疑似绕过；只改成了
        # 500/404 之类，最多说明错误页不同，不能引模型去复验（动态页的
        # CSRF/nonce 抖动也会让哈希必然不同）。
        for prefix, what in (("bypass:", "绕过头"), ("path:", "路径变形")):
            changed = [r for r in rows
                       if r["label"].startswith(prefix) and not r.get("same")
                       and "error" not in r]
            if not changed:
                continue
            hits = [r["label"] for r in changed
                    if isinstance(r.get("status"), int) and 200 <= r["status"] < 300]
            misses = [r["label"] for r in changed if r["label"] not in hits]
            if hits:
                verdicts.append(f"{what}疑似生效：{', '.join(hits)} 返回 2xx → "
                                "服务端信任客户端代理头/归一化差异可绕过路由")
            if misses:
                verdicts.append(f"{what}仅改变结果（非 2xx）：{', '.join(misses)} "
                                "——可能是错误页差异或动态内容抖动，需先复验")
        if not verdicts:
            verdicts.append("各变体无差异：该端点表现一致，换下一个输入点")

    if len(rows) > AUTHDIFF_MAX_ROWS:
        rows = rows[:AUTHDIFF_MAX_ROWS]
        verdicts.append(f"变体过多已截断到 {AUTHDIFF_MAX_ROWS} 条")
    payload = {
        "tool": "authdiff",
        "target": target,
        "method": method,
        "baseline": {k: baseline.get(k) for k in
                     ("id", "status", "len", "h", "type", "error") if k in baseline},
        "rows": rows,
        "verdicts": verdicts,
        "next": ("命中的绕过头/路径变形可直接用于 http_probe 复验；字段级差异"
                 "用 traffic_diff 按行内 id 比两条台账记录。"
                 if any("疑似生效" in v or "匿名可读" in v for v in verdicts)
                 else "换个端点或换 method（POST）再对照一次。"),
    }
    if stopped_early:
        payload["stopped_early"] = True
        payload["notes"] = [f"超过 {AUTHDIFF_BUDGET:.0f}s 预算，"
                            f"{len(rows)}/{len(plan)} 个变体已完成，结论基于已完成部分"]
    # 超限：按信息量从低到高裁（行从尾部裁，verdicts 是结论不裁），保持
    # 返回合法 JSON；_clip 只是最后兜底（硬切会破坏 JSON，模型拿到一段
    # 坏文本比少几行行更糟）。
    text = json.dumps(payload, ensure_ascii=False)
    while len(text) > TOOL_TEXT_MAX and len(payload["rows"]) > 1:
        payload["rows"] = payload["rows"][:-1]
        text = json.dumps(payload, ensure_ascii=False)
    if len(text) > TOOL_TEXT_MAX and len(payload.get("verdicts", [])) > 1:
        payload["verdicts"] = payload["verdicts"][:-1]
        text = json.dumps(payload, ensure_ascii=False)
    return _clip(text)


async def authdiff(
    url: str = "",
    method: str = "GET",
    body: str = "",
    headers_json: str = "",
    variants: str = "anon,bypass",
    session: str = "auto",
) -> str:
    """越权/鉴权对照探针：同请求多组变体一次出结论。

    把同一个请求按「原样（带会话）／去 Cookie／加代理绕过头／路径变形」
    四组变体各发一次，比对状态码、长度、内容哈希，直接给出「匿名可读=
    疑似未鉴权」这类结论。变体集合只能从 anon/bypass/path 里选。

    Args:
        url: 要对照的完整 URL（必填）。
        method: 请求方法，GET / POST / HEAD，默认 GET。写方法（PUT/PATCH/
            DELETE）不做对照——一次对照会重放 6~13 个变体，破坏性重放的
            放大风险大于对照价值；写端点的越权用 http_probe 单发判定。
        body: POST 等方法的请求体。
        headers_json: 额外请求头（JSON 字符串，≤6 个），如
            ``{"X-Custom": "v"}``。
        variants: 变体集合，逗号分隔：anon=去 Cookie；bypass=代理绕过头
            （X-Forwarded-For / X-Original-URL / X-Rewrite-URL / X-Admin）；
            path=路径变形（尾斜杠/双斜杠/点段/分号/大写/编码点/尾点）。
            默认 anon,bypass。
        session: 与 ``http_probe`` 同口径。默认 auto：沿用其按宿主的登录
            态做基线与带会话变体；anon 变体永远匿名。

    Returns:
        JSON：baseline、每行变体的三元组与 same 标记、verdicts 结论、
        next 下一步。所有请求都记入台账，可用 traffic_view / traffic_diff。
    """
    try:
        headers = json.loads(headers_json) if headers_json.strip() else {}
    except json.JSONDecodeError as exc:
        return f"[authdiff] headers_json 不是合法 JSON：{exc}"
    if not isinstance(headers, dict):
        return "[authdiff] headers_json 必须是 JSON 对象（花括号）。"
    try:
        return await asyncio.to_thread(
            _run_authdiff, url=url, method=method, body=body,
            headers=headers, variants=variants, session=session,
        )
    except ValueError as exc:
        return f"[authdiff] {exc}"


# ---------------- jsrecon ----------------

_SCRIPT_SRC_RE = re.compile(r"""(?is)<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""")
_INLINE_SCRIPT_RE = re.compile(r"(?is)<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>")
_SOURCEMAP_RE = re.compile(r"[#@]\s*sourceMappingURL=([^\s*\"']{3,200})")
_FETCH_CALL_RE = re.compile(
    r"""(?i)\b(fetch|axios(?:\.(?:get|post|put|delete|patch))?|\$\.(?:get|post|ajax))\s*\(\s*["'`]([^"'`]{2,200})["'`]"""
)
_STR_LIT_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./{}:$~%]{2,80})["'`]""")
_PARAMS_OBJ_RE = re.compile(r"(?is)\b(?:params|body|data|payload|query)\s*:\s*\{([^{}]{0,400})\}")
_PARAM_KEY_RE = re.compile(r"""["']?([A-Za-z_$][\w$]{1,30})["']?\s*:""")
_SEARCHPARAM_RE = re.compile(r"""(?i)searchParams\.(?:set|append)\(\s*["'`]([^"'`]{1,40})["'`]""")
_ROUTE_PATH_RE = re.compile(r"""(?i)\bpath\s*:\s*["'`](/[^"'`]{1,80})["'`]""")
_SECRET_RE = re.compile(
    r"""(?i)\b(api[_-]?key|secret|token|password|passwd|bearer|access[_-]?key)\b\s*[:=]\s*["'`]([^"'`\s]{6,120})["'`]"""
)
_COMMENT_HINT_RE = re.compile(
    r"(?i)(?://|/\*)\s*([^\n]{0,160}?\b(?:TODO|FIXME|HACK|debug|internal|admin|flag)\b[^\n]{0,120})"
)
_PRIORITY_WORDS: Final = (
    "admin", "internal", "flag", "upload", "user", "auth", "login", "token", "api",
)


def _rank(items: list[str]) -> list[str]:
    def score(item: str) -> int:
        low = item.lower()
        return -sum(1 for word in _PRIORITY_WORDS if word in low)
    return sorted(dict.fromkeys(items), key=score)


def _is_noise_path(path: str) -> bool:
    low = path.lower().split("?")[0]
    if low in ("/", ""):
        return True
    return low.endswith(JSRECON_NOISE_EXT)


def _run_jsrecon(*, url: str = "", session: str = "auto") -> str:
    """拉页面 + bundle，抽 API 面，返回结论 JSON。"""
    target = (url or "").strip()
    if not target:
        raise _fail("jsrecon 需要 url")
    started = time.perf_counter()

    try:
        _rid, page_url, status, ctype, html = _fetch(
            target, method="GET", session=session,
            follow_redirects=True, timeout=JSRECON_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 — 首屏不可达给可读报错，不是裸异常
        raise _fail(f"页面不可达：{type(exc).__name__}: {exc}") from exc
    scripts = _SCRIPT_SRC_RE.findall(html or "")
    inline = _INLINE_SCRIPT_RE.findall(html or "")

    bundles: list[dict] = []
    js_chunks: list[str] = []
    budget = JSRECON_MAX_JSON_CHARS
    stopped_early = False
    # 同源纪律（与 discovery 一致）：页面内容是**不可信输入**，页面里写的
    # 第三方绝对 URL 不抓（防 SSRF 式元数据端点/内网探测由页面内容驱动）；
    # 相对 src 按重定向后的最终页面 URL 解析（302 到 /login 后，
    # static/app.js 该挂在 /login/static/ 下）。
    origin_host = urlparse(page_url).netloc
    seen_src: set[str] = set()
    skipped_cross = 0
    picked_src: list[str] = []
    for src in scripts:
        abs_url = urljoin(page_url, src)
        if urlparse(abs_url).netloc != origin_host:
            skipped_cross += 1
            continue
        if abs_url in seen_src:
            continue
        seen_src.add(abs_url)
        picked_src.append(abs_url)
        if len(picked_src) >= JSRECON_MAX_BUNDLES:
            break
    for abs_url in picked_src:
        if time.perf_counter() - started > JSRECON_BUDGET:
            stopped_early = True
            break
        try:
            rid, final_url, bstatus, bctype, text = _fetch(
                abs_url, method="GET", session=session,
                follow_redirects=True, timeout=JSRECON_TIMEOUT,
                max_bytes=JSRECON_MAX_BUNDLE_BYTES,
            )
        except Exception as exc:  # noqa: BLE001 — 单个 bundle 失败不该作废整次
            bundles.append({"url": abs_url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        text = text or ""
        truncated = len(text) >= JSRECON_MAX_BUNDLE_CHARS
        kept = text[:JSRECON_MAX_BUNDLE_CHARS]
        if budget > 0:
            kept = kept[:budget]
            budget -= len(kept)
            js_chunks.append(kept)
        bundles.append({"url": abs_url, "id": rid, "status": bstatus,
                        "len": len(text), "truncated": truncated})

    for chunk in inline:
        if budget <= 0:
            break
        kept = (chunk or "")[:budget]
        budget -= len(kept)
        js_chunks.append(kept)

    js = "\n".join(js_chunks)
    api_paths = [p for p in _STR_LIT_PATH_RE.findall(js) if not _is_noise_path(p)]
    calls = [f"{fn}({arg})" for fn, arg in _FETCH_CALL_RE.findall(js)][:JSRECON_MAX_PER_KIND * 2]
    params: list[str] = []
    for block in _PARAMS_OBJ_RE.findall(js):
        params.extend(_PARAM_KEY_RE.findall(block))
    params.extend(_SEARCHPARAM_RE.findall(js))
    routes = _ROUTE_PATH_RE.findall(js)
    secrets = [f"{k}={v[:60]}" for k, v in _SECRET_RE.findall(js)]
    maps = _SOURCEMAP_RE.findall(js)
    comments = [c.strip() for c in _COMMENT_HINT_RE.findall(js)]

    payload = {
        "tool": "jsrecon",
        "page": {"status": status, "bytes": len(html or ""),
                 "type": (ctype or "").split(";")[0].strip()[:40],
                 "scripts": len(scripts), "inline": len(inline)},
        "skipped_cross_origin": skipped_cross,
        "bundles": bundles,
        "api": _rank(api_paths)[:JSRECON_MAX_PER_KIND],
        "api_total": len(set(api_paths)),
        "calls": calls[:JSRECON_MAX_PER_KIND],
        "params": _rank(params)[:JSRECON_MAX_PER_KIND],
        "routes": _rank(routes)[:JSRECON_MAX_PER_KIND],
        "secrets": secrets[:JSRECON_MAX_PER_KIND],
        "sourcemaps": maps[:4],
        "comments": comments[:6],
    }
    if not api_paths and not calls:
        payload["note"] = ("没抽到 API 线索：可能是纯静态站或 bundle 被混淆/加密；"
                           "先用 route_map crawl 看链接与表单，或对可疑 path 直接 "
                           "http_probe。")
    elif payload["sourcemaps"]:
        payload["note"] = "发现 sourceMap，可拉 .map 还原源码后按行读（比猜路径快）。"
    else:
        payload["note"] = ("对高置信 API 路径用 http_probe 逐个读；参数名可用于"
                           "方法对照或字典候选。")

    if stopped_early:
        payload["stopped_early"] = True
        payload["note"] = f"超过 {JSRECON_BUDGET:.0f}s 抓取预算提前停止；" + payload.get("note", "")

    # 超限：按优先级从低到高裁列表，保证返回合法 JSON（bundles 是兜底）。
    text = json.dumps(payload, ensure_ascii=False)
    for key in ("comments", "sourcemaps", "routes", "params", "calls", "api", "bundles"):
        while len(text) > TOOL_TEXT_MAX and payload.get(key):
            payload[key] = payload[key][:-1]
            text = json.dumps(payload, ensure_ascii=False)
    return _clip(text)


async def jsrecon(url: str = "", session: str = "auto") -> str:
    """JS 静态侦察：拉页面 bundle 抽 API 面，一次出全。

    抓页面引用的前端 bundle 与内联脚本，抽取 API 路径、参数名、前端路由、
    硬编码密钥线索、sourceMap 与可疑注释。用于「SPA 空壳、接口只在 JS
    里」的题，省掉手工落盘 + grep 的步骤。

    Args:
        url: 页面 URL（必填）。
        session: 与 ``http_probe`` 同口径；默认 auto 沿用登录态。

    Returns:
        JSON：page / bundles / api / params / routes / secrets / sourcemaps /
        comments，按 admin·internal·flag 等优先词排序。
    """
    try:
        return await asyncio.to_thread(_run_jsrecon, url=url, session=session)
    except ValueError as exc:
        return f"[jsrecon] {exc}"


TOOLS = (authdiff, jsrecon)


def register(register_fn=None) -> list[str]:
    """Register ``authdiff`` / ``jsrecon`` on every scan agent built afterwards."""
    from agents import function_tool

    if register_fn is None:
        from strix.agents import factory
        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()
    wrapped = [function_tool(timeout=120)(fn) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]
