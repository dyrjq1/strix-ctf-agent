"""结构化 HTTP 原语：把"发一个请求"从 shell 字符串里解放出来。

## 为什么必须有这一层

2026-10-30 的一次第一跑，12 次工具调用里有 7 次零信息量，其中
最致命的一次是这样的：

```bash
B=https://<target>; for p in ...; do curl -s -o /tmp/o "$B$p"; echo "$?"; done
```

agent 自己写的脚本有两个 bug——``$B`` 在**上一条** ``exec_command`` 里定义，
新 shell 里是空的；``/tmp/o`` 也没建。于是每条都返回 ``000``，agent 读成
"目标不支持 POST"，直接放弃了唯一可行的入口。真正的入口
``POST /api/plugins/preview`` 就在那串 000 里。

**根因不是模型笨，是观测把三件事压成了同一个字符串**：

1. 域名解析失败
2. TCP 连不上
3. 请求根本没发出去（脚本自己写错）

对模型来说 ``000`` 三者等价，而它们的下一步动作完全相反。这个工具的唯一
职责就是**把这三件事分开**，并且在失败时直接给出下一步（Anthropic 的
"tool errors should carry actionable context"）。

## 设计约束

- **返回必须短**：默认 body 只留 1200 字符。上下文是有限预算，整页 HTML
  灌进去会把前几轮的结论挤掉（context rot）。
- **含 ``FLAG{`` 时不截断**：日志钩子曾把 flag 物理切断（旧总账缺陷 #6），
  这里放宽到 4000，宁可多花 token 也不能让答案残缺。
- **不跟随重定向**：默认 ``follow_redirects=False``。Web CTF 里 302 指向
  哪里本身就是信息，自动跟过去会把"跳转"这个事实抹掉。
- **不依赖 shell 变量**：每次调用自带 method/url/header/body。009 翻车是因为
  ``$B`` 定义在上一条 ``exec_command`` 里，新 shell 是空的。
- **有会话，但只按 host 走**：默认 ``session="auto"``，同一个
  scheme+host+port 复用同一个 ``requests.Session``：响应的 ``Set-Cookie``
  自动保留、下次调用自动带上——注册/登录之后不用自己抄 cookie。换 host
  自动换会话（不同题、不同实例互不污染）；``session="off"`` 回到完全无状态。
"""

from __future__ import annotations

import json
import threading
import time
from typing import Final
from urllib.parse import urlsplit

from ctf_strix import traffic

import requests
import urllib3

from requests.exceptions import (
    ConnectionError as ReqConnectionError,
    ConnectTimeout,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    ReadTimeout,
    SSLError,
    TooManyRedirects,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#: 普通响应体的上限。够看清 JSON 错误和一小段 HTML，又不至于撑爆上下文。
_BODY_LIMIT: Final = 1200
#: 命中 flag 时的上限。旧总账缺陷 #6：flag 被截断=整题白跑。
_FLAG_LIMIT: Final = 4000

#: 本进程的会话表：``key -> requests.Session``。key 由 ``_session_key`` 生成。
_SESSIONS: dict[str, requests.Session] = {}
_SESSIONS_LOCK = threading.Lock()

#: requests 默认 UA 是 ``python-requests/x.y``，不少靶机/WAF 直接按它拦。
_USER_AGENT: Final = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

#: 明确表示“不要会话”的写法。其余任何值都进会话。
_SESSION_OFF: Final = frozenset({"off", "none", "-", "stateless", "0"})


def _session_key(name: str, url: str) -> str | None:
    """把 ``session`` 参数解析成会话键；``None`` 表示本次请求不进会话。

    ``auto``（默认）按 scheme+host+port 分桶：同一靶机连续调用共享 cookie，
    换一道题/换一个实例自动换桶。这样做既不用模型记住任何东西，也不会把
    A 题的登录态带进 B 题。具名会话跨 host 共享，用于多域名流程。

    Args:
        name: 模型传入的 ``session`` 值。
        url: 本次请求的 URL（auto 模式据此分桶）。

    Returns:
        会话键；``None`` 表示本次请求无状态。
    """
    raw = (name or "").strip()
    low = raw.lower()
    if low in _SESSION_OFF:
        return None
    if low in ("", "auto"):
        parts = urlsplit(url)
        return f"auto:{parts.scheme}://{parts.netloc}"
    return f"named:{raw}"


def _get_session(key: str) -> requests.Session:
    """取出（或新建）具名会话。

    ``requests.Session`` 不是线程安全的，所以这里只做创建/取用，不加锁
    保护后续发送——``http_probe`` 本身是串行的工具调用。
    """
    with _SESSIONS_LOCK:
        sess = _SESSIONS.get(key)
        if sess is None:
            sess = requests.Session()
            sess.headers["User-Agent"] = _USER_AGENT
            _SESSIONS[key] = sess
        return sess


def reset_sessions() -> list[str]:
    """丢弃本进程所有会话，返回被丢掉的键。

    会话是有状态的：用例之间不隔离就会互相串 cookie。主要给测试用。
    """
    with _SESSIONS_LOCK:
        keys = sorted(_SESSIONS)
        _SESSIONS.clear()
    return keys


def session_cookies(name: str, url: str) -> dict[str, str]:
    """某个会话对当前 URL 的 host 持有的 cookie（只读快照，报告 WEB-1）。

    ``method_sweep`` / ``path_variants`` 在线程池里并发发请求，而
    ``requests.Session`` 不是线程安全的，不能直接共享 Session 对象。
    于是扫描工具改为：调这里把会话 jar 里与目标 host 匹配的 cookie 拍一份
    快照，随每个请求附带——``http_probe`` 登录拿到的态就自动延续到后续
    扫描。扫描期间的 ``Set-Cookie`` 不回写会话（扫描必须只读）。

    Args:
        name: 与 ``http_probe`` 的 ``session`` 参数同口径（auto/具名/off）。
        url: 本次请求的 URL（auto 模式按其 host 匹配）。

    Returns:
        cookie 名 → 值；会话不存在或没有匹配项时为空 dict。
    """
    key = _session_key(name, url)
    if key is None:
        return {}
    host = urlsplit(url).hostname or ""
    if not host:
        return {}
    with _SESSIONS_LOCK:
        sess = _SESSIONS.get(key)
        if sess is None:
            return {}
        out: dict[str, str] = {}
        try:
            for cookie in sess.cookies:
                dom = (getattr(cookie, "domain", "") or "").lstrip(".")
                if not dom:
                    continue
                # host cookie 的 domain 就是 host 本身；带 Domain 属性的
                # cookie 是 ".host" 形态，两种都要认。
                if host == dom or host.endswith("." + dom):
                    out[cookie.name] = cookie.value
        except Exception:  # noqa: BLE001 — 快照失败=没有登录态，不该炸扫描
            return {}
        return out


def _parse_cookies(raw: str) -> dict[str, str]:
    """解析 ``cookies`` 入参：接受 JSON 对象或 ``a=b; c=d``。

    Raises:
        ValueError: 写法不合法（调用方转成可读报错，不发无效请求）。
        json.JSONDecodeError: JSON 形式本身坏了。
    """
    text = (raw or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError('JSON 形式必须是对象，如 {"sid": "abc"}')
        return {str(k): str(v) for k, v in data.items()}
    out: dict[str, str] = {}
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        if not sep or not key.strip():
            raise ValueError(f"片段 {part!r} 不是 name=value")
        out[key.strip()] = value.strip()
    return out


def _jar_summary(sess: requests.Session, url: str) -> str:
    """本会话对该 host 的 cookie 一览——让"已经登录了"在上下文里可见。

    值截到 40 字符：cookie 常常就是票据本身，整串灌进上下文没必要。
    摘要失败不能打断请求，所以一律吞异常。
    """
    host = urlsplit(url).hostname or ""
    try:
        jar = sess.cookies.get_dict(domain=host) if host else sess.cookies.get_dict()
    except Exception:  # noqa: BLE001 — 摘要失败不该影响请求结果
        return ""
    if not jar:
        return ""
    shown = [f"{k}={str(v)[:40]}" for k, v in list(jar.items())[:6]]
    tail = f" (+{len(jar) - 6})" if len(jar) > 6 else ""
    return "jar: " + "; ".join(shown) + tail


#: 优先展示的响应头。其余头对解题的边际价值很低，全列只会稀释注意力。
_HEADER_PRIORITY: Final = (
    "allow",
    "www-authenticate",
    "location",
    "x-powered-by",
    "server",
    "content-type",
    "set-cookie",
)

#: 传输层失败的分类。名字会直接出现在返回里，所以必须是模型能据以行动的。
_PHASE_HINT: Final = {
    "INVALID_URL": "URL 本身不合法（缺 scheme 或含非法字符）。先在 url 里写全 https://host/path。",
    "DNS": "域名解析失败。若刚换过实例，旧 node 域名会失效——用平台返回的当前 URL，别复用记忆里的地址。",
    "TLS": "TLS 握手失败。先试 http:// 或加 header 里不带 SNI 的写法；自签证书已在本工具内放行，所以这不是证书问题。",
    "CONNECT": "TCP 连不上（端口关闭或被防火墙丢包）。先确认端口，再确认实例还在跑。",
    "CONNECT_TIMEOUT": "连接超时。目标可能在做慢启动，或该端口被丢包——换端口比加大 timeout 更有用。",
    "READ_TIMEOUT": "连上了但没回数据。服务可能在等更多输入（比如需要先发一行），或卡死。",
    "REDIRECT_LOOP": "重定向成环。关掉 follow_redirects 直接看 Location。",
    "UNKNOWN": "未归类的传输错误，看 detail。",
}


def _root_cause(exc: BaseException) -> BaseException:
    """沿异常链找到最内层原因。

    ``requests`` 会把 ``socket.gaierror`` / ``ssl.SSLError`` 包两三层再抛出来，
    只看最外层的话 DNS 失败和连接被拒长得一模一样。
    """
    seen: set[int] = set()
    cur: BaseException = exc
    while True:
        if id(cur) in seen:
            return cur
        seen.add(id(cur))
        nxt = cur.__cause__ or cur.__context__
        if nxt is None:
            inner = cur.args[0] if cur.args else None
            if isinstance(inner, BaseException):
                nxt = inner
        if nxt is None:
            return cur
        cur = nxt


def _phase_of(exc: BaseException) -> str:
    """把一个异常归类成可行动的 ``phase``。"""
    if isinstance(exc, (MissingSchema, InvalidSchema, InvalidURL)):
        return "INVALID_URL"
    if isinstance(exc, TooManyRedirects):
        return "REDIRECT_LOOP"
    if isinstance(exc, ConnectTimeout):
        return "CONNECT_TIMEOUT"
    if isinstance(exc, ReadTimeout):
        return "READ_TIMEOUT"
    if isinstance(exc, SSLError):
        return "TLS"

    root = _root_cause(exc)
    text = f"{type(root).__name__}: {root}".lower()
    if isinstance(root, SSLError) or "ssl" in text or "certificate" in text:
        return "TLS"
    if isinstance(root, OSError) and getattr(root, "errno", None) in (-2, -3, 11001):
        return "DNS"
    for needle in ("name or service not known", "nodename nor servname",
                   "temporary failure in name resolution", "getaddrinfo",
                   "no address associated"):
        if needle in text:
            return "DNS"
    if isinstance(exc, ReqConnectionError) or "connection refused" in text:
        return "CONNECT"
    if "timed out" in text:
        return "READ_TIMEOUT"
    return "UNKNOWN"


def _clip(body: str, request_id: str = "") -> str:
    """按 flag 优先的规则裁剪响应体。

    截断处必须指向台账。旧文案说的是"用同一请求加 header 或换路径取全文"：
    加个头不会让服务端少回一个字，换路径拿到的是另一个路由 —— 两句话都是
    重发的许可，而全文早在 ``traffic.record`` 里存好了（报告 WEB-4）。
    ``offset=limit`` 正好从被截断处继续，不需要重发请求。
    """
    limit = _FLAG_LIMIT if "FLAG{" in body else _BODY_LIMIT
    if len(body) <= limit:
        return body
    hidden = len(body) - limit
    if request_id:
        return (
            f"{body[:limit]}\n…(+{hidden} chars 未显示；全文已在台账 {request_id}，"
            f'用 traffic_view("{request_id}", offset={limit}) 读回，不要重发这个请求)'
        )
    return f"{body[:limit]}\n…(+{hidden} chars, 用同一请求加 header 或换路径取全文)"


def _format_headers(headers: requests.structures.CaseInsensitiveDict) -> str:
    """挑有信息量的响应头，压成一行。"""
    picked: list[str] = []
    for name in _HEADER_PRIORITY:
        value = headers.get(name)
        if value:
            picked.append(f"{name}={value[:120]}")
    for name, value in headers.items():
        if len(picked) >= 6:
            break
        low = name.lower()
        if low in _HEADER_PRIORITY or low in ("date", "content-length", "cache-control"):
            continue
        picked.append(f"{low}={value[:80]}")
    return " | ".join(picked)


def _status_hint(status: int, body: str, request_id: str = "") -> str:
    """按状态码给出下一步动作。

    这段是本工具最有价值的部分之一：它把"读错误消息"这个人类习惯固化了。
    009 的转机正是 ``{"error":"code_b64 required"}`` —— 服务端直接告诉了你
    参数名。

    但"下一步"不能一律写成"再发一条"。404 原来说"换路径"、空 200 原来说
    "试 POST + 空 JSON"，两句都是凭空生成的下一步：台账里可能已经记着这一族
    全部已知路径和已试过的方法（报告 WEB-4）。所以这两个分支先让人读台账，
    再决定要不要换——先查已有证据，再产生新请求。
    """
    if status in (400, 422):
        return ("这是 schema 类报错：body 里的字段名就是接口要的参数，"
                "照它补全再发一次，不要换路径。")
    if status in (401, 403):
        return "鉴权被拒：先走注册/登录拿会话，别继续盲试参数。"
    if status == 404:
        where = f'traffic_view("{request_id}")' if request_id else "traffic_list()"
        return (f"路由不存在：先查台账（{where}，以及 traffic_list(url_contains=…)"
                "看这一族已出现过哪些路径）——在同一路径上换参数只会重复 404，"
                "要换就换成台账里出现过的路径。")
    if status == 405:
        return "方法不对：看响应头 Allow，它通常直接列出可用方法。"
    if status == 429:
        return "被限流：停手，换思路；继续发只会更慢。"
    if status >= 500:
        return "服务端异常：body 里可能有 stack 或文件名——这是源码泄露，优先读它。"
    if status == 200 and len(body.strip()) == 0:
        return ("200 但空 body：先 traffic_list(url_contains=…) 看这条路径上"
                "哪个 method 真给过内容，再从台账读回来；台账也没有才试 POST + 空 JSON。")
    return ""


async def http_probe(
    method: str = "GET",
    url: str = "",
    headers_json: str = "",
    body: str = "",
    timeout_s: float = 20.0,
    follow_redirects: bool = False,
    session: str = "auto",
    cookies: str = "",
) -> str:
    """发一个 HTTP 请求并返回结构化结果（默认带按 host 隔离的会话）。

    比 `curl` 好在三件事：① 传输失败会给出 phase（DNS/TLS/CONNECT/超时），
    不会和 4xx/5xx 混成同一个 `000`；② 响应体自动裁剪，不会把整页 HTML
    灌进上下文；③ 每个状态码都附带下一步动作。

    Args:
        method: HTTP 方法，GET / POST / PUT / PATCH / DELETE / OPTIONS / HEAD。
            **发现新入口靠换方法**：同一个路径换 POST/OPTIONS 经常能撞出
            未文档化的端点（009 的入口就是这么找到的）。
        url: 完整 URL，必须带 scheme（https://host/path）。
        headers_json: 额外请求头，**JSON 字符串**，如
            `{"Content-Type": "application/json"}`。用字符串而不是 dict，
            是因为 SDK 的 strict schema 不允许自由形状的 object
            （`additionalProperties` 会被直接拒绝，注册期就炸）。
        body: 原始请求体字符串。JSON 请自己 json.dumps 后用字符串传入。
        timeout_s: 超时秒数，默认 20。
        follow_redirects: 是否跟随 3xx，默认否（3xx 本身是信息）。
        session: 会话选择。默认 `auto` = 按 scheme+host+port 自动复用
            `requests.Session`：响应的 Set-Cookie 自动保留，下次同 host
            请求自动带上——登录/注册成功后直接打下一个路径，**不要**
            自己抄 cookie。传任意名字（如 `login`）得到跨 host 共享的
            具名会话（双账号越权用 `alice` / `bob` 两个）；传 `off`
            则完全不进会话，每次都是干净请求。
        cookies: 额外 cookie，只作用于**本次**请求：JSON 对象
            `{"sid": "abc"}` 或 `sid=abc; theme=dark`。不写回会话。

    Returns:
        单行摘要 + 关键响应头 + 截断后的 body；失败时给出 phase 与下一步提示。
    """
    method = (method or "GET").strip().upper()
    url = (url or "").strip()
    if not url:
        return "[http_probe] 缺少 url。格式：https://host/path"

    try:
        headers = json.loads(headers_json) if headers_json.strip() else {}
    except json.JSONDecodeError as exc:
        return f"[http_probe] headers_json 不是合法 JSON：{exc}。示例：{{\"Content-Type\": \"application/json\"}}"
    if not isinstance(headers, dict):
        return "[http_probe] headers_json 必须是 JSON 对象（花括号），不能是数组或字符串。"

    try:
        jar_in = _parse_cookies(cookies)
    except (ValueError, json.JSONDecodeError) as exc:
        return (
            f"[http_probe] cookies 解析失败：{exc}。"
            '写法："sid=abc; theme=dark" 或 {"sid": "abc"}'
        )
    key = _session_key(session, url)

    # Reserve the traffic id *before* sending: a refused connection also gets a
    # record, which is what stops the same dead end from being retried.
    request_id = traffic.ledger().next_id()
    started = time.time()
    sess = _get_session(key) if key is not None else None
    payload = body.encode("utf-8") if isinstance(body, str) and body else None
    try:
        if sess is None:
            resp = requests.request(
                method,
                url,
                headers=headers or {},
                cookies=jar_in or None,
                data=payload,
                timeout=timeout_s,
                allow_redirects=follow_redirects,
                verify=False,
            )
        else:
            # 走 Session 才能让 Set-Cookie 落进 jar、让下一次调用自动带上。
            # prepare_request 会把 jar 里的 cookie 并进来，所以台账里记的
            # 是**真正发出去的**头（含 Cookie），排查时不需再猜。
            prepared = sess.prepare_request(
                requests.Request(
                    method,
                    url,
                    headers=headers or {},
                    cookies=jar_in or None,
                    data=payload,
                )
            )
            resp = sess.send(
                prepared,
                timeout=timeout_s,
                allow_redirects=follow_redirects,
                verify=False,
            )
            headers = dict(prepared.headers)
    except Exception as exc:  # noqa: BLE001 — 这个工具必须免疫一切异常
        phase = _phase_of(exc)
        root = _root_cause(exc)
        elapsed = time.time() - started
        hint = _PHASE_HINT.get(phase, _PHASE_HINT["UNKNOWN"])
        traffic.record(
            request_id=request_id,
            method=method,
            url=url,
            req_headers=headers,
            req_body=body if isinstance(body, str) else "",
            phase=phase,
            elapsed=elapsed,
            note=f"{type(root).__name__}: {root}"[:300],
        )
        return (
            f"[NO RESPONSE] {method} {url} | {elapsed:.2f}s | phase={phase} | id={request_id}\n"
            f"detail: {type(root).__name__}: {root}"[:400] + "\n"
            f"hint: {hint}\n"
            "next: 这是**请求没到达服务器**，不是服务器拒绝了它。"
            "先修 URL/网络，再谈状态码。"
        )

    elapsed = time.time() - started
    raw = resp.content or b""
    text = raw.decode(resp.encoding or "utf-8", errors="replace")
    size = len(raw)
    ctype = resp.headers.get("content-type", "?")

    # The full body is kept in the ledger even when the text below is clipped,
    # so `traffic_view` can re-read it without re-sending the request.
    traffic.record(
        request_id=request_id,
        method=method,
        url=url,
        req_headers=headers,
        req_body=body if isinstance(body, str) else "",
        status=resp.status_code,
        resp_headers=dict(resp.headers),
        resp_body=text,
        size=size,
        elapsed=elapsed,
    )

    head = (
        f"[HTTP {resp.status_code}] {method} {url} | {elapsed:.2f}s | "
        f"{size}B | {ctype} | id={request_id}"
    )
    lines = [head]
    hdrs = _format_headers(resp.headers)
    if hdrs:
        lines.append(f"hdr: {hdrs}")
    jar_line = _jar_summary(sess, url) if sess is not None else ""
    if jar_line:
        lines.append(jar_line)
    if method != "HEAD" and text:
        lines.append(f"body: {_clip(text, request_id)}")
    hint = _status_hint(resp.status_code, text, request_id)
    set_cookie = bool(resp.headers.get("set-cookie"))
    if sess is not None and 300 <= resp.status_code < 400 and set_cookie:
        loc = resp.headers.get("location", "")
        where = f"，下一步直接打 {loc}" if loc else ""
        hint = (f"{hint} 会话：Set-Cookie 已进 jar{where}；别重发同一个请求。").strip()
    elif sess is None and set_cookie:
        hint = (
            f"{hint} 本次无会话（session=off），Set-Cookie 不会保留；"
            "要登录态就去掉 session=off。"
        ).strip()
    if hint:
        lines.append(f"next: {hint}")
    return "\n".join(lines)


TOOLS: Final = (http_probe,)


def register(register_fn=None) -> list[str]:
    """把 ``http_probe`` 注册进 strix 的扫描 agent。

    走官方扩展点 ``strix.agents.factory.register_agent_tools``，vendor 保持原样。
    同进程跑第二题时工具名已存在，重复注册会让 SDK 抛 ValueError，所以先查。

    Args:
        register_fn: 注入点，默认取 ``factory.register_agent_tools``。

    Returns:
        已注册的工具名列表（本次新注册的）。
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

    wrapped = [function_tool(timeout=90)(fn) for fn in TOOLS]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]