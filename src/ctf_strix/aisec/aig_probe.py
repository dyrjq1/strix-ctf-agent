"""探测目标上运行的 AI 组件与版本，并映射到已知 CVE。

模块边界
--------
本模块只做「探测 + 匹配」，**不发起任何写操作、不执行利用**。
所有请求都是 GET，且受 :class:`UrlGuard` 约束。

与上游 A.I.G（腾讯朱雀 AI-Infra-Guard）的关系
---------------------------------------------
规则数据来自上游 ``data/``，但平台本体不安装：它需要 docker compose +
4 GB 内存 + Web UI，在「每题一个短命容器」里起不来。这里只取规则，自带求值器。

三条从实战里换来的硬规则
------------------------
1. **无 matcher 的块不产生结果**。与 nuclei 一致：只发请求、不写匹配条件的块
   仅作辅助，不能按「返回 2xx 即命中」。早期版本违反这条，一个 Ollama 靶机上
   同时报出 11 个组件。
2. **版本块不是命中依据**。``kind=ver`` 只负责抽版本，必须等同组件的 ``kind=fp``
   命中后才采信。否则只探到版本号就报出一个组件，幽灵组件满天飞。
3. **目标必须过 SSRF 闸门**。这个工具是给 agent 用的，agent 会把「用户可控的
   URL」喂进来——这是 SSRF 的教科书入口，也是 AI 安全题里最常见的考点。
   早期版本直接 ``urlopen(target)``，等于把云元数据 ``169.254.169.254`` 和内网
   整个交给靶机诱导。
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from ctf_strix.aisec.verrule import evaluate

# ---------------------------------------------------------------- 数据目录

_HERE: Final = Path(__file__).resolve().parent


def data_dir() -> Path | None:
    """定位规则目录。

    每次都重新读 ``CTF_AISEC_DATA``，不在导入期固化：评测脚本是在进程启动
    **之后**才注入这个变量的（它要先把题目的服务端点解析出来），
    导入期缓存会让整条 AI 安全工具链静默失效——工具能注册，但一调用就报
    「规则库缺失」。这个坑是靠端到端验证抓到的，单测因为直接替换了
    ``_RULES`` 反而看不到。

    优先级：环境变量 → 运行期挂载点 → 仓库内的 data/。前者便于正赛把规则
    单独挂进容器，后者便于本机开发。

    Returns:
        存在的规则目录；都不存在时返回 ``None``。
    """
    cands = (
        Path(os.environ.get("CTF_AISEC_DATA") or "/var/ctf/aisec"),
        _HERE / "data",
    )
    for p in cands:
        if (p / "fingerprints.json").is_file():
            return p
    return None

_UA: Final = "Mozilla/5.0 (compatible; aig-lite/0.2)"
#: 单次请求超时。靶机通常同网段，8 秒足够；拖长的代价是挤占整题时间预算。
_TIMEOUT: Final = 8.0
#: 单次响应最多读 200 KB。防御靶机返回超大响应把内存和上下文一起撑爆。
_MAX_BODY: Final = 200_000
#: 指纹阶段总耗时上限。163 条规则去重后十几个路径，正常 2-5 秒完成；
#: 超过 45 秒说明目标在故意慢速响应（tarpit），此时应该放弃而不是拖死 agent。
_FP_DEADLINE: Final = 45.0
#: 并发探测数。靶机多为单进程 HTTP 服务，4 路并发既提速又不会把对方打挂。
_WORKERS: Final = 4

_CONF_ORDER: Final[dict[str, int]] = {"high": 0, "medium": 1, "low": 2}
_SEV_ORDER: Final[dict[str, int]] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


# ---------------------------------------------------------------- SSRF 闸门


class BlockedTarget(ValueError):
    """目标地址被 SSRF 策略拒绝。"""


#: 永远不允许访问的网段。宁可误伤（某些靶机恰好在这段里），
#: 也不允许 agent 被诱导去打云元数据或宿主机。
_DENY_NETS: Final[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",      # CGNAT，云厂商常用
        "127.0.0.0/8",
        "169.254.0.0/16",     # 链路本地：AWS/GCP/Azure 元数据 169.254.169.254
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)

#: 元数据服务的显式黑名单。上面的网段已覆盖，这里再做一次字符串级拦截，
#: 防住「解析前就拦掉」的短路场景（也便于日志里说清原因）。
_METADATA_HOSTS: Final[frozenset[str]] = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.azure.com",
        "instance-data",
        "169.254.169.254",
        "fd00:ec2::254",
    }
)


@dataclass
class UrlGuard:
    """目标 URL 的白名单闸门。

    默认策略是**拒绝一切私网**。CTF 里靶机就是私网地址，所以调用方必须显式
    用 ``allow_hosts`` 放行——放行粒度是「主机:端口」，不是整段，
    避免 ``allow 10.0.0.0/8`` 这种等于没拦的写法。

    Attributes:
        allow_hosts: 允许的 ``host:port`` 集合，取自题面声明的服务端点。

    Example:
        >>> g = UrlGuard(allow_hosts={"10.0.0.5:11434"})
        >>> g.check("http://10.0.0.5:11434/api/tags")
        'http://10.0.0.5:11434/api/tags'
        >>> g.check("http://169.254.169.254/latest/meta-data")
        Traceback (most recent call last):
        ...
        ctf_strix.aisec.aig_probe.BlockedTarget: ...
    """

    allow_hosts: set[str] = field(default_factory=set)

    @classmethod
    def from_env(cls) -> UrlGuard:
        """从 ``CTF_AISEC_ALLOW`` 读取放行清单（逗号分隔的 ``host:port``）。

        变量由本进程的入口在注册工具后写入（``tools.allow_targets``，输入是
        题面声明的端点）。它不经过工具参数，模型无法把自己想打的地址塞进来。
        变量缺失时清单为空，闸门退化为「只允许公网」。
        """
        raw = os.environ.get("CTF_AISEC_ALLOW", "")
        hosts = {h.strip() for h in raw.split(",") if h.strip()}
        return cls(allow_hosts=hosts)

    @staticmethod
    def _is_denied(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # 解析不出来就当作危险
        # IPv4-mapped IPv6（::ffff:10.0.0.1）必须按内层地址判定，
        # 否则 ::ffff:169.254.169.254 可以绕过所有网段检查。
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return any(addr in net for net in _DENY_NETS)

    def check(self, url: str) -> str:
        """校验 URL 是否允许访问。

        判定顺序（前两条是硬拒绝，后面才是白名单）::

            1. scheme 必须是 http/https
            2. 主机名是云元数据服务 → 拒
            3. 命中白名单 host:port → 放行（此时信任调用方，私网也允许）
            4. 未命中白名单 → 解析后任一地址落在禁网段就拒
            5. 白名单为空 → 只允许公网地址（特殊用途段一并拒）

        第 3 步必须排在网段检查**前面**：CTF 靶机本身就是私网地址，
        如果先检查网段，白名单里合法的 ``10.0.0.5:11434`` 也会被拦，
        工具在真实场景里就完全不可用了。早期版本栽在这里。

        Args:
            url: 待校验的绝对 URL。

        Returns:
            规范化后的 URL（补全 scheme、去掉 fragment）。

        Raises:
            BlockedTarget: 命中任一条拒绝规则。
        """
        if not url or not str(url).strip():
            raise BlockedTarget("空 URL")
        u = str(url).strip()
        if "://" not in u:
            u = "http://" + u
        p = urllib.parse.urlsplit(u)
        if p.scheme not in ("http", "https"):
            raise BlockedTarget(f"仅允许 http/https，收到 {p.scheme!r}")
        host = (p.hostname or "").lower()
        if not host:
            raise BlockedTarget("URL 缺少主机名")
        port = p.port or (443 if p.scheme == "https" else 80)
        # 元数据服务是硬拒绝，不进任何白名单讨论
        if host in _METADATA_HOSTS or host.rstrip(".") in _METADATA_HOSTS:
            raise BlockedTarget(f"{host} 是云元数据服务，禁止访问")

        key = f"{host}:{port}"
        if key in self.allow_hosts:
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))

        infos = _resolve(host, port)
        if not infos:
            raise BlockedTarget(f"{host} 无法解析")
        # 全部地址都必须合法：解析出多个 A 记录时，只要有一个落在禁网段就拒绝，
        # 防止「第一次解析给公网、第二次给内网」的 DNS rebinding。
        for ip in infos:
            if self._is_denied(ip):
                raise BlockedTarget(f"{host} 解析到受限地址 {ip}（私网/元数据网段）")
        if self.allow_hosts:
            raise BlockedTarget(
                f"{key} 不在本题放行清单内（{sorted(self.allow_hosts)}）"
            )
        # 白名单之外只允许公网地址。_is_denied 覆盖主要私网段，is_global 再兜住
        # 其余特殊用途段（TEST-NET、192.88.99.0/24 等）——那些段不在私网名单里，
        # 少了这道检查就按公网放行了。循环无条件执行：以前它挂在已经死掉的
        # allow_private 下，清单为空时整段跳过。
        for ip in infos:
            if not ipaddress.ip_address(ip).is_global:
                raise BlockedTarget(f"{host} 解析到非公网地址 {ip}，未显式放行")
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def _resolve(host: str, port: int) -> list[str]:
    """把主机名解析成 IP 列表（不做 DNS 之外的任何事）。

    Args:
        host: 主机名或 IP 字面量。
        port: 端口，仅用于 ``getaddrinfo`` 的参数完整。

    Returns:
        去重后的 IP 字符串列表；解析失败返回空列表。
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    out: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in out:
            out.append(ip)
    return out


# ---------------------------------------------------------------- HTTP 探测

#: 禁用的 opener：显式不给重定向能力。
#:
#: ``urlopen`` 默认跟随 30x，靶机只要回一个 ``Location: http://169.254.169.254/``
#: 就能把「已校验的目标」变成「未校验的元数据服务」——这是 SSRF 最常见的绕过。
#: 这里用自定义 handler 把重定向变成「直接返回 3xx」，由调用方决定要不要跟。
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201, PLR0913
        return None


_OPENER: Final = urllib.request.build_opener(_NoRedirect)


@dataclass(frozen=True)
class Probe:
    """一次 HTTP 探测的结果。

    Attributes:
        status: HTTP 状态码；网络失败为 ``None``。
        body: 响应体（最多 ``_MAX_BODY`` 字节，UTF-8 容错解码）。
        headers: 响应头（小写键 → 值）。
        error: 失败原因；成功为 ``None``。
    """

    status: int | None
    body: str
    headers: dict[str, str]
    error: str | None = None


def _get(url: str, guard: UrlGuard, method: str = "GET", timeout: float | None = None) -> Probe:
    """发一次受闸门约束的 HTTP 请求。

    永不抛异常：网络失败、被拦截、超时都折成 ``Probe(error=...)``。
    扫描器要连续探测几十个路径，单个失败不能中断整体。

    Args:
        url: 目标 URL。
        guard: SSRF 闸门。
        method: HTTP 方法，仅允许 GET/HEAD。
        timeout: 覆盖默认超时。

    Returns:
        :class:`Probe`。
    """
    if method.upper() not in ("GET", "HEAD"):
        # 只读约束：这个工具在任何情况下都不该改写靶机状态
        return Probe(None, "", {}, f"method {method} not allowed")
    try:
        safe = guard.check(url)
    except BlockedTarget as e:
        return Probe(None, "", {}, f"blocked: {e}")
    req = urllib.request.Request(safe, method=method.upper())
    req.add_header("User-Agent", _UA)
    req.add_header("Accept", "*/*")
    try:
        with _OPENER.open(req, timeout=timeout or _TIMEOUT) as r:
            raw = r.read(_MAX_BODY)
            return Probe(
                int(r.status),
                raw.decode("utf-8", "replace"),
                {k.lower(): v for k, v in r.headers.items()},
            )
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也要读响应体：很多框架的 404 页带完整指纹
        try:
            raw = e.read(_MAX_BODY)
            body = raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        return Probe(
            int(e.code), body,
            {k.lower(): v for k, v in (e.headers or {}).items()},
        )
    except urllib.error.URLError as e:
        return Probe(None, "", {}, str(getattr(e, "reason", e)))
    except Exception as e:  # noqa: BLE001 — 探测必须免疫一切网络异常
        return Probe(None, "", {}, f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------- 匹配规则


def match_probe(entry: dict[str, Any], probe: Probe) -> bool:
    """按 matchers 判定该探测是否命中。

    matcher 组合规则（对齐 nuclei）：

    - 没有 matcher 的块**不产生结果**（仅作辅助请求）
    - 同一条 matcher 内，``body`` 型的多个 value 是「与」关系
    - 不同 matcher 之间也是「与」关系（全部满足才算命中）
    - ``negative`` 表示该条件需**不**满足

    Args:
        entry: 规则中的探测块（含 ``matchers``）。
        probe: HTTP 探测结果。

    Returns:
        是否命中。
    """
    ms = entry.get("matchers") or []
    if not ms:
        return False  # 关键：无 matcher 不产生结果
    body = probe.body or ""
    for m in ms:
        typ, vals, neg = m.get("type"), m.get("value") or [], bool(m.get("negative"))
        if typ == "body":
            ok = all(v in body for v in vals)
        elif typ == "word":
            ok = any(v in body for v in vals)
        elif typ == "regex":
            ok = any(_safe_search(v, body) for v in vals)
        elif typ == "status":
            ok = probe.status is not None and str(probe.status) in {str(v) for v in vals}
        elif typ == "header":
            joined = "\n".join(f"{k}: {v}" for k, v in (probe.headers or {}).items())
            ok = all(v in joined for v in vals)
        else:
            ok = False
        if neg:
            ok = not ok
        if not ok:
            return False
    return True


#: 正则执行时间上限（毫秒）。超过即放弃该条规则。
#:
#: 只限制输入长度是不够的：``(a+)+$`` 对 8000 个 ``a`` 的字符串照样能跑几百秒，
#: 而 8000 字符的 body 在真实靶机上比比皆是。Python 3.11 起 ``re`` 没有内置
#: 超时参数，只能靠「限制字符串长度 + 信号/线程超时」双保险。
_RE_MAX_INPUT: Final = 8000
_RE_MAX_PATTERN: Final = 500
_RE_TIMEOUT_S: Final = 0.25


def _safe_search(pattern: str, text: str) -> bool:
    """执行正则，带长度上限与**执行超时**。

    规则来自第三方、body 来自靶机，两者都可控，必须双重设限：

    1. 长度上限：掐掉明显的超长输入
    2. 执行超时：即使长度合规，灾难性回溯仍可能跑几百秒

    超时实现用线程而非 ``signal``：本模块会被线程池（并发探测）调用，
    ``signal.alarm`` 只能在主线程用。

    Args:
        pattern: 正则原文。
        text: 待搜索文本。

    Returns:
        是否匹配；正则非法、输入超长未匹配或执行超时均返回 False。
    """
    if len(pattern) > _RE_MAX_PATTERN:
        return False
    if len(text) > _RE_MAX_INPUT:
        text = text[:_RE_MAX_INPUT]
    try:
        compiled = re.compile(pattern, re.I)
    except re.error:
        return False

    result: list[bool] = [False]

    def run() -> None:
        try:
            result[0] = compiled.search(text) is not None
        except Exception:  # noqa: BLE001
            result[0] = False

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(_RE_TIMEOUT_S)
    # 线程没结束说明正则失控。daemon 线程会随进程退出，
    # 这里不等它——等下去就等于把整次扫描挂死在这条规则上。
    return result[0] if not t.is_alive() else False


def _specificity(hit: dict[str, Any], fp_by_name: dict[str, dict[str, Any]]) -> int:
    """评估一条命中规则有多「硬」，用于压制弱规则的误报。

    规则库存在弱规则：例如 text-generation-webui 仅凭页面里有 ``gradio_config``
    就判定命中，而任何 Gradio 应用都含这个串。这里按「最长关键字长度」打分，
    不删规则、只降置信度，最终由 agent 判断。

    Args:
        hit: 命中的组件记录。
        fp_by_name: 组件名 → 规则原文。

    Returns:
        0~3。最长关键字 < 16 字符视为通用词，直接 0 分。
    """
    comp = fp_by_name.get(hit["component"], {})
    words = [
        v
        for p in comp.get("probes", [])
        for m in p.get("matchers", [])
        for v in (m.get("value") or [])
    ]
    if not words:
        return 0
    longest = max(len(w) for w in words)
    return 0 if longest < 16 else min(3, 1 + len(words) // 4)


# ---------------------------------------------------------------- 规则加载


class Rulebook:
    """惰性加载的规则库。

    冷启动只读 ``fingerprints.json``（约 100 KB）；``vuln_index.json``
    （数百 KB）在第一次查 CVE 时才读，避免「只做指纹」的场景白付 IO。

    **不缓存根目录**：``root`` 为 ``None`` 时每次调用都重新问 :func:`data_dir`。
    评测脚本会在进程启动后才注入 ``CTF_AISEC_DATA``，
    早期版本在 ``__init__`` 里把 ``self.root = None`` 固化下来，
    于是工具能注册、一调用却报「规则库缺失」——端到端验证才暴露的问题。

    Attributes:
        _root: 显式指定的根目录；``None`` 表示运行时动态发现。
    """

    def __init__(self, root: Path | None = None) -> None:
        self._root = root
        self._fp: list[dict[str, Any]] | None = None
        self._index: dict[str, list[dict[str, Any]]] | None = None
        self._lock = threading.Lock()

    @property
    def root(self) -> Path | None:
        """规则目录。显式传入优先，否则每次动态发现。"""
        return self._root if self._root is not None else data_dir()

    @property
    def available(self) -> bool:
        return self.root is not None

    def fingerprints(self) -> list[dict[str, Any]]:
        """加载指纹规则（线程安全，只读一次）。"""
        if self._fp is None:
            path = (self.root / "fingerprints.json") if self.root else None
            data: list[dict[str, Any]] = []
            if path and path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = []
            self._fp = data
        return self._fp

    def vuln_index(self) -> dict[str, list[dict[str, Any]]]:
        """加载「组件 → CVE 规则」索引（线程安全，只读一次）。"""
        with self._lock:
            if self._index is None:
                path = (self.root / "vuln_index.json") if self.root else None
                data: dict[str, list[dict[str, Any]]] = {}
                if path and path.is_file():
                    try:
                        data = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        data = {}
                self._index = data
            return self._index


_RULES: Final = Rulebook()


# ---------------------------------------------------------------- 主流程


def fingerprint(base: str, guard: UrlGuard | None = None, timeout: float | None = None) -> list[dict[str, Any]]:
    """探测 target 上运行的 AI 组件与版本。

    规则语义（与上游 A.I.G 一致，务必区分）::

        kind=fp   ：命中判定依据，必须匹配 matcher
        kind=ver  ：只负责抽取版本号，本身不算命中

    版本块的 regex 只在「同组件的 fp 块已命中」时才采信。

    性能：同一路径只请求一次（``probes`` 缓存）。163 条规则涉及的路径
    去重后通常只有十几个，这是能在有限预算内跑完的关键。并发 + 总时限
    双重保护，避免慢速靶机把 agent 拖死。

    Args:
        base: 目标根地址，如 ``http://10.0.0.5:11434``。
        guard: SSRF 闸门；``None`` 时从环境变量构造。
        timeout: 单请求超时覆盖值。

    Returns:
        组件列表，每条含 ``component / vendor / path / version /
        evidence / confidence``。按 (置信度, 组件名) 排序。
    """
    if not _RULES.available:
        raise RuntimeError(
            "规则库缺失：需要 fingerprints.json。请先运行 "
            "`python -m ctf_strix.aisec.build_kb <A.I.G 源码/data> <输出目录>`。"
        )
    g = guard or UrlGuard.from_env()
    base = (base or "").strip().rstrip("/")
    if not base:
        raise BlockedTarget("目标为空")
    if "://" not in base:
        base = "http://" + base
    g.check(base)

    fps = _RULES.fingerprints()
    fp_by_name = {f["component"]: f for f in fps}
    started = time.monotonic()
    cache: dict[tuple[str, str], Probe] = {}
    lock = threading.Lock()

    def fetch(path: str, method: str = "GET") -> Probe:
        key = (path, method.upper())
        with lock:
            if key in cache:
                return cache[key]
        if time.monotonic() - started > _FP_DEADLINE:
            return Probe(None, "", {}, "fingerprint deadline exceeded")
        pr = _get(base + path, g, method, timeout)
        with lock:
            cache[key] = pr
        return pr

    # 第一轮：为每条规则找命中依据。按组件并行，同路径由 cache 去重。
    def first_pass(comp: dict[str, Any]) -> dict[str, Any] | None:
        matched: dict[str, Any] | None = None
        for p in comp["probes"]:
            if p.get("kind", "fp") != "fp":
                continue
            pr = fetch(p["path"], p.get("method", "GET"))
            if pr.status is None or not match_probe(p, pr):
                continue
            if matched is None:
                matched = {
                    "component": comp["component"],
                    "vendor": comp.get("vendor"),
                    "path": p["path"],
                    # evidence 只留前 160 字符：够 agent 判断，又不撑爆上下文
                    "evidence": (pr.body or "")[:160],
                    "version": None,
                }
        return matched

    hits: list[dict[str, Any]] = []
    if fps:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            for res in pool.map(first_pass, fps):
                if res:
                    hits.append(res)

    # 第二轮：命中后再取版本（body 或响应头，取决于规则）
    for h in hits:
        comp = fp_by_name.get(h["component"], {})
        for p in comp.get("probes", []):
            if p.get("kind") != "ver" or not p.get("version_regex"):
                continue
            method = p.get("method", "GET")
            pr = fetch(p["path"], method)
            if pr.status is None:
                continue
            if p.get("version_part") == "header":
                named = p.get("version_header")
                src = (pr.headers.get(str(named).lower(), "") if named else "") or "\n".join(
                    f"{k}: {v}" for k, v in pr.headers.items()
                )
            else:
                src = pr.body or ""
            try:
                m = re.search(p["version_regex"], src, re.I)
            except re.error:
                continue
            if m:
                try:
                    h["version"] = m.group(p.get("version_group", 1))
                except (IndexError, re.error):
                    # 规则写的 group 超出实际分组数，退化为整个匹配串
                    h["version"] = m.group(0)
                break

    for h in hits:
        if h["version"]:
            h["confidence"] = "high"
        elif _specificity(h, fp_by_name) >= 2:
            h["confidence"] = "medium"
        else:
            h["confidence"] = "low"
    hits.sort(key=lambda x: (_CONF_ORDER.get(x["confidence"], 9), x["component"]))
    return hits


def lookup(component: str, version: str | None, vendor: str | None = None) -> list[dict[str, Any]]:
    """按组件名 + 版本号，返回命中的 CVE 规则（按严重度排序）。

    组件名匹配降级策略（三级，命中即停）：

    1. 精确匹配 —— ``ollama`` → ``ollama``
    2. 双向子串匹配 —— ``comfyui-custom-scripts`` 能匹配到 ``comfyui`` 的规则
    3. 用 vendor 兜底 —— 插件名对不上时按厂商名找

    没有版本号时**不要**调用本函数：所有版本类规则都无法判定，结果偏向漏报。

    Args:
        component: 组件名。
        version: 版本号；为 ``None`` 时只返回「无版本约束」类规则
            （未授权访问、默认口令等，往往最好打）。
        vendor: 厂商名，用于兜底匹配。

    Returns:
        命中的规则列表。
    """
    index = _RULES.vuln_index()
    if not index:
        return []
    key = (component or "").lower().replace(" ", "")
    cands = [c for c in index if c.lower().replace(" ", "") == key]
    if not cands and key:
        cands = [
            c for c in index
            if key in c.lower().replace(" ", "") or c.lower().replace(" ", "") in key
        ]
    if not cands and vendor:
        v = vendor.lower().replace(" ", "")
        cands = [
            c for c in index
            if v in c.lower().replace(" ", "") or c.lower().replace(" ", "") in v
        ]
    out: list[dict[str, Any]] = []
    for c in cands:
        for r in index[c]:
            # 空 rule 表示无版本约束，evaluate 直接 True，
            # 这类多是「未授权访问」「默认口令」，不受 version 是否为 None 影响
            if evaluate(r.get("rule"), version, {}):
                out.append({**r, "component": c})
    out.sort(key=lambda x: (_SEV_ORDER.get(x.get("severity", ""), 9), x.get("cve") or ""))
    return out


def scan(base: str, guard: UrlGuard | None = None, top_k: int = 5) -> list[dict[str, Any]]:
    """一步到位：指纹 + CVE 匹配，供 agent 进入一道 AI 安全题时单次调用。

    Args:
        base: 目标根地址。
        guard: SSRF 闸门。
        top_k: 每个组件返回的 CVE 条数上限。

    Returns:
        报告列表，按 (置信度, CVE 数量降序) 排序。
    """
    report: list[dict[str, Any]] = []
    for f in fingerprint(base, guard):
        v = f.get("version")
        vulns = lookup(f["component"], v, f.get("vendor"))
        report.append({**f, "vuln_count": len(vulns), "top_vulns": vulns[:top_k]})
    report.sort(key=lambda r: (_CONF_ORDER.get(r.get("confidence"), 9), -r["vuln_count"]))
    return report
