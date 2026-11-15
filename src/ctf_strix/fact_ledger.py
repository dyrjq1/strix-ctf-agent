"""收工台账（fact ledger）：把「工具已经给出、本轮却没试」的路由摆到收工门口。

## 为什么做这一层

历史 run 的 item 流离线复盘（`scripts/experiments/ledger_premise_audit*.py`，
零 token，可复算）：

- `route_map` 的结构化候选行是唯一可信的「目标自己说出过哪些路由」来源。
  11-07 之后的 28 场失败 run 里，未被请求的候选 p50=3 / p90=8，**13 场 >3 条**；
  其中 22/28 已经调过 `method_sweep`——工具给了答案，run 只用了一部分。
- 精度：114 条未试候选里 72 条（63%）**同族已有非 404 响应**，不是死路；
  同族全 4xx 的 21 条必须在渲染时丢掉，否则台账就是把人往沟里带。
- 触达：失败 run 88% 会调 `finish_scan`，当前时代 53% 被拒收——收工拒收文本
  是主通道；耗轮收场的 12% 是 v1 已知盲区（见 docs/32 §11）。

外部依据：Intentest 的「假设-验证对账」报告 +44pt、轮数 −33~−48%；PentestGPT
`memory.py` 把 Observation/Attempt/Transition 落盘成状态机。我们只取其中两件
最小的东西——**结构化事实**与**收工前对账**——并按 §7.7 的教训不碰 system
prompt、不按龄裁剪：台账只追加在拒收文本里，前缀缓存原样保留。

## 确定性边界

条目全部来自工具输出，**不读模型自由文本**：

| 条目 | 来源 |
|---|---|
| 候选路由 | `route_map` 的 `N. /path` 与 `  ? /path` 行 |
| 已请求 | 每次调用的 **arguments** 里出现的 URL / 引号内绝对路径（只做减法） |
| 同族活性 | `http_probe` / `method_sweep` / `path_variants` 的状态行 |
| 已确认事实 | 同上，2xx 行，按 (method, path) 去重 |

渲染上限 15 行；没有任何可指名条目时返回空串（零注入、零成本）。
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from agents.tool import FunctionTool

logger = logging.getLogger(__name__)

#: 渲染预算。标题 1 行 + 已确认段（标题 1 + 4 行）+ 未试段（标题 1 + 8 行）= 15。
_MAX_CONFIRMED = 4
_MAX_ENTRIES = 8

_METHODS = r"(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)"

_URL_RE = re.compile(r"https?://[^\s\"'`\\<>]+")
_QUOTED_RE = re.compile(r"[\"']([^\"'\n]{1,2000})[\"']")
_ROUTE_HEAD = re.compile(r"^\[route_map\]\s+(https?://[^\s|]+)", re.M)
_CAND_LINE = re.compile(r"^\s*(?:\d+\.\s+|\?\s+)(/[A-Za-z0-9_][A-Za-z0-9_\-./]*)", re.M)

#: 三种工具各自的响应行形状。逐行匹配，不做全文乱抓。
_PROBE_LINE = re.compile(
    r"^\[HTTP (?P<status>[1-5]\d{2})\]\s+(?P<method>" + _METHODS + r")\s+"
    r"(?P<target>https?://\S+)\s*\|\s*[\d.]+s\s*\|\s*(?P<size>\d+)B\s*\|"
    r"\s*(?P<ctype>[^|]+?)\s*(?:\||$)"
)
_SWEEP_LINE = re.compile(
    r"^\S{1,12}\s+(?P<status>[1-5]\d{2})\s+(?P<method>" + _METHODS + r")\s+"
    r"(?P<target>https?://\S+)(?:\s*\|\s*(?P<size>\d+)B)?"
)
_VARIANT_LINE = re.compile(
    r"^(?P<status>[1-5]\d{2})\s+(?P<method>" + _METHODS + r")\s+"
    r"\[[^\]]*\]\s+(?P<target>/\S+)(?:\s*\|\s*(?P<size>\d+)B)?"
)

_STATIC = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webmanifest)$", re.I
)
#: 前端框架的构建产物路径，route_map 会把它们和真实路由混在一列。
_FRAMEWORK = re.compile(r"^/_(?:next|nuxt|tree|app|document|layout)", re.I)
_NOISE_PATHS = frozenset({"/a", "/b", "/a/b", "/a/i"})

_HINT_TOOLS = frozenset({"route_map", "http_probe", "method_sweep", "path_variants"})


def enabled() -> bool:
    """台账是 **opt-in 实验**：``CTF_FACT_LEDGER=1`` 才安装。

    2026-11-15 的零 token 预检（`scripts/experiments/ledger_replay.py` /
    `ledger_source_width.py` / `ledger_digest_reach.py`）证明：在历史总体上，
    收工拒绝时只有 **7%** 能指名条目（放宽来源后 11%），改成每轮注入也只有
    **13%** 的失败 run 会说话——低于预注册（docs/32 §11.5）的 80% 门槛。
    机制按预注册作废，代码保留为开关，默认关。
    """
    raw = os.environ.get("CTF_FACT_LEDGER", "0").strip().lower()
    return raw in {"1", "true", "on", "yes"}


def _norm(target: str) -> str:
    """URL 或路径 → 规范化路径（去 query/fragment/尾斜杠）。

    ``urlparse`` 对畸形 IPv6 字面量（如 ``http://[::1``）会抛 ``ValueError``；
    历史 run 里真出现过，所以这里退回字符串切分，绝不让一条怪 URL 丢掉整次观测。
    """
    path = target
    if target.startswith(("http://", "https://")):
        try:
            path = urlparse(target).path or "/"
        except ValueError:
            rest = target.split("://", 1)[1]
            slash = rest.find("/")
            path = rest[slash:] if slash >= 0 else "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    stripped = path.rstrip("/")
    return stripped or "/"


def _host(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return ""
    try:
        parsed = urlparse(target)
        return f"{parsed.scheme}://{parsed.netloc}"
    except ValueError:
        return ""


def _family(path: str) -> str:
    """前两段路径为族：`/api/tasks/create` 与 `/api/tasks/list` 同族。"""
    segs = [s for s in path.split("/") if s]
    return "/" + "/".join(segs[:2])


def _acceptable(path: str) -> bool:
    """能进台账的路由形状。"""
    if not path or path == "/" or path in _NOISE_PATHS:
        return False
    if _FRAMEWORK.match(path) or _STATIC.search(path):
        return False
    if any(ch in path for ch in "{}:*<>$"):
        return False
    return path.count("/") >= 2


def _as_text(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception:  # noqa: BLE001 - 台账不能因结果形状怪而失败
        return str(result)


def _short_ctype(ctype: str) -> str:
    head = ctype.split(";", 1)[0].strip().lower()
    if "json" in head:
        return "json"
    if "html" in head:
        return "html"
    return head[:12]


class FactLedger:
    """本轮 run 内的事实/候选台账。纯内存、无 IO、无模型调用。"""

    def __init__(self) -> None:
        self.hosts: set[str] = set()
        self.candidates: dict[str, None] = {}
        self.requested: set[str] = set()
        #: (method, path) -> (status, size, ctype)
        self.probes: dict[tuple[str, str], tuple[int, int, str]] = {}
        self.calls = 0
        self.renders = 0
        self.rendered_lines = 0

    # -- 观测 ---------------------------------------------------------------

    def observe(self, tool_name: str, args: Any, result: Any = None) -> None:
        """登记一次工具调用。参数与结果都可能是任意形状。"""
        self.calls += 1
        args_text = args if isinstance(args, str) else _as_text(args)
        self._record_requested(args_text)
        if tool_name not in _HINT_TOOLS:
            return
        text = _as_text(result)
        if not text:
            return
        if tool_name == "route_map":
            self._record_route_map(text)
        self._record_probes(text)

    def _record_requested(self, args_text: str) -> None:
        for url in _URL_RE.findall(args_text):
            self.requested.add(_norm(url))
        for blob in _QUOTED_RE.findall(args_text):
            for tok in re.split(r"[\s,;]+", blob):
                if tok.startswith("/") and len(tok) > 1:
                    self.requested.add(_norm(tok))

    def _record_route_map(self, text: str) -> None:
        head = _ROUTE_HEAD.search(text)
        if head:
            self.hosts.add(head.group(1).rstrip("/"))
        for raw in _CAND_LINE.findall(text):
            path = _norm(raw)
            if _acceptable(path):
                self.candidates.setdefault(path, None)

    def _record_probes(self, text: str) -> None:
        for line in text.splitlines():
            match = _PROBE_LINE.match(line)
            size = ctype = ""
            method = target = status = ""
            if match:
                status = match.group("status")
                method = match.group("method")
                target = match.group("target")
                size = match.group("size")
                ctype = match.group("ctype")
            else:
                match = _SWEEP_LINE.match(line) or _VARIANT_LINE.match(line)
                if not match:
                    continue
                status = match.group("status")
                method = match.group("method")
                target = match.group("target")
                size = match.groupdict().get("size") or ""
            host = _host(target)
            if host and self.hosts and host not in self.hosts:
                # 外站响应（SSRF 载荷宿主等）不算本轮目标的事实。
                continue
            path = _norm(target)
            if not path or path == "/":
                continue
            key = (method, path)
            if key not in self.probes:
                self.probes[key] = (
                    int(status),
                    int(size) if str(size).isdigit() else 0,
                    ctype.strip(),
                )

    # -- 渲染 ---------------------------------------------------------------

    def _family_state(self, path: str) -> str:
        fam = _family(path)
        seen_four = False
        for (_method, other), (status, _size, _ctype) in self.probes.items():
            if _family(other) != fam:
                continue
            if status < 400:
                return "alive"
            seen_four = True
        return "dead" if seen_four else "unknown"

    def render(self) -> str:
        """渲染 ≤15 行台账；没有可指名条目时返回空串。"""
        if not self.candidates:
            return ""
        untried = [p for p in self.candidates if p not in self.requested]
        if not untried:
            return ""
        alive: list[str] = []
        unknown: list[str] = []
        for path in untried:
            state = self._family_state(path)
            if state == "alive":
                alive.append(path)
            elif state == "unknown":
                unknown.append(path)
        entries = alive[:_MAX_ENTRIES]
        if len(entries) < _MAX_ENTRIES:
            entries.extend(unknown[: _MAX_ENTRIES - len(entries)])
        if not entries:
            return ""
        confirmed = self._confirmed()[:_MAX_CONFIRMED]
        lines = ["[FACT LEDGER] built from this run's tool output, not from memory."]
        if confirmed:
            lines.append(f"Confirmed responses ({len(confirmed)}):")
            lines.extend(f"  {row}" for row in confirmed)
        reason = "same path family already answers" if alive else "never probed"
        lines.append(
            f"Listed by the tooling but never requested "
            f"({len(alive) + len(unknown)}, showing {len(entries)}; {reason}):"
        )
        lines.extend(f"  {path}" for path in entries)
        text = "\n".join(lines)
        self.renders += 1
        self.rendered_lines += len(lines)
        return text

    def _confirmed(self) -> list[str]:
        rows: list[tuple[int, int, str, str, int, int, str]] = []
        for (method, path), (status, size, ctype) in self.probes.items():
            if not (200 <= status < 300) or not _acceptable(path):
                continue
            is_json = 0 if "json" in ctype.lower() else 1
            rows.append((is_json, len(path), method, path, status, size, ctype))
        rows.sort()
        out: list[str] = []
        for _json, _len, method, path, status, size, ctype in rows:
            tail = f" {_short_ctype(ctype)}" if ctype else ""
            size_text = f" {size}B" if size else ""
            out.append(f"{method} {path} {status}{tail}{size_text}")
        return out

    def stats(self) -> dict[str, int]:
        return {
            "calls": self.calls,
            "candidates": len(self.candidates),
            "requested": len(self.requested),
            "probes": len(self.probes),
            "renders": self.renders,
            "lines": self.rendered_lines,
        }


def install() -> FactLedger | None:
    """包装所有 root 工具的调用入口，装上事实台账。

    与 `enum_guard` 同一手法（替换 ``factory._with_bounded_result``），因此
    必须先执行 ``guard_mount.install_mount_hook()``，否则 ``exec_command``
    这条真正打靶机的路不会被观测到。

    只观测、不拦截、不改返回体；台账正文只在收工拒收时由 ``FinishGuard``
    追加，前缀缓存不受影响。

    Returns:
        台账实例；默认 ``None``（opt-in：``CTF_FACT_LEDGER=1`` 才装）。
    """
    if not enabled():
        return None
    from strix.agents import factory

    ledger = FactLedger()
    original = factory._with_bounded_result

    def patched(tool: "FunctionTool") -> "FunctionTool":
        tool = original(tool)
        if getattr(tool, "_ctf_fact_observed", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            result = await inner(ctx, raw_input)
            try:
                ledger.observe(getattr(tool, "name", ""), raw_input, result)
            except Exception:  # noqa: BLE001 - 观测失败不能拖垮工具调用
                logger.warning("ctf fact ledger observe failed", exc_info=True)
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_fact_observed = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return ledger