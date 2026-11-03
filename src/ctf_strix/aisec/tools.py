"""把 A.I.G 探测能力包装成 strix 可以直接注册的工具函数。

为什么要有这层包装，而不是直接把 ``aig_probe`` 暴露给 agent
------------------------------------------------------------
1. **返回格式**：探测返回结构化 dict，agent 需要的是紧凑文本。
   实测 token 消耗的主因不是任务难度，而是工具输出撑爆上下文
   （单题 40 万 token 里有相当比例是重复的结构化 dump），
   所以这里压成人类可读短文本，并硬性限制行数。
2. **引导下一步**：agent 常拿到结果不知道干什么，直接在返回值末尾给行动建议，
   比在 system prompt 里多写一条规则更稳（system prompt 会被长对话稀释）。
3. **Schema 质量**：strix 用 docstring 生成工具的 JSON Schema，
   Args/Returns 的写法直接决定模型会不会正确填参数。

设计约束（来自 CTFY 契约）
--------------------------
- 单次调用即返回，无长连接、无常驻服务
- 只看目标 URL，不依赖外网
- 无副作用：只发 GET 探测请求，不改靶机状态

关于「只发 GET」
----------------
这不是保守，是硬约束。这个工具的目标地址来自**靶机诱导**（题目里的
"请你扫描一下这个地址"），一旦允许 POST 就等于给攻击者一个从我们容器
发起的写请求通道。闸门在 :mod:`ctf_strix.aisec.aig_probe` 里，这里只做包装。
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Final

from ctf_strix.aisec import aig_probe
from ctf_strix.aisec.aig_probe import BlockedTarget, UrlGuard
from ctf_strix.aisec import web_cve

#: 常见 AI 组件端口。探测失败时直接给出来，避免 agent 反复猜端口浪费轮次。
COMMON_PORTS: Final[tuple[int, ...]] = (
    11434,  # Ollama
    7860,   # Gradio / Stable Diffusion WebUI
    8188,   # ComfyUI
    5001,   # Dify (api)
    3000,   # Dify (web) / Open WebUI
    8000,   # 通用 FastAPI / LangServe
    8080,   # Open WebUI 备选 / LiteLLM
    9000,   # Portainer / Langflow 备选
    8501,   # Streamlit
    1234,   # LM Studio
)

#: 单次工具返回的最大行数。超过就截断并提示。
_MAX_LINES: Final = 40


def _guard() -> UrlGuard:
    """从环境变量构造闸门。

    ``CTF_AISEC_ALLOW`` 由评测/正赛脚本在启动 agent 前写入，值是本题
    题面声明的 ``host:port``。agent 在沙箱内改不了这个变量（它是父进程
    环境），因此这是可信的放行来源。

    Returns:
        配置好的 :class:`UrlGuard`。
    """
    return UrlGuard.from_env()


async def _run(fn: Any, *args: Any, timeout: float = 120.0) -> Any:
    """在线程里跑同步探测，并施加墙钟超时。

    为什么要绕这一道：
    strix 的 ``function_tool`` 只对 **async** handler 支持 ``timeout``
    （同步函数传 timeout 会直接抛 ValueError）。而探测本身是阻塞 IO，
    直接放在 async 里会卡住整个 agent 的事件循环——一个慢速靶机就能
    让 agent 在等待中耗尽自己的时间预算。

    Args:
        fn: 同步可调用对象。
        *args: 透传参数。
        timeout: 墙钟上限（秒）；超时抛 :class:`asyncio.TimeoutError`。

    Returns:
        ``fn`` 的返回值。
    """
    return await asyncio.wait_for(asyncio.to_thread(fn, *args), timeout=timeout)


def _precheck(target: str) -> str | None:
    """先做闸门与规则库检查，返回可读的错误串；一切正常返回 ``None``。

    顺序很重要：**先查闸门再查规则库**。反过来的话，越界目标会因为
    「规则库缺失」提前返回，把「被拒绝」这个安全事实掩盖成「环境没配好」——
    agent 会以为换个地址就能用，正好中诱导。测试里抓到过这个顺序问题。

    Args:
        target: 目标地址。

    Returns:
        错误文本，或 ``None``。
    """
    try:
        _guard().check(target)
    except BlockedTarget as e:
        return f"目标被拒绝：{e}\n这是授权范围限制，不要换其它地址重试。"
    if not aig_probe.data_dir():
        return (
            "规则库不可用：缺少 fingerprints.json。"
            "请先执行 python -m ctf_strix.aisec.build_kb <A.I.G 源码/data> <输出目录>。"
        )
    return None


def _trim(lines: list[str]) -> str:
    """限制返回行数，防止单次工具输出吃满上下文。"""
    if len(lines) <= _MAX_LINES:
        return "\n".join(lines)
    return "\n".join([*lines[:_MAX_LINES], f"...（另有 {len(lines) - _MAX_LINES} 行未显示）"])


async def ai_fingerprint(target: str) -> str:
    """探测目标上运行的 AI 组件及其版本（Ollama / Dify / ComfyUI / Langflow 等）。

    用于进入一道 AI 安全题时的第一步侦察：先确认「这是什么组件、什么版本」，
    再决定打哪个 CVE。传统 Web 扫描器认不出这些组件，这个工具补上这层知识。

    只发 GET 探测请求，不改动靶机状态。目标必须在本题授权范围内，
    越界地址会被拒绝（返回 blocked 原因）。

    Args:
        target: 目标根地址，需带 scheme 与端口，例如 http://10.0.0.5:11434

    Returns:
        组件清单（每行一个组件，含版本与置信度），末尾给出下一步建议。
        未命中时返回常见 AI 端口清单。
    """
    if err := _precheck(target):
        return f"[ai_fingerprint] {err}"
    try:
        hits = await _run(aig_probe.fingerprint, target, _guard())
    except asyncio.TimeoutError:
        return f"[ai_fingerprint] {target} 探测超时（目标可能在做慢速响应），放弃本次扫描。"
    except Exception as e:  # noqa: BLE001 — 工具必须免疫一切异常
        return f"[ai_fingerprint] 探测失败：{type(e).__name__}: {e}"

    if not hits:
        ports = " / ".join(str(p) for p in COMMON_PORTS)
        return (
            f"[ai_fingerprint] {target} 未识别到已知 AI 组件。\n"
            f"可尝试其它端口：{ports}\n"
            "也可以先看 HTTP 响应头（Server / X-Powered-By）判断是否自研服务。"
        )
    lines = [f"[ai_fingerprint] {target} 命中 {len(hits)} 个组件："]
    for h in hits:
        ver = h.get("version") or "未知版本"
        lines.append(
            f"- {h['component']} {ver} "
            f"(置信度 {h.get('confidence', '?')}, 依据 {h['path']}, 厂商 {h.get('vendor') or '?'})"
        )
    high = [h for h in hits if h.get("confidence") == "high"]
    if high:
        lines.append(
            "下一步：对 high 置信度组件调用 ai_cve_lookup(component, version) 查已知漏洞。"
        )
    else:
        lines.append(
            "下一步：全部是 medium/low 置信度，说明版本没取到。"
            "先手工读页面 / 响应头确认版本，再查 CVE；否则版本类规则全部无法判定。"
        )
    return _trim(lines)


async def ai_cve_lookup(component: str, version: str = "", top_k: int = 8) -> str:
    """查询指定组件版本上命中的已知 CVE（本地规则库，零外网）。

    Args:
        component: 组件名，如 ollama / dify / gradio / litellm / langflow
        version: 版本号，如 0.1.29。留空则只返回「无版本约束」类规则
            （未授权访问、默认口令这类，往往最好打）。
        top_k: 最多返回条数，默认 8

    Returns:
        按严重度排序的 CVE 列表，含版本约束表达式与规则文件路径
        （可直接读取该文件获取利用细节）。
    """
    if not aig_probe.data_dir():
        return "[ai_cve_lookup] 规则库不可用：缺少 vuln_index.json。"
    try:
        vulns = await _run(aig_probe.lookup, component, version or None, timeout=30)
    except Exception as e:  # noqa: BLE001
        return f"[ai_cve_lookup] 查询失败：{type(e).__name__}: {e}"
    if not vulns:
        return (
            f"[ai_cve_lookup] {component} {version or '(无版本)'} 未命中已知 CVE。\n"
            "可能是新版，或题目为自研 / 逻辑漏洞。建议直接读靶机接口找业务逻辑问题。"
        )
    lines = [f"[ai_cve_lookup] {component} {version or '(无版本约束类)'} 命中 {len(vulns)} 条："]
    for v in vulns[: max(1, int(top_k))]:
        # 空规则 = 无版本约束，多是未授权访问一类，单独标注便于优先尝试
        rule = v.get("rule") or "无版本约束（逻辑漏洞）"
        lines.append(f"- {v.get('cve') or 'N/A'} [{v.get('severity') or '?'}] {(v.get('summary') or '')[:80]}")
        lines.append(f"  约束: {rule} | 规则文件: {v.get('file')}")
    if len(vulns) > top_k:
        lines.append(f"（另有 {len(vulns) - top_k} 条未显示，可提高 top_k）")
    lines.append(
        "下一步：挑最贴合题目意图的一条，读规则文件里的 details/references 拿利用步骤，"
        "再用 shell 工具发请求验证。注意：CVE 命中只是「候选」，必须实际验证才能确认。"
    )
    return _trim(lines)


async def ai_quick_scan(target: str) -> str:
    """一步完成指纹 + CVE 匹配，进入 AI 安全题时的第一手侦察。

    Args:
        target: 目标根地址，例如 http://10.0.0.5:11434
    """
    if err := _precheck(target):
        return f"[ai_quick_scan] {err}"
    try:
        report = await _run(aig_probe.scan, target, _guard())
    except asyncio.TimeoutError:
        return f"[ai_quick_scan] {target} 扫描超时，放弃本次扫描。"
    except Exception as e:  # noqa: BLE001
        return f"[ai_quick_scan] 扫描失败：{type(e).__name__}: {e}"
    if not report:
        ports = " / ".join(str(p) for p in COMMON_PORTS)
        return f"[ai_quick_scan] {target} 无命中。可尝试端口：{ports}"
    lines = [f"[ai_quick_scan] {target}："]
    for r in report:
        lines.append(
            f"## {r['component']} {r.get('version') or '?'} "
            f"(置信度 {r.get('confidence')}) → {r['vuln_count']} 条 CVE"
        )
        # 每个组件只列 3 条：单题一上手就吃满上下文的代价太高
        for v in r["top_vulns"][:3]:
            lines.append(f"   - {v.get('cve') or 'N/A'} [{v.get('severity')}] {(v.get('summary') or '')[:60]}")
    lines.append("下一步：对最有希望的组件调用 ai_cve_lookup 看全量，再读规则文件。")
    return _trim(lines)


#: strix / openai-agents 注册用
TOOLS: Final = (ai_fingerprint, ai_cve_lookup, ai_quick_scan)


async def web_cve_lookup(component: str, version: str = "", top_k: int = 8) -> str:
    """Look a web product and version up in the offline CVE index.

    Args:
        component: banner name or vendor:product, e.g. nginx, tomcat, wordpress
        version: version from the banner; empty lists exploited-in-the-wild
            candidates only, because without a version no rule can be judged
        top_k: maximum rows, default 8

    Returns:
        Matching CVEs, each with its version rule; KEV-marked rows come first.
    """
    try:
        if web_cve.data_paths()[0] is None:
            return "[web_cve_lookup] 索引缺失：缺少 web_cve_index.json，本次不查询。"
        hits = await _run(web_cve.lookup, component, version or None, top_k, timeout=30)
    except Exception as e:  # noqa: BLE001 — 查询失败不能打断整题
        return f"[web_cve_lookup] 查询失败：{type(e).__name__}: {e}"
    if not hits:
        scope = "无版本时只列在野利用条目" if not (version or "").strip() else "已按版本求值"
        return (
            f"[web_cve_lookup] {component or '(空)'} {version or '(无版本)'} 未命中（{scope}）。\n"
            "若产品名与版本都没把握，先看响应头的 Server / X-Powered-By；"
            "也可能是自研或逻辑漏洞，直接读接口。"
        )
    label = (version or "").strip()
    head = f"[web_cve_lookup] {component} {label or '(无版本，仅候选)'} 命中 {len(hits)} 条："
    lines = [head]
    for hit in hits:
        mark = " [KEV 在野利用]" if hit.get("kev") else ""
        lines.append(
            f"- {hit.get('cve') or 'N/A'} [{hit.get('severity') or '?'}]{mark} "
            f"{(hit.get('product') or '')}"
        )
        rule = hit.get("rule") or "无版本约束"
        lines.append(f"  约束: {rule[:180]}")
    if not label:
        lines.append("注意：无版本，仅候选；取到版本后再查一次才会收紧。")
    lines.append("下一步：挑与题目功能吻合的一条，按 CPE 区间核对自己的版本，再实际验证。")
    return _trim(lines)


#: Web-product CVE tool. Registered for web kinds only, independent of the
#: AI-security gate: a plain Apache or WordPress box has no AI metadata.
WEB_CVE_TOOLS: Final = (web_cve_lookup,)


def register_web_cve(register_fn: Any | None = None) -> list[str]:
    """Register ``web_cve_lookup`` through the official extension point.

    Args:
        register_fn: injection point, defaults to ``factory.register_agent_tools``.

    Returns:
        Names newly registered (empty when already present).
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001 — older runtime without the query API
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=60)(fn) for fn in WEB_CVE_TOOLS]
    pending = [tool for tool in wrapped if tool.name not in existing]
    if pending:
        register_fn(*pending)
    return [w.name for w in wrapped]


# ---------------------------------------------------------------- strix 接入


def register(register_fn: Any | None = None) -> list[str]:
    """把三个工具注册进 strix 的扫描 agent（保留 vendor 原样）。

    走官方扩展点 ``strix.agents.factory.register_agent_tools``，
    不改 ``_BASE_TOOLS``，升级 strix 时无需 rebase。

    Args:
        register_fn: 注入点，默认取 ``factory.register_agent_tools``。
            显式传入便于单测。

    Returns:
        已注册的工具名列表。

    Raises:
        RuntimeError: 找不到注册函数，说明 strix 结构变更，应停下核对。
    """
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        # 同进程跑第二题时，第一题注册过的同名工具还在 ``_EXTRA_TOOLS`` 里；
        # 再注册一份会让 SDK 的"工具名唯一"检查抛 ValueError，三个 AI 安全
        # 工具就此从第二题起全部消失。
        try:
            existing = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001 — 老版本运行时没有这个查询接口
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    # timeout 只对 async handler 生效——三个工具都已改成 async，
    # 否则 function_tool 会直接抛 ValueError（这点在测试里抓到过）。
    wrapped = [function_tool(timeout=180)(fn) for fn in TOOLS]
    pending = [tool for tool in wrapped if tool.name not in existing]
    if pending:
        register_fn(*pending)
    return [w.name for w in wrapped]


def allow_for(target: str) -> None:
    """把目标写进 ``CTF_AISEC_ALLOW``，供本进程内的工具使用。

    Args:
        target: 形如 ``10.0.0.5:11434`` 或 ``http://10.0.0.5:11434``。
    """
    import urllib.parse

    u = target if "://" in target else "http://" + target
    p = urllib.parse.urlsplit(u)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    cur = {x for x in os.environ.get("CTF_AISEC_ALLOW", "").split(",") if x}
    cur.add(f"{host}:{port}")
    os.environ["CTF_AISEC_ALLOW"] = ",".join(sorted(cur))


if __name__ == "__main__":
    import sys

    t = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:11434"
    allow_for(t)
    print(asyncio.run(ai_quick_scan(t)))
    print("\n" + "=" * 50 + "\n")
    print(asyncio.run(ai_fingerprint(t)))
    print("\n" + "=" * 50 + "\n")
    print(ai_fingerprint(t))
