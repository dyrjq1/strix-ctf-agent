"""CTF 模式下的工具面裁剪。

设计原则：**不改 vendor 源码**。strix 的 ``_BASE_TOOLS`` 是模块级 tuple，
在 ``build_strix_agent`` 里按模块全局名引用，因此运行时替换即可生效，
vendor 目录保持 1.7.0 原样，升级无需 rebase。

裁剪依据来自基线实验（docs/02-基线实验报告.md）：默认工具面 44 个，
其中 17 个是记账类（coverage / notes / threat_model / reports），在
UPLOADLABS-001 上消耗了 27.6% 的调用预算且对拿 flag 零贡献。
另有 6 个代理工具依赖 Caido，本机不存在，调用必失败——留着只会制造
无效轮次。
"""

from __future__ import annotations

from typing import Final

#: 记账类工具：产出渗透测试交付物，CTF 下不计分。
_BOOKKEEPING: Final[frozenset[str]] = frozenset(
    {
        # 笔记
        "create_note",
        "list_notes",
        "get_note",
        "update_note",
        "delete_note",
        # 覆盖度登记
        "record_coverage",
        "update_coverage",
        "list_coverage",
        # 威胁建模
        "get_threat_model",
        "save_threat_model",
        "amend_threat_model",
        # 报告
        "create_vulnerability_report",
        "create_dependency_report",
        "update_vulnerability_report",
        "delete_vulnerability_report",
        "list_reports",
        "get_report",
        # 计划清单。与上面 17 个是同一判据：产出不计分。CTF 只认 flag，
        # 而 ``think`` 已经能承担"想清楚下一步"的职责；再给 6 个 schema 只会
        # 让模型把轮次花在维护清单上。7 条失败轨迹里 todo 调用次数为 0，
        # 却占工具面 4,212 字符（30.8%）——这是裁剪后最贵的一项，比记账工具
        # 还贵，留着它与"记账工具该删"的判断自相矛盾。
        #
        # engagement 题型例外：交付物是报告，计划清单确实要产出。调用方用
        # ``drop_bookkeeping=kind != "engagement"`` 区分，所以这里合并进同一个
        # 开关即可，不需要第二个参数。
        "create_todo",
        "list_todos",
        "update_todo",
        "mark_todo_done",
        "mark_todo_pending",
        "delete_todo",
    }
)

#: 依赖 Caido 的代理工具。本机无 caido-cli，调用只会报错。
_CAIDO_DEPENDENT: Final[frozenset[str]] = frozenset(
    {
        "list_requests",
        "view_request",
        "repeat_request",
        "list_sitemap",
        "view_sitemap_entry",
        "scope_rules",
    }
)

#: 子 agent 编排工具。
#:
#: 实测（2026-10-30 009 复跑，77 次调用）：root 既 spawn 了 2 个子 agent，
#: 又自己下场做侦察，中间还插了 `wait_for_agents` ×2、`agent_finish` ×2、
#: `send_message_to_agent`、`view_agent_graph`——约 17 次调用（22%）花在
#: 协调上，真正的入口在第 3 次调用就已经由 `route_map` 给出了。
#:
#: 这同时是"角色冲突"的硬解法：只要 `create_agent` 还在工具面里，root 就会
#: 在"该不该派"上做没用的元推理（009 第一跑的原文："root agent shouldn't do
#: hands-on testing... However..."，连续两轮）。删掉工具比写 prompt 稳。
#:
#: 需要多 agent 的题（长时间、多独立方向）可以用 ``CTF_ALLOW_SUBAGENTS=1``
#: 打开——默认关闭，因为默认预算是 25-40 轮，协调成本占比过高。
_AGENT_GRAPH: Final[frozenset[str]] = frozenset(
    {
        "create_agent",
        "send_message_to_agent",
        "wait_for_agents",
        "stop_agent",
        "view_agent_graph",
    }
)

#: 依赖 MCP server 的工具。
#:
#: 容器里没有任何 MCP server：``docker/`` 下没有 ``.strix/mcp-servers.json``，
#: 平台也不下发 ``mcp_connection_requests``；``runner`` 那条路读的是**镜像内**
#: 的 ``~/.strix/mcp-servers.json``，镜像里同样不存在。
#:
#: 后果不是"调用会失败"，而是比失败更糟：``list_mcps`` 返回空列表后，模型仍会
#: 花轮次去 ``search_mcp_tools`` / ``describe_mcp`` 找一条不存在的路。实测 7 条
#: 失败轨迹 200 次调用里这 5 个工具**一次都没被调用**——它们只是在工具面里
#: 占了 3,355 字符（24.5%）的决策噪声。
_MCP_DEPENDENT: Final[frozenset[str]] = frozenset(
    {
        "list_mcps",
        "search_mcp_tools",
        "get_mcp_tool_schema",
        "describe_mcp",
        "call_mcp",
    }
)

#: 依赖外网的工具。
#:
#: ⚠️ 正赛的 `internet_policy=deny`、`agent_internet=deny`，**agent 没有外网**，
#: 这个工具在正赛里必然失败。但评测机有网，于是它会真的去搜——实测
#: CTFARENA-012 有一轮直接发了 ``web_search "ctfy.run node2 CTF challenge FLAG{"``，
#: 既浪费轮次，又让测试环境与正赛环境不一致（测试有网、正赛没网，
#: 测出来的行为不能用来推断正赛）。
#:
#: 但“直接摘掉”会让模型撞上 ``Tool 'web_search' not found`` ——实测
#: CTFARENA-095 的 DeepSeek 连撞 2 次，每次都是整整一轮 LLM 调用。
#: 因此这里不摘，而是**换成同名桩**：schema 不变，调用立刻返回一句
#: 确定性说明，模型下一轮就会转向本地手段，不浪费第二轮。
_NETWORK_DEPENDENT: Final[frozenset[str]] = frozenset({"web_search", "web_get_contents"})

#: 最近一次 :func:`install_ctf_toolset` 中被换成离线桩的工具名。
_CTF_STUBBED_TOOLS: list[str] = []

#: 第一次裁剪**之前**的 ``_BASE_TOOLS`` 快照。
#:
#: 两个用途，都不是锦上添花：
#:
#: 1. **回滚**。``_BASE_TOOLS`` 是 vendor 的模块级 tuple，裁剪是原地替换，
#:    一旦裁掉就再也拿不回原始面（重新 import 也不会重置，模块已缓存）。
#:    没有快照就只能重启进程。
#: 2. **校验"名字真的存在过"**。守卫的工具名白名单最典型的失效是写了一个
#:    从不存在或早已被裁掉的名字——``repeat_request`` 就属于后者（Caido 工具，
#:    默认摘除）。不报错、只静默不匹配。有了快照，测试能断言白名单里的每个
#:    名字都来自真实工具面，而不是凭印象写的。
_ORIGINAL_BASE_TOOLS: tuple = ()

_OFFLINE_NOTICE = (
    "no outbound internet in this competition environment "
    "(internet_policy=deny). This tool is stubbed and performs no network access. "
    "Do not retry web_search/web_get_contents. Use local evidence instead: "
    "read the bundle/source already on disk, curl the target host directly, "
    "or consult the loaded skills."
)


def _offline_stub(original: object) -> object:
    """构造与 ``original`` 同名的离线桩工具。

    保留原工具的**名称**，把描述压成一行、参数 schema 压成空对象，执行体换成
    立即返回 ``_OFFLINE_NOTICE`` 的协程。这样：
    * 模型不会看到 "tool not found"，省一轮重试；
    * 桩本身不发任何网络请求，测试环境与正赛 ``internet_policy=deny`` 一致。

    为什么不再继承上游 schema：两个桩原样继承 ``web_search`` /
    ``web_get_contents`` 的参数定义，合计 4,143 字符，占裁剪后工具面的 30%，
    是全表最贵的一处——而这 4,143 字符描述的检索能力在本容器里一次都用不上。
    桩的实际语义是"零参数、立刻返回一句话"，schema 就应当长成这个样子。

    ``strict_json_schema`` 必须显式关掉：strict 模式不接受空 ``properties``，
    也不接受 ``additionalProperties``，构造时就会抛 ``UserError``（已实测）。
    """
    import agents.tool as _agents_tool

    async def _stub(ctx, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ARG001
        return _OFFLINE_NOTICE

    tool = _agents_tool.FunctionTool(
        name=original.name,
        description=(
            "[OFFLINE STUB] No outbound internet (internet_policy=deny). "
            "Calling this returns a fixed notice and performs no network access; "
            "use local evidence instead."
        ),
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=_stub,
        strict_json_schema=False,
    )
    tool._ctf_stubbed = True  # type: ignore[attr-defined]
    return tool


def install_ctf_toolset(
    *,
    drop_caido: bool = True,
    drop_bookkeeping: bool = True,
    drop_agent_graph: bool | None = None,
    drop_mcp: bool = True,
) -> list[str]:
    """把 strix 的基础工具面裁成 CTF 版本。

    Args:
        drop_caido: 是否摘掉 6 个 Caido 代理工具。本机没有 `caido-cli`，
            这 6 个调用必然报错，**裁掉是纯收益**。
        drop_bookkeeping: 是否摘掉 17 个记账工具（笔记/覆盖度/威胁建模/
            报告）。默认 True：CTF 只认 flag，这些工具的产出不计分；且其中
            ``create_vulnerability_report`` 在 VM 上**必然报错**
            （`No module named 'cvss'`），留着只是白烧两轮。
        drop_agent_graph: 是否摘掉子 agent 编排工具。默认按
            ``CTF_ALLOW_SUBAGENTS`` 环境变量决定（不设=摘掉）。
        drop_mcp: 是否摘掉 5 个 MCP 工具。默认 True——容器里没有任何 MCP
            server，这 5 个工具永远只能返回空列表，却在工具面里占 24.5%。
            若将来镜像真的注入了 MCP server，传 False 即可恢复。

    Returns:
        被摘掉的工具名列表（按原顺序），便于打印核对。

    Raises:
        RuntimeError: 若裁剪后工具面为空，说明 strix 的内部结构已变更，
            此时应停下来重新确认而不是继续跑。
    """
    from strix.agents import factory

    import os

    if drop_agent_graph is None:
        drop_agent_graph = os.environ.get("CTF_ALLOW_SUBAGENTS", "").strip() not in ("1", "true", "yes")

    global _ORIGINAL_BASE_TOOLS
    if not _ORIGINAL_BASE_TOOLS:
        _ORIGINAL_BASE_TOOLS = tuple(factory._BASE_TOOLS)  # noqa: SLF001

    keep: list = []
    dropped: list[str] = []
    stubbed: list[str] = []
    for tool in factory._BASE_TOOLS:  # noqa: SLF001 — 这是唯一可用的注入点
        if drop_bookkeeping and tool.name in _BOOKKEEPING:
            dropped.append(tool.name)
            continue
        if drop_caido and tool.name in _CAIDO_DEPENDENT:
            dropped.append(tool.name)
            continue
        if drop_agent_graph and tool.name in _AGENT_GRAPH:
            dropped.append(tool.name)
            continue
        if drop_mcp and tool.name in _MCP_DEPENDENT:
            dropped.append(tool.name)
            continue
        if tool.name in _NETWORK_DEPENDENT:
            # 幂等：install_ctf_toolset 可能被调用两次（入口 + 评测脚本），
            # 再包一层会让描述变成 "[OFFLINE STUB] [OFFLINE STUB] ..."。
            # 实测过这个套娃，它不会报错，只会让工具面悄悄变长。
            if getattr(tool, "_ctf_stubbed", False):
                keep.append(tool)
            else:
                keep.append(_offline_stub(tool))
            stubbed.append(tool.name)
            continue
        keep.append(tool)

    if not keep:
        msg = "工具裁剪后为空，strix 内部结构可能已变更，请重新核对 _BASE_TOOLS"
        raise RuntimeError(msg)

    factory._BASE_TOOLS = tuple(keep)  # noqa: SLF001
    _CTF_STUBBED_TOOLS[:] = stubbed
    return dropped


#: 沙箱清单校验只接受 workspace 内的 workdir，而 agent 习惯写 ``/tmp``、
#: ``/workspace``。实测 GLM-5.3-EV 在 CTFARENA-009 上连续两次因为
#: ``workdir=/tmp`` / ``workdir=/workspace`` 被直接拒绝，白烧 2 轮。
#: 这里不改 vendor：把 workdir 改写成命令前缀 ``cd ... &&``，语义等价，
#: 且 shell 本身在宿主上执行，``cd /tmp`` 本来就可达。
def original_tool_names() -> set[str]:
    """Return every tool name strix shipped with, before any trimming.

    Returns:
        The upstream names.  Empty until :func:`install_ctf_toolset` has run at
        least once (nothing has been mutated before that, so callers can fall
        back to ``factory._BASE_TOOLS``).
    """
    return {getattr(t, "name", "") for t in _ORIGINAL_BASE_TOOLS}


def restore_base_tools() -> bool:
    """Put ``factory._BASE_TOOLS`` back the way strix shipped it.

    Exists because trimming mutates a vendor module-level tuple in place: after
    the first call the original surface is unreachable without a process
    restart.  Rollback during an A/B needs to be one call, not a re-exec.

    Returns:
        True when a snapshot existed and was restored; False otherwise.
    """
    if not _ORIGINAL_BASE_TOOLS:
        return False
    from strix.agents import factory

    factory._BASE_TOOLS = _ORIGINAL_BASE_TOOLS  # noqa: SLF001
    _CTF_STUBBED_TOOLS.clear()
    return True


def install_workdir_shim() -> None:
    """让 ``exec_command`` 接受 workspace 之外的 ``workdir``。

    在 ``factory._wrap_exec_command`` 外层再包一层：调用时把
    ``workdir`` 从参数里摘掉，拼成 ``cd <dir> && <cmd>``。这样既不触发
    ``InvalidManifestPathError``，也不改变命令实际执行位置。
    """
    import json as _json
    import shlex

    from strix.agents import factory as _factory

    if getattr(_factory, "_ctf_workdir_shim", False):
        return

    original = _factory._wrap_exec_command  # noqa: SLF001

    def wrapper(tool):
        wrapped = original(tool)
        invoke_tool = wrapped.on_invoke_tool

        async def invoke(ctx, raw_input):
            try:
                parsed = _json.loads(raw_input)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                workdir = parsed.pop("workdir", None)
                if isinstance(workdir, str) and workdir.strip():
                    cmd = str(parsed.get("cmd") or "")
                    parsed["cmd"] = f"cd {shlex.quote(workdir)} && {cmd}"
                    raw_input = _json.dumps(parsed)
                elif workdir is not None:
                    raw_input = _json.dumps(parsed)
            return await invoke_tool(ctx, raw_input)

        wrapped.on_invoke_tool = invoke
        return wrapped

    _factory._wrap_exec_command = wrapper  # noqa: SLF001
    _factory._ctf_workdir_shim = True  # noqa: SLF001