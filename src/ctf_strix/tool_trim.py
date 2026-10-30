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

#: 依赖外网的工具。
#:
#: ⚠️ 正赛的 `internet_policy=deny`、`agent_internet=deny`，**agent 没有外网**，
#: 这个工具在正赛里必然失败。但评测机有网，于是它会真的去搜——实测
#: CTFARENA-012 有一轮直接发了 ``web_search "ctfy.run node2 CTF challenge FLAG{"``，
#: 既浪费轮次，又让测试环境与正赛环境不一致（测试有网、正赛没网，
#: 测出来的行为不能用来推断正赛）。
#:
#: 裁掉它有两个好处：贴合正赛环境，且消除"去网上找 flag"这条歪路。
_NETWORK_DEPENDENT: Final[frozenset[str]] = frozenset({"web_search"})


def install_ctf_toolset(
    *,
    drop_caido: bool = True,
    drop_bookkeeping: bool = True,
    drop_agent_graph: bool | None = None,
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

    keep: list = []
    dropped: list[str] = []
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
        if tool.name in _NETWORK_DEPENDENT:
            dropped.append(tool.name)
            continue
        keep.append(tool)

    if not keep:
        msg = "工具裁剪后为空，strix 内部结构可能已变更，请重新核对 _BASE_TOOLS"
        raise RuntimeError(msg)

    factory._BASE_TOOLS = tuple(keep)  # noqa: SLF001
    return dropped
