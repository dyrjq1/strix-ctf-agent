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


def install_ctf_toolset(*, drop_caido: bool = True, drop_bookkeeping: bool = True) -> list[str]:
    """把 strix 的基础工具面裁成 CTF 版本。

    Args:
        drop_caido: 是否摘掉 6 个 Caido 代理工具。本机没有 `caido-cli`，
            这 6 个调用必然报错，**裁掉是纯收益**。
        drop_bookkeeping: 是否摘掉 17 个记账工具（笔记/覆盖度/威胁建模/
            报告）。默认 True 保持历史行为，但**评测与正赛必须一致**：
            评测脚本不裁剪时，正赛也不该裁，否则评测数据不代表正赛。
            收益本身已被证伪——`--trim-tools` 的 006 用了 48 次调用，
            未裁剪的 011 只用 42 次，且原因是 prompt 仍在教被摘掉的工具。

    Returns:
        被摘掉的工具名列表（按原顺序），便于打印核对。

    Raises:
        RuntimeError: 若裁剪后工具面为空，说明 strix 的内部结构已变更，
            此时应停下来重新确认而不是继续跑。
    """
    from strix.agents import factory

    keep: list = []
    dropped: list[str] = []
    for tool in factory._BASE_TOOLS:  # noqa: SLF001 — 这是唯一可用的注入点
        if drop_bookkeeping and tool.name in _BOOKKEEPING:
            dropped.append(tool.name)
            continue
        if drop_caido and tool.name in _CAIDO_DEPENDENT:
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
