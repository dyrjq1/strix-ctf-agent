"""上下文封顶的行为契约测试。

为什么这些用例存在：CTFARENA-012 那次教训是"日志打印了 installed，但
实际裁剪次数为 0"——**装上了**不等于**起作用了**。日志会说谎，所以每一层
都要有会失败的断言。

2026-11-01 又补了一条更贵的教训：按龄裁剪（"最近 N 条原文"）虽然让
raw token 降了 9%，却把 prefix cache 命中率从 95.7% 打到 57.8%，
等效成本涨 6.3 倍。所以这里的核心契约是**幂等 + 位置无关**：

1. 同一段内容无论在历史第几条，处理结果完全一致；
2. f(f(x)) == f(x)，重复应用不再变化；
3. 逐轮追加时，旧条目的输出逐字节不变（前缀缓存的前提）；
4. 结构不变：function_call / function_call_output 一条不少、call_id 不配对不乱；
5. 被压掉的输出里若含 flag，flag 原样留下。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import context as ctx_mod  # noqa: E402
from ctf_strix import prompt as prompt_mod  # noqa: E402


def _pair(call_id: str, name: str, args: str, output: str) -> list[dict]:
    return [
        {"type": "function_call", "call_id": call_id, "name": name, "arguments": args},
        {"type": "function_call_output", "call_id": call_id, "output": output},
    ]


def test_short_output_is_untouched():
    """没超上限的输出必须逐字节原样通过：这是绝大多数正常 curl 的情形。"""
    capper = ctx_mod.HistoryCapper(cap_chars=8_000)
    items = _pair("c1", "exec_command", '{"cmd":"ls"}', "a.txt\nb.txt")

    out, saved = capper.apply(items)

    assert saved == 0
    assert out == items


def test_long_output_is_capped_but_structure_survives():
    """压过长的输出，但条目数量、类型、call_id 配对一条不能少。"""
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, head=1_200, tail=600)
    big = "HTTP/1.1 200 OK\n" + ("x" * 20_000)
    items = _pair("c1", "exec_command", '{"cmd":"curl /"}', big)

    out, saved = capper.apply(items)

    assert saved > 0
    assert len(out) == len(items)
    assert [i["type"] for i in out] == [i["type"] for i in items]
    for call, output in zip(items[0::2], items[1::2]):
        assert call["call_id"] == output["call_id"]
    assert len(out[1]["output"]) < len(big)
    assert len(out[1]["output"]) <= 2_000 + 200


def test_capping_is_idempotent():
    """f(f(x)) == f(x)：重复应用不再变化，否则每轮都会漂移、缓存必崩。"""
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, head=1_200, tail=600)
    big = "y" * 20_000
    items = _pair("c1", "exec_command", '{"cmd":"curl /"}', big)

    once, _ = capper.apply(items)
    twice, saved_twice = capper.apply(once)

    assert saved_twice == 0
    assert twice == once


def test_capping_is_position_independent():
    """同一条输出在历史第 1 位和第 50 位，处理结果必须完全一致。"""
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, head=1_200, tail=600)
    big = "z" * 20_000
    target = _pair("target", "exec_command", '{"cmd":"big"}', big)

    alone, _ = capper.apply(target)

    buried: list[dict] = []
    for i in range(50):
        buried += _pair(f"pad{i}", "exec_command", '{"cmd":"ls"}', "ok")
    buried += target

    out, _ = capper.apply(buried)

    assert out[-2:] == alone


def test_prefix_is_stable_across_turns():
    """逐轮追加时，**已存在条目的输出逐字节不变**——前缀缓存的前提。

    这是本轮最关键的回归：旧版按龄裁剪在这里必然失败，因为第 10 轮的
    原文到第 11 轮会变成头尾截断。
    """
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, head=1_200, tail=600)
    items: list[dict] = []
    previous_texts: list[str] = []

    for turn in range(1, 41):
        big = f"turn{turn}:" + ("p" * 5_000)
        items += _pair(f"c{turn}", "exec_command", '{"cmd":"curl"}', big)
        out, _ = capper.apply(items)

        texts = [ctx_mod._text_of(i) for i in out]
        # 上一轮的所有条目必须是这一轮的前缀，逐字节相同。
        assert texts[: len(previous_texts)] == previous_texts, f"prefix drifted at turn {turn}"
        previous_texts = texts


def test_flag_in_capped_output_survives():
    """被压掉的输出里若含 flag，flag 原文必须留下。"""
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, head=1_200, tail=600)
    big = (
        "header\n"
        + ("y" * 9_000)
        + "\nFLAG{02d0c0de02d0c0de02d0c0de02d0c0de}\n"
        + ("z" * 9_000)
    )
    items = _pair("c1", "exec_command", '{"cmd":"cat /flag"}', big)

    out, _ = capper.apply(items)

    assert "FLAG{02d0c0de02d0c0de02d0c0de02d0c0de}" in out[1]["output"]


def test_big_arguments_are_capped_too():
    """工具调用参数同样每轮重发，超长脚本也要封顶。"""
    capper = ctx_mod.HistoryCapper(cap_chars=2_000, arg_cap=1_000)
    args = '{"cmd": "' + ("A" * 12_000) + '"}'
    items = _pair("c1", "exec_command", args, "short")

    out, saved = capper.apply(items)

    assert saved > 0
    assert len(out[0]["arguments"]) < len(args)
    assert out[0]["call_id"] == "c1"


def test_install_replaces_every_render_binding():
    import strix.agents.factory as factory
    import strix.agents.prompt as prompt_api
    import strix.core.runner as runner

    prompt_mod.install()

    rendered = prompt_api.render_system_prompt(
        system_prompt_context={
            "authorized_targets": [{"type": "url", "value": "https://t.test/"}]
        }
    )

    # 三处绑定必须是同一个实现。只改一处会让不同 agent 拿到不同提示。
    assert factory.render_system_prompt is prompt_api.render_system_prompt
    assert runner.render_system_prompt is prompt_api.render_system_prompt
    assert "https://t.test/" in rendered
    # 通用渗透提示里的"必须委派子 agent"已经和摘掉的 create_agent 冲突。
    assert "multi_agent_system" not in rendered
    assert len(rendered) < 20_000


def test_installed_prompt_is_much_smaller():
    text = prompt_mod.build({"authorized_targets": [{"type": "url", "value": "https://t.test/"}]})

    # 原提示 103,541 字符；只要还回到六位数字就说明替换失效了。
    assert len(text) < 15_000
    assert "no internet" in text.lower()