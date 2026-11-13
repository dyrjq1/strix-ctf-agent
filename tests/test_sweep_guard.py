"""P20-c：单次调用内部的扫描守卫。

三条断言对应三次真实的"守卫装了但没生效"：

1. 判定逻辑本身（050 的 36,000 次路径探测必须命中）；
2. **接线**（`install()` 必须让 `_with_bounded_result` 走出来的工具带上标记，
   在 050 那次运行里 `sweep` 计数是 0，因为压根没人调用 install）；
3. 不误伤（正常的单请求工具调用不能触发，否则提示会变成噪声，被模型忽略）。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.sweep_guard import (  # noqa: E402
    SWEEP_HARD,
    SWEEP_WARN,
    SweepGuard,
    hint_for,
    sweep_summary,
)


def test_detects_the_050_shape() -> None:
    """050 的真实形态：一条 exec_command 里的 Python 双循环 + 组合构造。

    参数里只有几十个种子词，候选由 `itertools.product` 在运行时算出来。
    按字面量数会漏判，必须认"组合 + 批量发送"这对特征。
    """
    args = (
        '{"cmd": "python3 - <<PY\\n'
        "import itertools, requests\\n"
        "words = ['vault','admin','api','internal','core','proxy']\\n"
        "for a,b in itertools.product(words, words):\\n"
        "    for n in range(6):\\n"
        "        requests.get(f'{B}/{a}_{b}_{n}')\\n"
        'PY"}'
    )
    summary = sweep_summary(args)

    assert summary is not None, "050 的形态必须被识别"
    family, count = summary
    assert family == "generated"
    assert hint_for(family, count)


def test_literal_sweep_above_warn_is_flagged() -> None:
    """`?id=1..N` 这种字面量扫描也要认——两族形态缺一不可。"""
    args = "?" + "&".join(f"id={i}" for i in range(SWEEP_WARN * 2))

    summary = sweep_summary(args)

    assert summary is not None
    family, count = summary
    assert count >= SWEEP_WARN
    assert "SWEEP GUARD" in (hint_for(family, count) or "")


def test_hard_threshold_changes_advice() -> None:
    """超硬阈值时提示必须更硬：从"先确认"变成"立刻停"。"""
    soft = hint_for("param:id", SWEEP_WARN)
    hard = hint_for("param:id", SWEEP_HARD)

    assert soft and hard
    assert soft != hard
    assert "Stop it" in hard


def test_single_probe_is_not_flagged() -> None:
    """一道正常的 web 题，一次 http_probe 不能触发——否则提示变成噪声。"""
    guard = SweepGuard()

    assert guard.check("http_probe", '{"url": "https://x.test/admin"}') is None
    assert guard.hits == 0


def test_non_probe_tools_are_ignored() -> None:
    """记账工具即使参数里有长列表，也不该触发（它们打不到靶机）。"""
    guard = SweepGuard()
    many = ",".join(f'"v{i}"' for i in range(200))

    assert guard.check("todo_write", "{" + many + "}") is None
    assert guard.hits == 0


def test_counters_split_warn_and_hard() -> None:
    guard = SweepGuard()
    mid = "?" + "&".join(f"id={i}" for i in range(SWEEP_WARN + 2))
    big = "?" + "&".join(f"id={i}" for i in range(SWEEP_HARD + 20))

    guard.check("exec_command", mid)
    guard.check("exec_command", big)

    assert (guard.warn, guard.hard) == (1, 1)
    assert guard.hits == 2
    assert guard.worst >= SWEEP_HARD + 20


def test_stats_reports_all_four_counters() -> None:
    """result.json 只能看到 stats()，四个计数少一个就归不了因。"""
    guard = SweepGuard()
    mid = "?" + "&".join(f"id={i}" for i in range(SWEEP_WARN + 2))
    big = "?" + "&".join(f"id={i}" for i in range(SWEEP_HARD + 20))

    guard.check("exec_command", mid)
    guard.check("exec_command", big)

    stats = guard.stats()
    assert set(stats) == {"hits", "warn", "hard", "worst"}
    assert (stats["hits"], stats["warn"], stats["hard"]) == (2, 1, 1)
    assert stats["worst"] >= SWEEP_HARD + 20


def test_stats_stay_zero_without_a_hit() -> None:
    """没命中时快照必须是全零，否则"没触发"和"触发过"在数据上同形。"""
    guard = SweepGuard()

    assert guard.check("http_probe", '{"url": "https://x.test/admin"}') is None
    assert guard.stats() == {"hits": 0, "warn": 0, "hard": 0, "worst": 0}


def test_install_marks_exec_command(monkeypatch) -> None:
    """接线本身：install 之后，走过 `_with_bounded_result` 的工具必须带标记。

    这条是这次修复的核心。`sweep_guard` 之前只有两个纯函数，**没有任何
    地方 import 它**；纯函数单测全绿，真实运行里计数恒为 0。
    """
    pytest.importorskip("strix")
    pytest.importorskip("agents")

    from agents.tool import FunctionTool
    from strix.agents import factory

    import ctf_strix.guard_mount as mount_mod
    import ctf_strix.sweep_guard as sweep_mod

    # 每次都从干净状态开始，避免其它测试装过的钩子干扰
    monkeypatch.setattr(factory, "_with_bounded_result", lambda t: t)
    monkeypatch.setattr(mount_mod, "_MARK", mount_mod._MARK, raising=False)

    tool = FunctionTool(
        name="exec_command",
        description="probe",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=lambda ctx, raw: "ok",
    )

    guard = sweep_mod.install()
    wrapped = factory._with_bounded_result(tool)

    assert getattr(wrapped, "_ctf_sweep_guarded", False) is True
    assert isinstance(guard, SweepGuard)


def test_installed_guard_appends_hint_without_dropping_result() -> None:
    """命中后必须保留原结果再加提示——拒绝会让模型重发（enum_guard 的老教训）。"""
    pytest.importorskip("strix")
    pytest.importorskip("agents")
    import asyncio

    from agents.tool import FunctionTool
    from strix.agents import factory

    import ctf_strix.sweep_guard as sweep_mod

    original = factory._with_bounded_result
    factory._with_bounded_result = lambda t: t
    try:
        async def inner(ctx, raw):  # noqa: ANN001, ARG001
            return "REAL OUTPUT"

        tool = FunctionTool(
            name="exec_command",
            description="probe",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=inner,
        )
        sweep_mod.install()
        wrapped = factory._with_bounded_result(tool)
        args = "?" + "&".join(f"id={i}" for i in range(SWEEP_HARD + 5))

        out = asyncio.run(wrapped.on_invoke_tool(None, args))
    finally:
        factory._with_bounded_result = original

    assert out.startswith("REAL OUTPUT"), "原结果不能被吞掉"
    assert "SWEEP GUARD" in out



def test_detects_through_json_escaping() -> None:
    """**最关键的一条**：`on_invoke_tool` 交来的参数是 JSON 序列化后的字符串。

    真实形态是 `a=[\"api\",\"v1\"]`。原版字面量正在左引号能匹配、右引号前
    多了个反斜杠，于是**整条调用的字面量全部丢失**。050 复跑时 1440 个候选
    路径返回 None，守卫零触发，就是这个原因。
    """
    import json

    cmd = "\n".join(
        [
            "import requests",
            "from concurrent.futures import ThreadPoolExecutor",
            'base = "https://x.test"',
            'a = ["api", "v1", "vault", "admin", "user", "internal", "core", "ops",',
            '     "auth", "data", "proxy", "meta", "flag", "debug", "config"]',
            'paths = [f"/{x}" for x in a] + [f"/api/{x}" for x in a]',
            "with ThreadPoolExecutor(20) as ex:",
            "    for p, s in ex.map(go, paths): print(p, s)",
        ]
    )

    summary = sweep_summary(json.dumps({"cmd": cmd}))

    assert summary is not None, "序列化后的参数必须照样能识别"
    assert summary[0] == "generated"


def test_detects_list_comprehension_and_threadpool() -> None:
    """050 真实形态：列表推导 + 线程池，不含 itertools.product。

    注意规模：种子要够多才算扫描。4 个种子 x 1 个推导式只有 4 次请求，
    **不该**报警——这条分支的边界由下面 `test_small_loop_is_not_a_sweep`
    从另一侧钉住。
    """
    import json

    seeds = '","'.join(
        ["api", "v1", "vault", "admin", "user", "internal", "core", "ops", "auth",
         "data", "proxy", "meta", "flag", "debug", "config", "health", "status"]
    )
    cmd = "\n".join(
        [
            f'a = ["{seeds}"]',
            'paths = [f"/{x}" for x in a] + [f"/api/{x}" for x in a]',
            "with ThreadPoolExecutor(20) as ex: ex.map(go, paths)",
        ]
    )

    summary = sweep_summary(json.dumps({"cmd": cmd}))

    assert summary is not None
    assert summary[0] == "generated"


def test_normalise_only_touches_escapes() -> None:
    """反转义不能破坏原文本，否则正常的一次请求会被误判成扫描。"""
    from ctf_strix.sweep_guard import _normalise

    normal = '{"url": "https://x.test/a"}'
    assert _normalise(normal) == normal
    assert _normalise("") == ""


def test_escaped_single_probe_stays_silent() -> None:
    """反转义的**代价**必须被控住：一次普通请求仍不能触发。"""
    import json

    args = json.dumps({"url": "https://x.test/admin", "method": "GET"})

    assert sweep_summary(args) is None


def test_small_loop_is_not_a_sweep() -> None:
    """**误伤回归**：三行的 shell 循环不能被判成硬爆破。

    旧版 `_generated_sweep` 返回 `max(estimate, SWEEP_HARD)`，下限顶到硬阈值，
    于是 `for i in 1 2 3; do curl ...; done` 判成 8000 次扫描（实测误伤 1/10）。
    提示一旦恒亮，模型就学会忽略它——比不装还差。
    """
    import json

    args = json.dumps({"cmd": "for i in 1 2 3; do curl -s https://x.test/$i; done"})

    assert sweep_summary(args) is None


def test_real_burst_still_hits_hard() -> None:
    """收紧不能过头：真实的批量爆破仍必须命中。"""
    import json

    cmd = "\n".join([
        'a = ["api","v1","v2","vault","admin","user","users","internal","core","ops",',
        '     "auth","data","proxy","tier","tiers","me","service","services","meta",',
        '     "flag","flags","answer","answers","debug","config","health","status"]',
        'paths = [f"/{x}" for x in a] + [f"/api/{x}" for x in a]',
        "with ThreadPoolExecutor(20) as ex: ex.map(go, paths)",
    ])

    summary = sweep_summary(json.dumps({"cmd": cmd}))

    assert summary is not None
    assert summary[1] >= SWEEP_HARD


# --- AI-6：规模估算器的静默失效 + shell 计数循环 + 词表驱动 -------------------
#
# 修前 `_RANGE_RE` 是 ``range\(\s*\d*\s*,?\s*(\d{2,7})\s*\)``：捕获取前面的贪婪
# ``\d*`` 先把数字吃光再回溯，``range(3000)`` 分出 ``"00"``（=0），于是规模恒为 0、
# `_generated_sweep` 恒定 None。**守卫装着等于没装**——这是本模块第三次。


def test_python_range_scale_is_not_lost_to_the_capture_group() -> None:
    """``range(3000)`` 的规模必须是 3000，不是 0。

    旧正则把它分成 ``"00"``；这是"写法上认了 range、实际一次也没报过"的根因。
    """
    import json

    cmd = ("python3 -c \"import requests\n"
           "for i in range(3000):\n"
           "    requests.get(f'http://x.test/api/u/{i}')\"")

    summary = sweep_summary(json.dumps({"cmd": cmd}))

    assert summary is not None
    family, count = summary
    assert family == "generated"
    assert count == 3000


def test_range_start_and_step_keep_the_upper_bound() -> None:
    """``range(1, 3000)`` / ``range(0, 5000, 2)`` 都取上界。

    第三个参数（步长）不能把上界挤掉，也不能被当成上界。
    """
    import json

    two_arg = 'python3 -c "[requests.get(\'http://x.test/api/%d\' % i) for i in range(1, 3000)]"'
    three_arg = 'python3 -c "[requests.get(\'http://x.test/api/%d\' % i) for i in range(0, 5000, 2)]"'

    assert sweep_summary(json.dumps({"cmd": two_arg}))[1] == 3000
    assert sweep_summary(json.dumps({"cmd": three_arg}))[1] == 5000


def test_a_small_range_of_known_size_stays_silent() -> None:
    """``range(3)`` 是三次请求，不是扫描——修规模估算不许把阈值弄丢。"""
    import json

    cmd = 'python3 -c "[requests.get(\'http://x.test/api/%d\' % i) for i in range(3)]"'

    assert sweep_summary(json.dumps({"cmd": cmd})) is None


def test_shell_brace_and_seq_ranges_are_counted() -> None:
    """shell 的计数循环：``{1..2000}`` / ``seq 1 4000`` / ``seq 2000``。

    `_COMBINE_RE` 里原有的 `range(` 只覆盖 Python；这三种写法在 `curl` 前面
    同样是"一次调用里发 N 个请求"，而且 N 是**参数里写明的**，必须精确计数。
    """
    import json

    cases = {
        "for i in {1..2000}; do curl -s http://x.test/$i; done": 2000,
        "for i in $(seq 1 4000); do curl -s http://x.test/$i; done": 4000,
        "for i in $(seq 2000); do curl -s http://x.test/$i; done": 2000,
    }

    for cmd, expected in cases.items():
        summary = sweep_summary(json.dumps({"cmd": cmd}))
        assert summary is not None, cmd
        assert summary[0] == "generated", cmd
        assert summary[1] == expected, cmd


def test_shell_loop_over_listed_words_stays_silent() -> None:
    """反例：``for w in apple banana cherry`` 只有三次，不能算规模未知的爆破。"""
    import json

    cmd = "for w in apple banana cherry; do curl -s http://x.test/$w; done"

    assert sweep_summary(json.dumps({"cmd": cmd})) is None


def test_wordlist_driven_burst_is_flagged_without_inventing_a_count() -> None:
    """词表在文件里：必须报，但**不许编数字**。

    `while read` / `xargs` / `ffuf` / `gobuster` 的候选数量在参数文本里根本不存在。
    守卫能做的是说"你正在刷一个未确认的名字空间"，不能假装看见 2000。
    """
    import json

    from ctf_strix.sweep_guard import SWEEP_WARN as WARN

    cases = [
        "while IFS= read -r p; do curl -s http://x.test/$p; done < paths.txt",
        "cat paths.txt | xargs -P 20 -I{} curl -s 'http://x.test/{}'",
        "ffuf -w paths.txt -u http://x.test/api/FUZZ -mc 200",
        "gobuster dir -u http://x.test -w list.txt",
        "python3 -c \"import requests\nfor p in open('w.txt'):\n    requests.post('http://x.test/api/i', data=p)\"",
    ]

    for cmd in cases:
        summary = sweep_summary(json.dumps({"cmd": cmd}))
        assert summary is not None, cmd
        assert summary == ("wordlist-run", WARN), cmd
        hint = hint_for(*summary) or ""
        assert "WORD LIST" in hint, cmd
        # 提示里不能出现"扫了 N 个"这种编出来的具体数字。
        assert f"{WARN} distinct" not in hint, cmd
        assert "2000" not in hint, cmd


def test_curl_status_code_flag_is_not_a_wordlist_sweep() -> None:
    """反例：``curl -w '%{http_code}'`` 不是词表。

    这正是不把裸 ``-w`` 收进 `_FILE_SWEEP_RE` 的原因——那样每一次带状态码的
    探测都会被标成爆破，提示立刻退化成噪声。
    """
    import json

    cmd = "curl -s -o /dev/null -w '%{http_code}' http://x.test/api/login"

    assert sweep_summary(json.dumps({"cmd": cmd})) is None
