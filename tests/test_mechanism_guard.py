"""假设类别计数：同一类机制里的六次不同请求，仍然是同一个假设。

## 为什么需要第二套计数

现有的 ``counts`` 按"族 + 观测指纹"计数，它回答的是"我是不是又发了同一个请求"。
但 043 那类失败不是这样：52 个 ``note_*`` 名字，每个都是新 URL、新参数、新指纹，
于是每个族的计数都被清零，一次警告都不响；而 52 次调用其实全在同一个机制里
（收集信息）。这就是"每步换参数、假设不变"的方向锁定。

第二套计数按**机制类别**计，类别取自 MITRE CAPEC 视图 1000
（https://capec.mitre.org/data/definitions/1000.html，2026-11-03 取）：
它按"攻击怎么做"而不是"攻击想得到什么"分组，正好对应"假设"这一层。
分类落在请求语法上是本项目做的，划分本身来自 CAPEC。

## 反向约束

* 本地 ``ls`` / 读文件不是探针，不能计入（否则守卫天天响，模型学会忽略）；
* 没有机制标记的普通 GET 不配一个类别——猜出来的类别比缺失更糟；
* 硬停（完全相同的响应）优先于类别提示：盲注可以合法地重复同一机制，
  但不能合法地重复同一个响应。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import enum_guard as eg  # noqa: E402


def _probe(url: str, extra: str = "") -> str:
    return '{"method": "GET", "url": "%s"%s}' % (url, extra)


def test_taxonomy_matches_the_capec_top_level():
    """九类必须与 CAPEC-1000 的顶层类别一一对应，不能随手加减。"""
    capec = {
        "156": "deception",
        "210": "abuse-functionality",
        "255": "data-structures",
        "262": "system-resources",
        "152": "injection",
        "223": "probabilistic",
        "172": "timing-state",
        "118": "information-collection",
        "225": "access-control",
    }
    rules = {cid: name for cid, name, _re in eg._MECHANISM_RES}
    assert rules == capec
    assert set(eg.MECHANISM_NAMES) == set(capec.values())
    assert len(eg.MECHANISM_NAMES) == 9


def test_rule_table_and_public_order_cannot_drift():
    assert {name for _cid, name, _re in eg._MECHANISM_RES} == set(eg.MECHANISM_NAMES)


@pytest.mark.parametrize(
    "args,expected",
    [
        (_probe("https://x.test/admin/users"), "access-control"),
        (_probe("https://x.test/api/me", ', "headers_json": "{\\"X-Forwarded-For\\": \\"127.0.0.1\\"}"'), "access-control"),
        (_probe("https://x.test/a?id=1 union select 1,2"), "injection"),
        (_probe("https://x.test/s", ', "body": "{{7*7}}"'), "injection"),
        (_probe("https://x.test/f", ', "body": "{\\"__proto__\\":{\\"admin\\":true}}"'), "data-structures"),
        (_probe("https://x.test/f?p=../../etc/passwd"), "system-resources"),
        (_probe("https://x.test/api/notes"), None),
    ],
)
def test_classification_by_syntax(args, expected):
    assert eg._mechanism_of(args) == expected


def test_deception_headers_are_not_swallowed_by_information_collection():
    """``Host:`` 是欺骗标记；收集类规则也会匹配 header 字样，顺序必须让欺骗先命中。"""
    args = _probe("https://x.test/", ', "headers_json": "{\\"Host\\": \\"evil.test\\"}"')
    assert eg._mechanism_of(args) == "deception"


def test_local_commands_are_not_probes():
    """``ls`` / 读文件没有机制标记，也不该被算成探针。"""
    assert eg._mechanism_of('{"cmd": "ls -la /var/ctf"}') is None
    assert eg._mechanism_of('{"cmd": "cat /var/ctf/work/notes.txt"}') is None


def test_the_043_shape_fires_the_mechanism_guard():
    """043 的形态：同一机制里换 6 个名字，指纹全不同，机制守卫必须响。

    The bodies differ in *words*, not digits: ``_obs_signature`` folds digits,
    so a digit-only difference would be caught by the identical-response guard
    and this test would never reach the mechanism counter.
    """
    guard = eg.EnumerationGuard()
    hints = []
    for word in (
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    ):
        args = _probe(f"https://x.test/api/notes/note_{word}")
        token = guard.begin("http_probe", args)
        hint = guard.finish(token, f"[HTTP 200] note body {word}")
        if hint:
            hints.append(hint)
    assert any("[MECHANISM GUARD]" in h for h in hints), hints
    assert any("information-collection" in h for h in hints), hints


def test_untried_classes_are_named():
    guard = eg.EnumerationGuard()
    hint = None
    for word in (
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    ):
        args = _probe(f"https://x.test/api/notes/{word}")
        token = guard.begin("http_probe", args)
        hint = guard.finish(token, f"[HTTP 200] body {word}") or hint
    assert hint is not None
    assert "access-control" in hint
    assert "injection" in hint
    assert "information-collection" not in hint.split("Untried classes:")[1].split(".")[0]


def test_switching_class_resets_the_streak():
    """一换机制类别就是新假设，计数清零，不能对正常的多方向探测误报。"""
    guard = eg.EnumerationGuard()
    # The first leaf of a family is not classified (one URL is not enumeration);
    # every leaf after that is.  So n distinct leaves give n-2 to the streak.
    for word in ("alpha", "bravo", "charlie", "delta", "echo", "foxtrot"):
        token = guard.begin("http_probe", _probe(f"https://x.test/api/notes/{word}"))
        guard.finish(token, f"[HTTP 200] body {word}")
    before = guard.class_streak
    assert before >= 3, f"enumeration leaves did not accumulate: {before}"

    token = guard.begin("http_probe", _probe("https://x.test/api/save", ', "body": "{\\"__proto__\\":1}"'))
    guard.finish(token, "[HTTP 200] different")
    assert guard.class_streak == 0
    assert "information-collection" in guard.mechanisms
    assert "data-structures" in guard.mechanisms


def test_identical_response_still_wins_over_the_class_hint():
    """完全相同的响应是更强的信号；类别提示不能把它盖掉。"""
    guard = eg.EnumerationGuard()
    args = _probe("https://x.test/admin/users")
    hints = []
    for _ in range(6):
        token = guard.begin("http_probe", args)
        hint = guard.finish(token, "[HTTP 403] forbidden")
        if hint:
            hints.append(hint)
    joined = "\n".join(hints)
    assert "IDENTICAL response" in joined
    assert "[ENUMERATION GUARD]" in joined


def test_guard_does_not_fire_below_the_shared_threshold():
    """阈值沿用 _STALL_AFTER，不另造预算。"""
    guard = eg.EnumerationGuard()
    hints = []
    for i in range(eg._CLASS_STREAK_AFTER - 1):
        token = guard.begin("http_probe", _probe(f"https://x.test/api/{i}"))
        hint = guard.finish(token, f"[HTTP 200] body {i}")
        if hint:
            hints.append(hint)
    assert not any("[MECHANISM GUARD]" in h for h in hints), hints


def test_threshold_is_not_a_new_budget():
    assert eg._CLASS_STREAK_AFTER == eg._STALL_AFTER
