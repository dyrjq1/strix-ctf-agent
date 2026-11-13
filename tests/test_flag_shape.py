"""flag 形态：标签式前缀 + 原体字符集。

平台题面不声明 flag 格式，前缀不可枚举（实测出现过完全不在旧白名单里的
真答案）。所以抽取层只约束"长相"：2–16 位字母数字/点/横线的标签，紧跟
``{...}``。这里锁定的是这条契约本身，以及"整个包里只有一份真值"。

已知代价一并锁进来：``div{margin}`` 这类 LaTeX/模板文本会命中 ``FLAG_RE``，
而 ``is_placeholder`` / ``is_code_template`` 都挡不住。这不是漏改——前缀
放宽后无法从形态上区分"标签 + 变量名"和"标签 + flag"。下游靠平台
verify-answer 预检（``scripts/batch_eval.py::Client.verify``）在提交前问
判分器，明知为假就不提交。
"""

from __future__ import annotations

import pytest

from ctf_strix.flag_extract import (
    CANDIDATE_RE,
    FLAG_RE,
    _PREFIX_RE,
    is_code_template,
    is_placeholder,
)

# 全部是明显编造的体，不要换成真实答案。
LABELLED_FLAGS = [
    "HTB{fake_body_0ne}",
    "TPCTF{fake_body_2}",
    "picoCTF{fake_body_three}",
    "HackTheBox{fake_body_4}",
    "FCSC{fake_body-five}",
    "ctf_arena{fake_body_six}",
]


@pytest.mark.parametrize("value", LABELLED_FLAGS)
def test_label_prefix_matches_any_platform(value: str) -> None:
    """标签不白名单：真答案的前缀可以是任何平台自己的写法。"""
    match = FLAG_RE.search(value)

    assert match is not None, value
    assert match.group(0) == value


@pytest.mark.parametrize("value", ["FLAG{a}", "HTB{x}"])
def test_body_needs_two_characters(value: str) -> None:
    """体长度门槛没有放宽：单字符体是噪声，不是答案。"""
    assert FLAG_RE.search(value) is None


@pytest.mark.parametrize("value", ["FLAG{ab}", "HTB{x1}"])
def test_two_character_body_is_enough(value: str) -> None:
    """体长度门槛没有收紧：``{2,}`` 之下两条都算。"""
    assert FLAG_RE.search(value) is not None


@pytest.mark.parametrize(
    "value",
    [
        "div{margin:0}",   # CSS：体里有冒号，窄集接不住
        '{"k":1}',         # JSON：标签不是字母数字开头
        "${x}",            # shell：标签为空
        "<%= x %>",        # ERB：没有花括号体
        "%s",              # printf：没有花括号
        "{{flag}}",        # 未渲染模板：没有标签
    ],
)
def test_obvious_non_answers_do_not_match(value: str) -> None:
    """这些是原体字符集挡住的典型噪声，不能因为前缀放宽就变成候选。"""
    assert FLAG_RE.search(value) is None, value


def test_relaxed_prefix_accepts_latex_artifact_and_is_documented() -> None:
    """已知代价：``div{margin}`` 命中 ``FLAG_RE``，两道形态闸门都放它过。

    体里没有冒号，窄集认它；它也不是模板（不是 ``{{`` / ``${`` / ``%s`` /
    ``[a-z]`` 开头）。无法在形态层修——真 flag 的体就是这种字母串。
    下游由 verify-answer 预检负责（``scripts/batch_eval.py::_verify_pick``：
    判分器说全错就不提交），见 ``test_batch_eval.py`` 的 miss 用例。
    """
    assert FLAG_RE.search("div{margin}") is not None
    assert is_placeholder("div{margin}") is False
    assert is_code_template("div{margin}") is False


def test_regexes_have_no_capture_groups() -> None:
    """``AutoSubmitter.candidates()`` 按 ``pat.groups`` 决定取哪一段。

    多一个捕获组，它就会用 ``m.group(1)`` 取到错误片段并当成答案。
    """
    assert FLAG_RE.groups == 0
    assert CANDIDATE_RE.groups == 0
    assert _PREFIX_RE.groups == 0


def test_modules_share_the_single_source_of_truth() -> None:
    """各模块不再各抄一份字面量：同名对象必须 ``is`` 同一份真值。

    体宽窄不同，所以要分开断言：落盘/掩码/竞速这类"只要看见 flag 形状"的
    用宽集 ``CANDIDATE_RE``；判分与收工守卫用窄集 ``FLAG_RE``。
    """
    from ctf_strix import attempt_digest, context, file_triage, finish_guard, nonweb, parallel

    assert finish_guard._FLAG_RE is FLAG_RE
    assert file_triage._FLAG_RE is FLAG_RE
    assert nonweb._FLAG_RE is FLAG_RE

    assert attempt_digest._FLAG_RE is CANDIDATE_RE
    assert context._FLAG_RE is CANDIDATE_RE
    assert parallel._FLAG_RE is CANDIDATE_RE
