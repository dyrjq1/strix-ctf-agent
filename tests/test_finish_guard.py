"""收工守卫的回归测试。

三条都对应真实的 0 分路径：

1. 只认大写 ``FLAG{`` → ``ctfy{...}`` 这类答案被连拒三次，白烧轮次；
2. engagement 题没有 flag → 每一次正常收工都被拒，agent 永远退不出去；
3. checker 题同理，而且它的交付物是副作用，不是 flag。
"""

from __future__ import annotations

import re

from ctf_strix.finish_guard import FinishGuard, _MAX_REFUSALS


def test_flag_forms_are_all_recognised() -> None:
    """平台可能用任意一种前缀，守卫只认一种就会误拦。"""
    for flag in ("FLAG{abc123def}", "flag{abc123}", "ctfy{deadbeef}", "CTF{x_y-z}"):
        guard = FinishGuard()
        assert guard.check(f'{{"summary": "got {flag}"}}') is None, flag
        assert guard.allowed == 1
        assert guard.refusals == 0


def test_placeholder_is_not_a_flag() -> None:
    """``FLAG{...}`` 这种模板占位符不能当成已解出。"""
    guard = FinishGuard()
    refusal = guard.check('{"summary": "the answer is FLAG{...}"}')
    assert refusal is not None
    assert refusal["success"] is False


def test_x_placeholder_is_not_a_flag() -> None:
    """``FLAG{xxxx}`` 来自镜像源码注释，2026-11-06 v6 冒烟据此误判 solved。"""
    guard = FinishGuard()
    refusal = guard.check('{"summary": "the answer is FLAG{xxxx}"}')
    assert refusal is not None
    assert refusal["success"] is False


def test_refusal_budget_is_bounded() -> None:
    """解不出题时必须能干净收尾，不能把预算全耗在撞墙上。"""
    guard = FinishGuard()
    for _ in range(_MAX_REFUSALS):
        assert guard.check("nothing here") is not None
    assert guard.check("nothing here") is None
    assert guard.allowed == 1


def test_second_refusal_tells_the_model_to_change_mechanism() -> None:
    """连拒两次仍是同一段文案时，模型会把同一份白卷原样再交一次。

    第 2 次起必须要求换向，而且这段文案得停在机制级：出现 URL、IP、路径或
    flag 字面量，通用守卫就退化成只对某一道题有效的提示。
    """
    guard = FinishGuard()
    first = guard.check("nothing here")
    second = guard.check("nothing here")
    assert first is not None and second is not None

    head = str(first["error"])
    tail = str(second["error"])[len(head):]
    assert str(second["error"]).startswith(head)
    assert tail, "第 2 次拒绝必须比第 1 次多说换向指令"
    assert "mechanism" in tail.lower()
    assert "finish_scan" in tail
    # 题面特定串：URL、flag 字面量、绝对路径片段。
    for leak in ("http://", "https://", "FLAG{", "ctf{", "/flag"):
        assert leak not in tail
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", tail)


def test_first_refusal_stays_the_plain_instruction() -> None:
    """第 1 次不该一上来就要求换向：它还没试过通用建议里的动作。"""
    guard = FinishGuard()
    first = guard.check("nothing here")

    assert first is not None
    assert "mechanism" not in str(first["error"]).lower()


def test_fourth_call_is_allowed_and_marked_as_giving_up() -> None:
    """拒满后放行等于放弃，不是通过；结果必须能被事后区分出来。"""
    guard = FinishGuard()
    for _ in range(_MAX_REFUSALS):
        assert guard.check("nothing here") is not None
    assert guard.gave_up is False

    assert guard.check("nothing here") is None
    assert guard.allowed == 1
    assert guard.gave_up is True


def test_stats_tracks_refusals_allowed_and_give_up() -> None:
    guard = FinishGuard()
    assert guard.stats() == {"refusals": 0, "allowed": 0, "gave_up": 0}

    guard.check("nothing here")
    guard.check("nothing here")
    assert guard.stats() == {"refusals": 2, "allowed": 0, "gave_up": 0}

    guard.check("nothing here")
    assert guard.check("nothing here") is None
    guard.check('{"summary": "got FLAG{abc123}"}')
    assert guard.stats() == {"refusals": 3, "allowed": 2, "gave_up": 1}


def test_engagement_and_checker_never_require_flag() -> None:
    """engagement / checker 没有 flag；守卫必须让路。"""
    for _ in range(3):
        guard = FinishGuard(require_flag=False)
        assert guard.check("report saved, 5 findings") is None
        assert guard.refusals == 0


def test_refusal_quotes_the_answer_verbatim() -> None:
    """改前缀是实测过的 0 分路径：体对、标签被归一化。

    第一次拒信就要说清「标签是题目的」，否则模型按自己的惯例重写前缀，
    交上去体逐字节相同、判分器仍然给 0。
    """
    guard = FinishGuard()
    first = guard.check('{"summary": "no answer yet"}')

    assert first is not None
    text = str(first["error"])
    assert "Quote the answer exactly as the target emitted it" in text
    assert "scores zero" in text
    # 换向指令只属于第 2 次起的追补段；第 1 次不能被它污染。
    assert "mechanism" not in text.lower()


def test_giveup_synthesises_the_answer_from_the_summary() -> None:
    """拒满放行那一次要把 summary 里的候选记下来，而不是交白卷。

    证据账本是空的（``supports()`` 恒 False），所以每一次调用都走「无证据」
    分支并累计拒绝——这正是实测里那条 refused=3 allowed=1 却 answer=None 的
    run 的形状。
    """
    from ctf_strix.evidence import EvidenceLedger
    from ctf_strix.success_stop import SuccessLedger

    success = SuccessLedger()
    guard = FinishGuard(success=success, evidence=EvidenceLedger())
    raw = '{"summary": "found utflag{abc123} in the dumped config"}'

    for _ in range(_MAX_REFUSALS):
        assert guard.check(raw) is not None
    assert success.solved is False

    assert guard.check(raw) is None
    assert guard.stats()["gave_up"] == 1
    assert success.solved is True
    assert success.answer == "utflag{abc123}"
    assert success.source == "finish_guard_giveup"


def test_giveup_with_only_a_placeholder_leaves_the_answer_empty() -> None:
    """占位符不是答案：放行可以，但不能编出一条 answer。"""
    from ctf_strix.evidence import EvidenceLedger
    from ctf_strix.success_stop import SuccessLedger

    success = SuccessLedger()
    guard = FinishGuard(success=success, evidence=EvidenceLedger())
    raw = '{"summary": "the answer is FLAG{xxxx}"}'

    for _ in range(_MAX_REFUSALS):
        assert guard.check(raw) is not None

    assert guard.check(raw) is None
    assert guard.stats()["gave_up"] == 1
    assert success.solved is False
    assert success.answer == ""


def test_giveup_prefers_a_candidate_with_output_evidence() -> None:
    """summary 里两个候选时，选有输出证据支持的那个，不选自回声。

    先说出口的那个字符串只是模型自己参数的复读（``echoed_only`` 为真），
    它排在最前面但不可信；第二个来自一次不含该字面量的工具输出。
    """
    from ctf_strix.evidence import EvidenceLedger

    ledger = EvidenceLedger()
    ledger.observe_output(
        "echo utflag{aaa111}", arguments="echo utflag{aaa111}"
    )
    ledger.observe_output("cat /flag\nHTB{bbb222}")
    guard = FinishGuard(evidence=ledger)

    best = guard._giveup_answer(
        '{"summary": "echo utflag{aaa111} -> HTB{bbb222}"}',
        ["utflag{aaa111}"],
    )
    assert best == "HTB{bbb222}"


def test_goal_prompt_says_the_tag_belongs_to_the_target() -> None:
    """goal prompt 不许再像白名单那样枚举前缀：模型会按名单归一化。"""
    from pathlib import Path

    goal = Path(__file__).resolve().parents[1] / "config" / "ctf_goal.txt"
    text = goal.read_text(encoding="utf-8")

    assert "belongs to the" in text
    assert "Never rename" in text
    assert "Most challenges grade a flag token" not in text


def test_goal_prompt_has_a_depth_exit_after_the_walk() -> None:
    """The walk-in list used to end at "send the hypothesis": breadth was the
    whole of it. A fifth step must say to push one route to exploitation."""
    from pathlib import Path

    goal = Path(__file__).resolve().parents[1] / "config" / "ctf_goal.txt"
    text = goal.read_text(encoding="utf-8")

    assert "go deep, not wide" in text
    assert "a second sweep is not progress" in text


def test_giveup_ignores_config_and_template_shapes() -> None:
    """拒满放行那一次不许把配置/模板串当 flag 交上去（RISK 4）。

    花括号体带标点的形态（CSS / 配置）过不了窄集 ``FLAG_RE``；宽集
    ``CANDIDATE_RE`` 会照单全收。这条路径的产物会被写成主答案并提交，
    交错串就是白耗一次提交机会。
    """
    guard = FinishGuard()
    best = guard._giveup_answer(
        '{"summary": "the page keeps div{margin:0} and style{color:red} rules"}'
    )
    assert best == ""


def test_giveup_still_takes_a_real_flag_next_to_config_text() -> None:
    """窄集不误杀：配置文本旁边躺着一个真 flag 时仍然要取到。"""
    guard = FinishGuard()
    best = guard._giveup_answer(
        '{"summary": "the page keeps div{margin:0}; the flag is utflag{abc123}"}'
    )
    assert best == "utflag{abc123}"


def test_giveup_residual_word_word_shape_is_shared_with_accept() -> None:
    """``word{word}``（无标点）残余与 accept 路径共享，不是 giveup 引入的。

    ``flag_extract.FLAG_RE`` 的 docstring 把这类形态列为"接受，不修"，补偿
    控制是平台 verify-answer 预检。钉住它是防止有人把这里当 bug 修宽了。
    """
    from ctf_strix.flag_extract import FLAG_RE

    assert FLAG_RE.search("div{margin}") is not None
    guard = FinishGuard()
    best = guard._giveup_answer('{"summary": "css: div{margin}"}')
    assert best == "div{margin}"



# -- 非 flag 形态答案：模型显式写下的 ``answer:`` 行 ----------------------


def test_explicit_answer_line_finishes_the_run() -> None:
    """slug / token 型答案没有 ``tag{...}`` 长相：显式 ``answer:`` 行即已交付。

    改前这类收工被「无 flag」拦下：答案明明在模型手里，守卫却叫它回去
    拿一个不存在的 flag，白烧轮次后交白卷。
    """
    guard = FinishGuard()
    assert guard.check('{"executive_summary": "answer: sample-slug-9f3a"}') is None
    assert guard.allowed == 1
    assert guard.refusals == 0
    assert guard.gave_up is False


def test_explicit_answer_line_survives_json_escaping() -> None:
    """raw_input 是 JSON 参数串：答案行的换行在原文里是 ``\\n`` 字面量。

    行锚定正则必须先解码 JSON 再扫字段值，否则显式答案永远抽不到——
    这正是 slug 型题收工零提交的直接根因（抽取层看不见已写下的答案）。
    """
    guard = FinishGuard()
    raw = (
        '{"executive_summary": "found it\\nanswer: token-4f2ab9", '
        '"methodology": "walked the app", "technical_analysis": "t", '
        '"recommendations": "r"}'
    )
    assert guard.check(raw) is None
    assert guard.allowed == 1


def test_explicit_answer_beats_unsupported_flag_shape() -> None:
    """summary 混入未被证据背书的 ``word{word}`` 形态串时，显式交付仍放行。

    否则一段恰好含配置样式串的散文就能把真答案拖进三连拒收。
    """

    class _NoEvidence:
        def supports(self, flag: str) -> bool:
            return False

        def echoed_only(self, flag: str) -> bool:
            return False

    guard = FinishGuard(evidence=_NoEvidence())
    raw = '{"executive_summary": "css shows div{margin}\\nanswer: real-slug-77"}'
    assert guard.check(raw) is None


def test_explicit_answer_allowance_does_not_mark_solved() -> None:
    """放行 ≠ 判 solved：slug 答案没有证据链可背书，权威在平台裁决。

    守卫若在这里把 success 置位，一次口头的 ``answer:`` 行就绕过了
    ``observe_answer`` 的证据口径（与 flag 路径分叉）。
    """

    class _Ledger:
        solved = False
        answer = ""
        source = ""

    ledger = _Ledger()
    guard = FinishGuard(success=ledger)
    assert guard.check('{"executive_summary": "answer: sample-slug-9f3a"}') is None
    assert ledger.solved is False


def test_refusal_teaches_the_explicit_answer_format() -> None:
    """第 1 次拒信就要教交付格式：非 flag 形态答案写成 ``answer:`` 行。

    模型手里有个 slug 却被叫「回去拿 flag」时，它只会再交一次白卷；
    拒信必须告诉它这类答案该怎么交付。
    """
    guard = FinishGuard()
    first = guard.check('{"executive_summary": "no answer yet"}')
    assert first is not None
    text = str(first["error"])
    assert "answer:" in text
    assert "slug" in text
    assert "finish_scan" in text
    assert "mechanism" not in text.lower()


def test_explicit_placeholder_answer_is_refused() -> None:
    """``answer: FLAG{xxxx}`` 是占位符不是交付，仍按无答案拦下。"""
    guard = FinishGuard()
    assert guard.check('{"executive_summary": "answer: FLAG{xxxx}"}') is not None
    assert guard.refusals == 1



def test_mapped_qid_answer_line_finishes_the_run() -> None:
    """``ANSWER[qid]=value`` 契约行与 ``answer:`` 行同判：都是显式交付。

    非 flag 类任务的收工若被「无 flag」拦下，模型只会把同样的答案再写
    一遍，三次拒收后整题交白卷——答案明明就在终稿里。
    """
    guard = FinishGuard()
    assert guard.check('{"executive_summary": "ANSWER[counter]=3"}') is None
    assert guard.allowed == 1
    assert guard.refusals == 0
