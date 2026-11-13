# -*- coding: utf-8 -*-
"""B-4 跑批路径非 flag 提交链三层断链的接线钉（平台试跑 2026-11-13 实录）。

断链1：batch_eval 子进程不传 --autosubmit/--platform/--instance——agent 侧
候选链（显式 flag > ``answer:`` 行 > 裸 hex）在跑批路径是死代码，单测全绿、
真题零提交；断链2：EXPLICIT_ANSWER_RE 值下限 6 字符，counter 类答案（1–4
位十进制）永不匹配，019 首次 finish 写对仍被连拒、答案漂移；断链3：ANSWER
行教学只在多问题题发，单问题非 flag 题从未被教过交付格式。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402
from ctf_strix.flag_extract import (  # noqa: E402
    explicit_answer_values,
    per_question_answers,
)

BE_SRC = (ROOT / "scripts" / "batch_eval.py").read_text(encoding="utf-8")
FX_SRC = (ROOT / "src" / "ctf_strix" / "flag_extract.py").read_text(encoding="utf-8")


# ---------------------------------------------------------------- 断链1
def test_run_agent_passes_autosubmit_triple() -> None:
    """子进程必须拿到三件套 + 凭据，agent 侧答案链才能装上。

    断言用格式无关的子串（G1 之后 cmd += 换成了多行列表），防止再被
    重排版打断。
    """
    assert '"--autosubmit",' in BE_SRC
    assert '"--platform",' in BE_SRC
    assert '"--instance",' in BE_SRC
    assert 'env["CTF_PLATFORM_TOKEN"] = token' in BE_SRC
    # 调用点：实例号与凭据来自本进程刚起的实例，不是全局状态。
    assert "instance=iid" in BE_SRC
    assert "token=client.token" in BE_SRC


def test_platform_host_gets_no_proxy_pardon() -> None:
    """代理黑洞必须放行平台域名，否则提交请求被黑洞吞掉（接线即失效）。"""
    env = {"NO_PROXY": "127.0.0.1,tgt.example", "no_proxy": "127.0.0.1,tgt.example"}
    batch_eval._allow_platform_in_no_proxy(env, "https://ctfy.example.edu.cn")
    assert "ctfy.example.edu.cn" in env["NO_PROXY"].split(",")
    assert env["NO_PROXY"] == env["no_proxy"]
    # 幂等：重复放行不产生重复条目。
    batch_eval._allow_platform_in_no_proxy(env, "https://ctfy.example.edu.cn")
    assert env["NO_PROXY"].count("ctfy.example.edu.cn") == 1


def test_allow_platform_in_no_proxy_bad_url_is_noop() -> None:
    env: dict[str, str] = {}
    batch_eval._allow_platform_in_no_proxy(env, "not a url")
    assert env == {}


# ---------------------------------------------------------------- 断链2
def test_short_decimal_answer_is_now_a_value() -> None:
    """counter 类答案就是短十进制数——6 字符下限曾把它永久挡在门外。"""
    assert explicit_answer_values("answer: 3\n") == ["3"]
    assert explicit_answer_values("Final Answer: 42") == ["42"]


def test_explicit_answer_json_param_string_is_decoded() -> None:
    """finish_scan 的参数是 JSON 串：行锚正则扫原文打不中，必须先解码。"""
    assert explicit_answer_values('{"summary": "answer: 3"}') == ["3"]


def test_explicit_answer_dedup_and_order() -> None:
    assert explicit_answer_values("answer: 3\nanswer: 3\nflag=9") == ["3", "9"]


def test_long_values_unchanged() -> None:
    assert explicit_answer_values("answer: 32-hex-slug-like-value") == [
        "32-hex-slug-like-value"
    ]


def test_lower_bound_is_one_in_source() -> None:
    """钉住下限本身——6 的回归会复活整个拒绝-漂移循环。"""
    assert "{1,200})\"\"\"" in FX_SRC
    assert "{6,200})\"\"\"" not in FX_SRC


# ---------------------------------------------------------------- 断链3
def test_single_nonflag_question_gets_answer_line_teaching() -> None:
    detail = {
        "description": "count the rows",
        "tags": ["misc"],
        "questions": [{"id": "counter"}],
    }
    brief = batch_eval._challenge_brief(detail)
    assert "ANSWER[counter]=" in brief
    assert "单独一行" in brief


def test_single_flag_question_brief_is_unchanged() -> None:
    """flag 单问题题的教学保持原样——不塞「不一定是 flag」的误导。"""
    detail = {
        "description": "get the flag",
        "questions": [{"id": "flag"}],
    }
    assert "ANSWER[" not in batch_eval._challenge_brief(detail)


def test_multi_question_teaching_still_present() -> None:
    detail = {
        "description": "two",
        "questions": [{"id": "slug"}, {"id": "flag"}],
    }
    brief = batch_eval._challenge_brief(detail)
    assert "全部" in brief
    assert "ANSWER[<问题id>]=" in brief



# ---------------------------------------------------------------- B-4 契约行
def test_per_question_answers_maps_lines_to_qids() -> None:
    """``ANSWER[qid]=value`` 行要解析成 qid → 值 的映射。"""
    raw = "ANSWER[counter]=3\n  ANSWER[guest-count]: seven"
    assert per_question_answers(raw) == {"counter": "3", "guest-count": "seven"}


def test_per_question_answers_decodes_json_and_last_wins() -> None:
    """JSON 参数串先解码；同一 qid 多行取最后一行（终稿在后）。"""
    raw = '{"executive_summary": "ANSWER[q1]=wrong\\nANSWER[q1]=right"}'
    assert per_question_answers(raw) == {"q1": "right"}


def test_per_question_answers_refuses_placeholders() -> None:
    """占位符不是交付：``ANSWER[q1]=FLAG{xxxx}`` 必须被过滤。"""
    assert per_question_answers("ANSWER[q1]=FLAG{xxxx}") == {}


def test_per_question_answers_matches_inline_answer() -> None:
    """SAMPLE-019 实录：``**Answer:** `ANSWER[counter]=3` `` 必须被抽到。

    行锚定版本把这一行整个漏掉，提交层判"无候选"，整题零提交。
    """
    raw = '{"executive_summary": "**Answer:** `ANSWER[counter]=3`"}'
    assert per_question_answers(raw) == {"counter": "3"}


def test_per_question_answers_keeps_left_boundary() -> None:
    """放宽行首后仍不能命中更长标识符的一部分。"""
    assert per_question_answers("MYANSWER[q1]=3") == {}
