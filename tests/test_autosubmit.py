"""``autosubmit`` 的回归测试。

每一条都对应一个真实故障，不是凑覆盖率：

1. 候选顺序错了 → 把哈希/session id 当答案先交，白白浪费一次提交；
2. 没有候选也发请求 → 空答案会污染平台账本；
3. 串行投递未去重 → 同一 question 被反复提交，日志无法判读；
4. HTTP 失败让收工本身崩掉 → agent 的最后一步炸了，整轮日志丢失；
5. 裁决没写回 summary → 复盘时只能从状态码猜平台说了什么。
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from ctf_strix.autosubmit import AutoSubmitter
from ctf_strix.flag_extract import FLAG_RE, is_placeholder


def _mk(questions: list[dict[str, Any]]) -> tuple[AutoSubmitter, list[dict[str, Any]]]:
    """造一个 submitter，``_questions`` 返回给定列表，``_post`` 记录所有请求。"""
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    sent: list[dict[str, Any]] = []

    sub._questions = lambda: questions  # type: ignore[method-assign]

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        sent.append(body)
        # 只有交 "right" 才算对，其余判错
        return {"correct": body["answer"] == "right", "question_id": body["question_id"]}

    sub._post = fake_post  # type: ignore[method-assign]
    return sub, sent


def test_explicit_flag_ranks_before_bare_hex() -> None:
    """``FLAG{...}`` 必须排在裸 hex 之前。

    SAMPLE-001 的 slug 是 32 位 hex，而 summary 里同时可能夹着 MD5、session
    id、提交哈希。先交裸 hex 就是把一次提交浪费在噪声上。
    """
    cands = AutoSubmitter.candidates(
        "hash=0123456789abcdef0123456789abcdef real=FLAG{yes_this_one}"
    )
    assert cands[0] == "FLAG{yes_this_one}"
    assert "0123456789abcdef0123456789abcdef" in cands


def test_candidates_dedupe_and_cap() -> None:
    """重复候选要去重，且总量有上限，避免一次收工打出几十个请求。"""
    many = " ".join(f"FLAG{{x{i}}}" for i in range(20))
    cands = AutoSubmitter.candidates(many)
    assert len(cands) <= 6
    assert len(set(cands)) == len(cands)


def test_no_candidate_sends_nothing() -> None:
    """summary 里没有答案形态时，一个请求都不该发。

    空答案提交会污染平台账本，而且会让"没解出"和"解出来但没写对"混为一谈。
    """
    sub, sent = _mk([{"id": "q1", "mode": "dynamic"}])
    verdict = sub.submit("I looked around and found nothing.")
    assert sent == []
    assert verdict["tried"] == []
    assert verdict["note"]


def test_answered_correctly_does_not_block_submission() -> None:
    """``answered_correctly=true`` **不该**挡住提交。

    这条测试是"反向"的，因为它锁死的是一个我自己犯过的错：第一版按这个字段
    过滤，SAMPLE-001 收工时打印 "NOT SUBMITTED: 没有待答的 question"，
    而 slug 明明就在 summary 里。

    平台实测：``answered_correctly=true`` 时提交错误答案是 ``correct:false``，
    提交正确答案是 ``correct:true``——这个标记根本不拦提交，拿它当闸门是自伤。
    """
    sub, sent = _mk([
        {"id": "slug", "mode": "dynamic", "answered_correctly": True},
        {"id": "flag", "mode": "dynamic", "answered_correctly": True},
    ])
    verdict = sub.submit("FLAG{abc}")
    assert [b["question_id"] for b in sent] == ["slug", "flag"]
    assert verdict["tried"], verdict


def test_checker_question_is_skipped() -> None:
    """checker 走 ``/check`` 通道，往 ``/submissions`` 交只会得到 correct:false。"""
    sub, sent = _mk([{"id": "outage", "mode": "checker"}])
    verdict = sub.submit("FLAG{abc}")
    assert sent == []
    # 提示里要说明是"只有非 flag 类 question"，不能笼统说"没有 flag 类"
    assert "非 flag 类" in verdict["note"], verdict


def test_correct_answer_stops_trying_more_candidates() -> None:
    """一个 question 投中后就换下一个 question，别把剩余候选也打出去。"""
    sub, sent = _mk(
        [{"id": "q1", "mode": "dynamic"}, {"id": "q2", "mode": "dynamic"}]
    )
    calls = {"n": 0}

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        # 预检不记账，所以只统计真正写进 /submissions 的那条。
        if path.endswith("/submissions"):
            sent.append(body)
        calls["n"] += 1
        # q1 的第一个候选就中；q2 全部判错
        return {"correct": body["question_id"] == "q1", "question_id": body["question_id"]}

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{right_here}")
    q1_calls = [b for b in sent if b["question_id"] == "q1"]
    assert len(q1_calls) == 1
    assert verdict["correct"] == ["q1=FLAG{right_here}"]


def test_http_error_does_not_raise() -> None:
    """网络失败必须折算成 ``error`` 字段，不能让收工本身炸掉。"""
    sub, _ = _mk([{"id": "q1", "mode": "dynamic"}])
    sub._post = lambda *a, **k: {"error": "HTTP 429"}  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{abc}")
    assert verdict["tried"][0]["error"] == "HTTP 429"
    assert verdict["correct"] == []


def test_decorate_puts_verdict_into_summary() -> None:
    """裁决要写进 summary，否则日志里没有"平台说对/错"的硬证据。"""
    sub, _ = _mk([])
    ok = sub.decorate("done", {"correct": ["q1=FLAG{a}"], "tried": []})
    assert "ACCEPTED" in ok and "q1=FLAG{a}" in ok

    bad = sub.decorate("done", {"correct": [], "tried": [{"qid": "q1"}]})
    assert "REJECTED" in bad

    none = sub.decorate("done", {"correct": [], "tried": [], "note": "无候选"})
    assert "NOT SUBMITTED" in none and "无候选" in none


def test_question_fetch_failure_is_reported_not_swallowed() -> None:
    """拉 question 失败必须说出原因，不能静默变成"本题没有 flag 类 question"。

    这条锁死的是一个排查花了两轮的真实 bug：``_TIMEOUT`` 被写成
    ``(10, 45)`` 元组（requests 的写法），而 urllib 只吃单个浮点数，
    ``urlopen`` 直接抛 TypeError，又被 ``except Exception: return []`` 吞掉。
    日志只有"没有待答的 question"，看起来像题目本身没有 flag 题。
    """
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    sub.platform = "http://127.0.0.1:1"  # 必定连不上
    verdict = sub.submit("FLAG{abc}")
    assert verdict["tried"] == []
    # note 必须是真实错误，而不是那句容易误读的"没有 flag 类 question"
    assert "flag 类 question" not in verdict["note"], verdict
    assert verdict["note"], verdict


def test_verdict_json_serialisable() -> None:
    """tried 里含平台原始字段，必须能直接 json 序列化写进结果文件。"""
    sub, _ = _mk([{"id": "q1", "mode": "dynamic"}])
    verdict = sub.submit("FLAG{abc}")
    json.dumps(verdict)  # 不抛异常即可


def _mk_oracle(questions, truth: dict[str, str]):
    """A submitter whose verify-answer endpoint knows the answers."""
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    posted: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []

    sub._questions = lambda: questions  # type: ignore[method-assign]

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        if path.endswith("/verify-answer"):
            verified.append(body)
            return {
                "correct": truth.get(body["question_id"]) == body["answer"],
                "question_id": body["question_id"],
            }
        posted.append(body)
        return {
            "correct": truth.get(body["question_id"]) == body["answer"],
            "question_id": body["question_id"],
        }

    sub._post = fake_post  # type: ignore[method-assign]
    return sub, posted, verified


def test_verify_is_used_before_spending_a_submission() -> None:
    """Wrong candidates must not consume the per-question attempt cap.

    The platform's openapi says verify-answer runs the same grader while
    writing no submission record. Six wrong candidates against a cap of
    three is a real loss; the probe makes the wrong ones free.
    """
    sub, posted, verified = _mk_oracle(
        [{"id": "flag", "mode": "dynamic", "attempts_remaining": 3}],
        {"flag": "FLAG{right}"},
    )
    verdict = sub.submit("FLAG{wrong} FLAG{right}")
    assert len(verified) == 2, verified
    assert [b["answer"] for b in posted] == ["FLAG{right}"], posted
    assert verdict["correct"] == ["flag=FLAG{right}"]


def test_seeded_mode_is_submitted() -> None:
    """``seeded`` answers go through /submissions like dynamic ones."""
    sub, posted, _ = _mk_oracle(
        [{"id": "storage_remark", "mode": "seeded"}],
        {"storage_remark": "s3cr3t"},
    )
    verdict = sub.submit("answer: s3cr3t")
    assert [b["question_id"] for b in posted] == ["storage_remark"]
    assert verdict["correct"] == ["storage_remark=s3cr3t"], verdict


def test_exhausted_question_is_skipped_not_hammered() -> None:
    """``attempts_remaining=0`` means the platform will reject: say so."""
    sub, posted, verified = _mk_oracle(
        [{"id": "flag", "mode": "dynamic", "attempts_remaining": 0}],
        {"flag": "FLAG{right}"},
    )
    verdict = sub.submit("FLAG{right}")
    assert posted == [] and verified == []
    assert verdict["skipped"] and "attempts_remaining=0" in verdict["skipped"][0]


def test_verify_unavailable_falls_back_to_submitting() -> None:
    """An older platform without verify-answer must still score."""
    sub = AutoSubmitter("https://example.invalid", "inst-1", "tok")
    posted: list[dict[str, Any]] = []
    sub._questions = lambda: [{"id": "flag", "mode": "dynamic"}]  # type: ignore[method-assign]

    def fake_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
        if path.endswith("/verify-answer"):
            return {"error": "HTTP 404"}
        posted.append(body)
        return {
            "correct": body["answer"] == "FLAG{right}",
            "question_id": body["question_id"],
        }

    sub._post = fake_post  # type: ignore[method-assign]
    verdict = sub.submit("FLAG{wrong} FLAG{right}")
    assert [b["answer"] for b in posted] == ["FLAG{wrong}", "FLAG{right}"]
    assert verdict["correct"] == ["flag=FLAG{right}"]


def test_labelled_answer_is_extracted_for_non_flag_shapes() -> None:
    """A seeded answer is often not flag-shaped; the label is the only signal."""
    cands = AutoSubmitter.candidates(
        "some noise 6420f7ff74fc44616ecf891691049580\nfinal answer: `s3cr3t-value`"
    )
    assert cands[0] == "s3cr3t-value", cands


def test_bare_prose_is_still_not_a_candidate() -> None:
    """Scraping free text would submit sentences; only labels and shapes count."""
    cands = AutoSubmitter.candidates("I looked around and the page said nothing useful.")
    assert cands == [], cands


def test_placeholder_shapes_are_not_candidates() -> None:
    """占位符不能成为提交候选。

    2026-11-06 v6 冒烟：agent 读到自己源码注释里的示例 flag，证据链把它当成
    "检索到的证据"，一道不可能解出的题被判 solved。提交是最后一道门，宽正则
    能抽出的每种占位形态都要覆盖。
    """
    cands = AutoSubmitter.candidates(
        "a=FLAG{xxxx} b=FLAG{...} c=FLAG{<value>} d=FLAG{***} e=FLAG{{flag}}"
    )
    assert cands == [], cands


def test_real_flags_survive_placeholder_filter() -> None:
    """过滤占位符不能误杀真实 flag。"""
    hex32 = "0123456789abcdef0123456789abcdef"
    cands = AutoSubmitter.candidates(f"FLAG{{r34l_fl4g_9f2a}} {hex32}")
    assert cands[0] == "FLAG{r34l_fl4g_9f2a}"
    assert hex32 in cands


def test_ctfy_prefix_wins_over_ctf() -> None:
    """``CTFY`` 必须排在 ``CTF`` 前面，否则被吃掉三个字符后判定失效。"""
    for raw in ("ctfy{...}", "CTFY{xxxx}", "ctfy{<value>}", "ctfy{???}"):
        assert is_placeholder(raw), raw
        assert AutoSubmitter.candidates(f"answer: {raw}") == [], raw


def test_non_ascii_flag_body_is_not_placeholder() -> None:
    """中文体不是符号：判据必须是 Unicode 感知的 ``str.isalnum()``。"""
    assert not is_placeholder("FLAG{测试}")
    assert AutoSubmitter.candidates("answer: FLAG{测试}") == ["FLAG{测试}"]


#: 经典前缀。只用于"镜像里有没有历史示例/诱饵"这一条测试：生产代码不再
#: 枚举前缀（标签式），这里留着是因为它正是那类示例串的写法。
_CLASSIC_LABEL_RE = re.compile(r"(?i)(?:CTFY|FLAG|CTF)\{")


def test_image_source_has_no_extractable_placeholder() -> None:
    """镜像会把这些目录打进去，里面不许出现"经典前缀 + 非模板体"的字面量。

    ``docker/Dockerfile`` 直接 ``COPY src/``，agent 读自己的源码时会把注释里
    的示例当成「检索到的证据」。2026-11-06 的假 solved 就是这么来的。

    ⚠️ 2026-11-12：前缀改成标签式之后，"零命中"不再可维持——源码里的
    f-string（``agent-{name}``）和 LaTeX（``frame_{width}``）与真 flag 同形，
    全仓几十处，形态层无法区分（``div{margin}`` 就是已知代价）。这类误判交给
    平台 verify-answer 预检兜底，见 ``scripts/batch_eval.py``。

    这里保留的是原来**真正在防的那件事**：不许有 ``MetaCTF{...}`` 这种
    "经典前缀 + 看着像真答案"的示例串。``FLAG{...}``（点）这类占位符由
    ``is_placeholder`` 放行——文档里就是靠它说明 flag 形状的；``${x}`` /
    ``{{x}}`` 这类由 ``is_code_template`` 放行。
    """
    from pathlib import Path

    from ctf_strix.flag_extract import FLAG_RE, is_code_template, is_placeholder

    repo = Path(__file__).resolve().parents[1]
    # 与 docker/Dockerfile 的 COPY 清单对齐：src / vendor/src / config / docker。
    roots = [repo / "src", repo / "vendor" / "src", repo / "config", repo / "docker"]
    files = [
        path
        for root in roots
        if root.is_dir()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]
    assert len(files) > 200, f"扫描范围异常，只找到 {len(files)} 个文件"

    offenders: list[str] = []
    scanned = 0
    for path in files:
        data = path.read_bytes()
        if b"\x00" in data:
            # 二进制资源（图片/字体）不是 agent 会当文本读的证据源，跳过。
            continue
        # 解不开就抛异常：``errors="replace"`` 会把非 UTF-8 文件解成乱码，
        # 顺手切断 ASCII flag，测试就假绿了。
        text = data.decode("utf-8")
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), 1):
            # 经典前缀（FLAG / CTF / CTFY）是历史示例与诱饵的写法；标签式
            # 前缀下任意 ``word{var}`` 都会命中，那部分只能靠预检兜底。
            for match in FLAG_RE.finditer(line):
                hit = match.group(0)
                if not _CLASSIC_LABEL_RE.search(hit):
                    continue
                if is_placeholder(hit) or is_code_template(hit):
                    continue
                offenders.append(f"{path}:{lineno}: {hit}")
    assert not offenders, "镜像源码里仍有占位串：\n" + "\n".join(offenders)
    assert scanned > 200, f"实际只扫到 {scanned} 个文本文件，范围不对"
