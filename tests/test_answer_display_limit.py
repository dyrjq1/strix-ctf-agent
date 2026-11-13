"""答案不能死在日志截断上。

背景：``run.log`` 里工具参数默认只打 400 字符（为了可读）。但 QA / 选择题
的答案是一行 ``ANSWER[<qid>]=<value>``，模型常常把它写在 ``finish_scan``
的摘要末尾——摘要前 300 字符全是解释，标记正好被切在边界上，父进程
提取不到值，「答对」在账本里记成「没作答」。

这里测的是判据本身：带 flag 或带答案标记的参数不截断，其余照旧。
同时测「不该扩容的时候不扩容」——否则每条工具调用都变成 4000 字符，
日志失去可读性这一初衷。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

import run_strix_ctf  # noqa: E402


def test_answer_marker_keeps_the_argument_whole() -> None:
    text = "解释" * 200 + "\nANSWER[answer]=D"
    assert run_strix_ctf._arg_display_limit(text) == 4000


def test_flag_keeps_the_argument_whole() -> None:
    assert run_strix_ctf._arg_display_limit("x" * 1000 + " FLAG{abc}") == 4000


def test_plain_argument_keeps_the_readable_cap() -> None:
    assert run_strix_ctf._arg_display_limit("curl -s http://x/") == 400


def test_empty_argument_is_harmless() -> None:
    assert run_strix_ctf._arg_display_limit("") == 400


def test_lookalike_words_do_not_expand_the_cap() -> None:
    """``ANSwer`` / 无方括号的 ``ANSWER=`` 不算标记，别让日志被误扩。"""
    assert run_strix_ctf._arg_display_limit("ANSWER=D") == 400
    assert run_strix_ctf._arg_display_limit("answer[1]=D") == 400