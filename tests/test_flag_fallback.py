"""回归：解出来了却判 FAIL。

2026-10-30 009 复跑的日志里，host 写在 `cat > /tmp/ev.py <<'EOF'` 这一段，
flag 出现在**几轮之后** `python3 /tmp/ev.py` 的输出里。实测那份真实日志：
最近一次 host 出现在第 8271 字符，第一个 flag 在第 16749 字符（差 8478），
主判据因此判"无证据"，`flags_found` 为空 —— agent 解对了，账本记 0。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix.flag_extract import best_flag, fallback_flag  # noqa: E402

HOST = "smsqtgst3y2hdk3dd.node2.ctfy.run"
FLAG = "FLAG{8000c9960d30949816202811fc1a3678}"

#: 把 host 与 flag 之间的跨度撑到 2000 字符以上，否则复现不出误判。
FILLER = "\n".join(
    "--- probe result: no signal here (padding line %03d)" % i for i in range(90)
)

_HEAD = (
    '  [aaaa1111] TOOL exec_command {"cmd": "cat > /tmp/ev.py <<\'EOF\'\\n'
    'import requests\\nB=\\"https://' + HOST + '/api/plugins/preview\\"\\nEOF"}\n'
    "  [aaaa1111] OUT  Chunk ID: 3bd516\nOutput:\n"
)
_MIDDLE = (
    '  [aaaa1111] TOOL exec_command {"cmd": "cd /tmp; for c in ...; do echo $c; done"}\n'
    "  [aaaa1111] OUT  Chunk ID: 6be692\nOutput:\n"
    "--- return typeof require => (200, '{\"ok\":true,\"preview\":\"function\"}')\n"
)
_TAIL = (
    '  [aaaa1111] TOOL exec_command {"cmd": "cd /tmp; '
    'printf %s \\"return require(\'fs\').readFileSync(\'/flag\')\\" | python3 /tmp/ev.py"}\n'
    "  [aaaa1111] OUT  Chunk ID: abf761\nOutput:\n"
    "(200, '{\"ok\":true,\"preview\":\"" + FLAG + "\"}')\n"
)
LOG = _HEAD + _MIDDLE + FILLER + "\n" + _TAIL


def test_main_rule_misses_this_shape():
    """先承认现状：主判据在这种形态下确实挑不出来（否则这条回归没有意义）。"""
    assert best_flag(LOG, HOST) is None


def test_fallback_recovers_the_real_solve():
    assert fallback_flag(LOG, HOST) == FLAG


def test_fallback_is_off_when_several_flags_exist():
    """多 flag 就意味着可能有诱饵，兜底必须让位给主判据。"""
    noisy = LOG + "\nFLAG{deadbeefdeadbeefdeadbeefdeadbeef}\n"
    assert fallback_flag(noisy, HOST) is None


def test_fallback_rejects_stale_recon_target():
    """残留文件自称的靶机不是本题时，唯一候选也不能交。"""
    stale = (
        '  [bbbb2222] TOOL exec_command {"cmd": "cat ctf_recon.md"}\n'
        "  [bbbb2222] OUT  # CTF Recon — https://other-host.node1.ctfy.run/\n"
        + FLAG + "\n"
    )
    assert fallback_flag(stale, HOST) is None


def test_fallback_ignores_placeholders():
    log = LOG + "\nFLAG{...}\n"
    assert fallback_flag(log, HOST) == FLAG


def test_placeholders_never_become_candidates():
    """2026-11-06 v6 冒烟：镜像源码注释里的 ``FLAG{xxxx}`` 被当成检索到的证据。

    占位符必须在抽取层就丢掉。只要它活到 ``EvidenceLedger.supports()``，
    「读自己的源码」就会把一道不可能解出的题判成 solved。

    ``own_host`` 传空串是关键：带 host 的文本会先被「靶机不在附近」淘汰，
    那样这条用例无论修没修都通过，等于什么都没测。
    """
    text = "  [cccc3333] OUT  模板占位符（``FLAG{...}`` / ``FLAG{xxxx}``）\n"
    assert best_flag(text, "") is None
    assert fallback_flag(text, "") is None


def test_placeholder_shapes_are_shared_with_finish_guard():
    """占位符只允许有一套定义，抽取层与收工守卫必须同口径。"""
    from ctf_strix.flag_extract import is_placeholder

    for flag in ("FLAG{...}", "FLAG{xxxx}", "flag{XXXX}", "CTF{XxX}"):
        assert is_placeholder(flag), flag
    for flag in ("FLAG{0123456789abcdef}", "ctfy{x_y-z}"):
        assert not is_placeholder(flag), flag


def test_placeholder_does_not_mask_a_real_flag():
    """同一段输出里既有占位符又有真 flag 时，真 flag 必须照常交付。"""
    text = f"{HOST}\nplaceholder: FLAG{{xxxx}}\nreal: {FLAG}\n"
    assert best_flag(text, HOST) == FLAG
