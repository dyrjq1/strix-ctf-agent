"""C1 证据保留型封顶的行为契约。

为什么这些用例存在：截断是「省 token」和「丢精度」的交换。这里锁死三件事——

1. 被折叠掉的中段里的证据（Set-Cookie / Location / 标识符 / 路径）必须
   出现在证据块里，一个不丢；
2. 证据块是整段原文的纯函数：二次截断输出逐字节一致，位置无关；
3. 没有证据的纯文本响应，行为与加证据块之前完全一致（零回归）。

证据值全是合成 fixture，不是任何真实题目/平台的样例。
"""

from __future__ import annotations

import asyncio
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import context as ctx_mod  # noqa: E402
from ctf_strix import llm_telemetry  # noqa: E402
from ctf_strix import usage_meter  # noqa: E402

COOKIE = "sid=8f14e45fceea167a5a36dedd4bea2543; Path=/; HttpOnly"
TOKEN = "tok_9d3f8a2c1b"
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
HEX64 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiJ9.c2lnbmF0dXJlLXZhbHVl"
PATH = "/admin/panel.php"
ASSET = "/static/app.js"


def _pair(call_id: str, name: str, args: str, output: str) -> list[dict]:
    return [
        {"type": "function_call", "call_id": call_id, "name": name, "arguments": args},
        {"type": "function_call_output", "call_id": call_id, "output": output},
    ]


def _big_payload() -> str:
    """10k 响应：证据埋在会被折叠掉的中段，头尾只有填充。"""
    middle = (
        "HTTP/1.1 302 Found\n"
        f"Set-Cookie: {COOKIE}\n"
        f"Location: {PATH}\n"
        "Allow: GET, POST\n"
        'WWW-Authenticate: Basic realm="x"\n'
        "Content-Type: text/html; charset=utf-8\n"
        f'<a href="{PATH}">next</a>\n'
        f'<script src="{ASSET}"></script>\n'
        f'<form action="{PATH}?step=2" method="post"></form>\n'
        + json.dumps({"token": TOKEN, "uuid": UUID, "hash": HEX64, "jwt": JWT})
    )
    return "A" * 6_000 + "\n" + middle + "\n" + "B" * 4_000


def _capper(**kwargs) -> ctx_mod.HistoryCapper:
    params = {"cap_chars": 2_000, "head": 1_200, "tail": 600, "arg_cap": 0}
    params.update(kwargs)
    return ctx_mod.HistoryCapper(**params)


def test_capped_output_keeps_all_evidence():
    """证据保留率 100%：中段被折叠，证据块仍逐条命中。"""
    text = _big_payload()
    assert len(text) > 10_000

    out, saved = _capper().apply(_pair("c1", "http_probe", "{}", text))
    capped = out[1]["output"]

    assert saved > 0
    assert ctx_mod._EVIDENCE_MARK in capped
    block = capped[capped.index(ctx_mod._EVIDENCE_MARK) :]
    for value in (COOKIE, TOKEN, UUID, HEX64, JWT, PATH, ASSET):
        assert value in block, value
    # 证据不在头/尾的保留窗口里，只能来自证据块。
    assert COOKIE not in capped[: capped.index(ctx_mod._EVIDENCE_MARK)]


def test_evidence_block_is_idempotent():
    """同一输出二次截断：输出与证据块内容/顺序完全一致。"""
    text = _big_payload()
    items = _pair("c1", "http_probe", "{}", text)

    once, _ = _capper().apply(items)
    twice, saved_twice = _capper().apply(once)

    assert saved_twice == 0
    assert twice == once
    assert once[1]["output"].count(ctx_mod._EVIDENCE_MARK) == 1
    assert ctx_mod._evidence_lines(text) == ctx_mod._evidence_lines(text)
    block_once = once[1]["output"][once[1]["output"].index("\n" + ctx_mod._EVIDENCE_MARK) :]
    # 证据只从中段抽：比较时用同一组排除窗口（请求的 head/tail）。
    assert block_once == ctx_mod._evidence_block(text, skip_head=1_200, skip_tail=600)


def test_plain_text_has_no_evidence_and_behaves_as_before():
    """无证据可抽：纯文本响应 → 证据块为空、无异常、与旧行为逐字节一致。"""
    plain = "lorem ipsum dolor sit amet\n" * 800
    assert ctx_mod._evidence_lines(plain) == []

    with_flag, _ = _capper().apply(_pair("c1", "exec_command", "{}", plain))
    legacy = ctx_mod._cap_text(plain, limit=2_000, head=1_200, tail=600, evidence=False)

    assert ctx_mod._EVIDENCE_MARK not in with_flag[1]["output"]
    assert with_flag[1]["output"] == legacy


def test_evidence_block_respects_char_cap():
    """块 ≤800 字符：大量不同 cookie 也不会把截断变成没截断。"""
    text = "\n".join(f"Set-Cookie: s{i:03d}={'a' * 40}; Path=/" for i in range(200))
    block = ctx_mod._evidence_block(text)

    assert block
    assert len(block) <= ctx_mod._EVIDENCE_MAX_CHARS
    assert block.startswith("\n" + ctx_mod._EVIDENCE_MARK + "\n")


def test_evidence_block_is_position_independent():
    """同一条输出放在历史第 1 位和第 101 位，结果完全一致。"""
    target = _pair("target", "http_probe", "{}", _big_payload())
    alone, _ = _capper().apply(target)

    buried: list[dict] = []
    for i in range(100):
        buried += _pair(f"pad{i}", "exec_command", '{"cmd":"ls"}', "ok")
    buried += target

    out, _ = _capper().apply(buried)
    assert out[-2:] == alone


def _usage(input_tokens: int, cached: int) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        input_tokens=input_tokens,
        output_tokens=10,
        total_tokens=input_tokens + 10,
        input_tokens_details=types.SimpleNamespace(
            cached_tokens=cached, cache_write_tokens=0
        ),
    )


def _three_turn_run(evidence: bool, trace: Path):
    """3 轮合成 run：计数器与真实 C8 钩子/落盘路径，不用假 JSON。"""
    from strix.core import hooks as strix_hooks

    capper = _capper(evidence=evidence)
    hook = strix_hooks.ReportUsageHooks(model="test-model")
    ctx = types.SimpleNamespace(context={"agent_id": "root"})
    items: list[dict] = []
    prev = ""
    prev_texts: list[str] = []
    hits: list[float] = []

    async def go() -> None:
        nonlocal prev, prev_texts
        for turn in range(1, 4):
            if turn == 1:
                items.extend(_pair("c1", "http_probe", "{}", _big_payload()))
            else:
                items.extend(_pair(f"c{turn}", "http_probe", "{}", f"ok-{turn}"))
            await strix_hooks.ReportUsageHooks.on_llm_start(
                hook, ctx, None, "system", list(items)
            )
            capped, _ = capper.apply(items)
            texts = [ctx_mod._text_of(i) for i in capped]
            # 真正的漂移断言（P1-6）：上一轮每条 capped 文本必须逐字节不变。
            assert texts[: len(prev_texts)] == prev_texts, f"prefix drifted at turn {turn}"
            prev_texts = texts
            prompt = "system\x1e" + "\x1e".join(texts)
            common = 0
            if prev:
                assert prompt.startswith(prev), f"prefix drifted at turn {turn}"
                for left, right in zip(prev, prompt):
                    if left != right:
                        break
                    common += 1
            input_tokens = max(1, len(prompt) // 4)
            cache_read = common // 4
            hits.append(round(cache_read / input_tokens, 4))
            await strix_hooks.ReportUsageHooks.on_llm_end(
                hook, ctx, None, types.SimpleNamespace(usage=_usage(input_tokens, cache_read))
            )
            prev = prompt

    asyncio.run(go())
    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    return hits, rows


def test_three_turn_synthetic_run_hit_rate_not_below_baseline(tmp_path, monkeypatch):
    """C8 遥测：证据块不破坏前缀 → hit_rate 不低于无证据臂；
    first_capped_index / capped_hash 仍能正确指认被改写的历史条。"""
    usage_meter.install()
    try:
        base_trace = tmp_path / "base.jsonl"
        new_trace = tmp_path / "evidence.jsonl"

        monkeypatch.setenv(llm_telemetry.ENV_PATH, str(base_trace))
        base_hits, base_rows = _three_turn_run(evidence=False, trace=base_trace)

        monkeypatch.setenv(llm_telemetry.ENV_PATH, str(new_trace))
        new_hits, new_rows = _three_turn_run(evidence=True, trace=new_trace)
    finally:
        usage_meter.reset_for_tests()

    assert len(base_rows) == len(new_rows) == 3
    # 注意：这条 hit_rate 比较是**遥测链路检查**（读到的 cache_read/input_tokens
    # 有没有被写反/写错），不是漂移检测器——只要 prompt 前缀成立，加大前缀常量
    # 在数学上恒满足 >= 基线。真正的漂移断言在 _three_turn_run 的 texts 比较里。
    for turn in (1, 2):
        assert new_hits[turn] >= base_hits[turn] - 1e-9, (new_hits, base_hits)
    assert new_hits[2] > 0.9

    for row in new_rows:
        assert row["capped_items"] == 1
        assert row["evidence_items"] == 1  # P1-3：真的落盘，不只是 LAST_CAP_STATS
        assert row["first_capped_index"] == 1  # function_call_output 在第 2 条
        assert row["capped_hash"]
        assert row["hit_rate"] == new_hits[row["turn"] - 1]
    for row in base_rows:
        assert row["evidence_items"] == 0


def test_hex_evidence_cannot_crowd_out_headers():
    """P1-1 回归：md5×25 + sha256×11 不得把 cookie/location 挤出块。

    hex 是低优先级：只能吃剩余预算且总长 ≤200 字符（800 的 25%）。
    """
    md5s = [f"{i:032x}" for i in range(1, 26)]
    sha = [f"{i:064x}" for i in range(100, 111)]
    text = "\n".join(sha + md5s) + (
        "\nSet-Cookie: SID=deadbeefcafebabe0123456789abcdef; Path=/; HttpOnly"
        f"\nLocation: {PATH}\n"
    )
    block = ctx_mod._evidence_block(text)

    assert "deadbeefcafebabe0123456789abcdef" in block
    assert PATH in block
    low = [line for line in block.splitlines() if line.startswith(("hex:", "id:"))]
    assert sum(len(line) + 1 for line in low) <= ctx_mod._EVIDENCE_LOW_PRIORITY_CHARS


def test_head_window_content_is_not_repeated_in_block():
    """P1-2：头窗口里的 cookie 不再重复进块；中段隐藏 token 仍被抽出。"""
    text = (
        "x" * 1_000
        + f"\nSet-Cookie: {COOKIE}\n"
        + "y" * 5_000
        + f"\nhidden_token={TOKEN}\n"
        + "z" * 2_000
    )
    out, _ = _capper(cap_chars=8_000, head=1_200, tail=600).apply(
        _pair("c1", "http_probe", "{}", text)
    )
    capped = out[1]["output"]
    block = capped[capped.index(ctx_mod._EVIDENCE_MARK) :]

    assert not [line for line in block.splitlines() if "8f14e45fceea167a5a36dedd4bea2543" in line]
    assert TOKEN in block


def test_small_limits_never_exceed_limit():
    """P1-4：limit 四档都必须满足 len(out) <= limit（旧公式在 500 时输出 555）。"""
    text = _big_payload()
    for limit in (500, 800, 2_000, 8_000):
        out = ctx_mod._cap_text(text, limit=limit, head=1_200, tail=600, evidence=True)
        assert len(out) <= limit, (limit, len(out))
        assert ctx_mod._EVIDENCE_MARK in out


def test_kv_boundary_catches_session_token_and_phpsessid():
    """P1-5：`session_token=` / `PHPSESSID=` 命中，`mytoken=` 仍不命中。"""
    rendered = "\n".join(
        ctx_mod._evidence_lines(
            "session_token=abcdef123456\nPHPSESSID=fedcba654321\nsession_id=123456abcdef"
        )
    )
    assert "session_token: abcdef123456" in rendered
    assert "phpsessid: fedcba654321" in rendered
    assert "session_id: 123456abcdef" in rendered
    assert ctx_mod._evidence_lines("mytoken=abcdef123456") == []


def test_leading_evidence_mark_is_not_counted_as_new_block():
    """P2-1：输入本身以 [evidence block] 开头时，evidence_items 必须是 0。"""
    text = ctx_mod._EVIDENCE_MARK + "\n" + "q" * 9_000
    capper = _capper()
    out, saved = capper.apply(_pair("c1", "http_probe", "{}", text))

    assert saved > 0
    assert out[1]["output"].count(ctx_mod._EVIDENCE_MARK) == 1
    stats = ctx_mod.LAST_CAP_STATS.get()
    assert stats is not None and stats["evidence_items"] == 0


def test_http_status_line_is_collected():
    """P2-3：`HTTP/1.1 302 Found` 状态行进块；`javascript:` 仍不算路径。"""
    lines = ctx_mod._evidence_lines(
        'HTTP/1.1 302 Found\nLocation: /next\n<a href="javascript:void(0)">x</a>\n'
    )
    assert "status: HTTP/1.1 302 Found" in lines
    assert not [line for line in lines if "javascript" in line]


def test_telemetry_records_evidence_items(tmp_path, monkeypatch):
    """P1-3：evidence_items 真的落进 JSONL（stats 通道），默认 0。"""
    usage_meter.install()
    try:
        trace = tmp_path / "evidence_items.jsonl"
        monkeypatch.setenv(llm_telemetry.ENV_PATH, str(trace))
        _three_turn_run(evidence=True, trace=trace)
    finally:
        usage_meter.reset_for_tests()

    rows = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assert [row["evidence_items"] for row in rows] == [1, 1, 1]
    assert all("evidence_items" in row for row in rows)


def test_ledger_phase2_anchor_is_unique():
    """台账 §4.83/§4.84 锚点唯一：追加位置不会落到重复标题里。"""
    ledger = ROOT / "docs" / "11-实验台账.md"
    text = ledger.read_text(encoding="utf-8")
    assert text.count("### 4.83 ") == 1
    assert text.count("### 4.84 Phase 2") == 1
