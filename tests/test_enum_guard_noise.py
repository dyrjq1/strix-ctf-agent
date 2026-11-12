"""结果指纹必须先洗掉传输层噪声，否则守卫生效与否无法区分。

## 这条测试守的是什么

2026-11-01 诊断批 7 道失败题全部"无干预烧完预算"。回放真实轨迹
（`traces/094.json`）才发现：16 次 `exec_command` 的观测指纹 **16 个全不同**，
而它们的响应只差在 `Chunk ID: 6b2fbc` 和 `Wall time: 2.5237 seconds` 这两处
随机串上。指纹建在随机串上 → 每次调用都被判成"有新信息" →
`ENUMERATION GUARD` 与 stall 判据一次都不触发。

这类失效在日志里看不见：没有异常，没有报错，守卫只是"从来不说话"。
所以必须有一条反向用例——用两个只差随机串的响应，断言它们被算成同一个观测。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix.enum_guard import (  # noqa: E402
    EnumerationGuard,
    _is_bundle_read,
    _obs_signature,
)


def _shell_output(chunk_id: str, wall: str, body: str, sandbox: str = "/tmp/sandbox-58695-0") -> str:
    return (
        f"Chunk ID: {chunk_id}\nWall time: {wall} seconds\n"
        f"Process exited with code 0\nOutput:\n{body}\n"
        f"(cwd {sandbox})"
    )


def test_chunk_id_and_wall_time_do_not_create_false_novelty() -> None:
    """只差随机串的两个响应，必须折叠成同一个观测指纹。"""
    a = _shell_output("6b2fbc", "2.5237", "HTTP 403 origin not trusted")
    b = _shell_output("aaa111", "0.9497", "HTTP 403 origin not trusted")
    assert _obs_signature(a, "") == _obs_signature(b, ""), (
        "Chunk ID / Wall time 没有被洗掉——守卫会永远认为每次调用都是新信息"
    )


def test_sandbox_dir_name_does_not_create_false_novelty() -> None:
    """沙箱目录名带 pid，同一响应在不同 session 里也会被算成新观测。"""
    a = _shell_output("abc", "1.0", "same body", sandbox="/tmp/sandbox-52998-0")
    b = _shell_output("abc", "1.0", "same body", sandbox="/tmp/sandbox-58695-0")
    assert _obs_signature(a, "") == _obs_signature(b, "")


def test_different_bodies_still_count_as_new_information() -> None:
    """洗噪声不能洗过头：正文不同仍然必须是新信息（反向对照）。"""
    a = _shell_output("abc", "1.0", "HTTP 403 origin not trusted")
    b = _shell_output("abc", "1.0", "HTTP 200 {\"ok\":true}")
    assert _obs_signature(a, "") != _obs_signature(b, "")


def test_guard_fires_on_repeated_identical_shell_output() -> None:
    """端到端：同一族 3 个不同叶子 + 同响应：先警告，到阈值必须硬停。"""
    # 3 个不同叶子：硬封锁现在要求族内路径多样性 >= 3（同一路径重试只警告）。
    guard = EnumerationGuard()
    hints: list[str] = []
    for i in range(5):
        args = f'curl -s https://x.test/api/widgets/leaf-{i % 3} -H "Origin: null"'
        token = guard.begin("exec_command", args)
        hint = guard.finish(
            token, _shell_output(f"{i:06x}", f"{i}.0", "HTTP 403 origin not trusted")
        )
        if hint:
            hints.append(hint)
    assert any("SAME response" in h for h in hints), (
        f"重复 5 次同响应没有触发警告，实际只有: {hints}"
    )
    assert any("IDENTICAL response" in h for h in hints), (
        f"重复 5 次同响应没有触发硬停，实际只有: {hints}"
    )

# ---------------------------------------------------------------------------
# 2026-11-01 第二轮：回放 7 条失败轨迹后查出两个新的判据失真
# ---------------------------------------------------------------------------


def test_head_digits_do_not_create_false_novelty() -> None:
    """状态行里的耗时/字节数每次不同，不能算成新观测。

    实测 traces/094.json 第 5、6 步：两次探测指向同一族、响应体逐字相同，
    唯一差别是 ``0.11s`` vs ``0.10s``。旧实现只归一化 body，于是判成两个
    新观测，同一族永远凑不满 3 次，ENUMERATION GUARD 一次都没响。
    """
    args = '{"url": "https://x.test/api/widgets", "method": "GET"}'
    a = "[HTTP 403] GET <url> | 0.11s | 41B | application/json\nbody"
    b = "[HTTP 403] GET <url> | 0.94s | 41B | application/json\nbody"
    assert _obs_signature(a, args) == _obs_signature(b, args), (
        "状态行里的数字没有被归一化——同族重复永远数不到阈值"
    )


def test_different_status_codes_are_still_different_observations() -> None:
    """归一化不能抹掉状态码（反向对照）。"""
    args = '{"url": "https://x.test/api/widgets", "method": "GET"}'
    a = "[HTTP 403] GET <url> | 0.11s | 41B\nbody"
    b = "[HTTP 500] GET <url> | 0.11s | 41B\nbody"
    assert _obs_signature(a, args) != _obs_signature(b, args), (
        "403 和 500 被归一成同一个指纹，守卫会把真实状态变化当成重复"
    )


def test_bundle_regex_does_not_fire_on_prose() -> None:
    """英文散文里出现 ``cation ... .js`` 不能算成"在读 bundle"。

    实测 traces/022 第 30 步、traces/028 第 29/30 步：``finish_scan`` 的
    executive_summary 是几千字英文，``cat ... .js`` 命中了
    ``certification walkthrough (...)``，产出假警告。
    """
    prose = (
        '{"executive_summary": "The assessment included a certification '
        'walkthrough covering the client build, and header/cookie probing."}'
    )
    assert not _is_bundle_read(prose), "自由文本被误判成在读前端 bundle"


def test_bundle_regex_does_not_fire_on_script_writing() -> None:
    """``cat > x.py <<'EOF'`` 是写文件，不是读 .js。

    实测 traces/094 第 16 步、traces/096 第 15 步：脚本体里出现 ``.js``
    字样，旧的 _BUNDLE_RE 把"写脚本"判成"又在读前端产物"。
    """
    write = '{"cmd": "cd /tmp && cat > s.py <<\'EOF\'\nimport urllib.request\nctx=x\nEOF"}'
    assert not _is_bundle_read(write), "写脚本被误判成在读前端 bundle"
    write2 = '{"cmd": "cat > wl.txt <<\'EOF\'\npreview\nqueue\nlogin\nEOF"}'
    assert not _is_bundle_read(write2)


def test_bundle_regex_still_fires_on_real_reads() -> None:
    """真正读 .js 仍必须命中（反向对照）。"""
    assert _is_bundle_read('{"cmd": "curl -s https://x.test/_next/static/chunks/app.js"}')
    assert _is_bundle_read('{"cmd": "cd pm && cat BbkGSyGJ.js"}')
    assert _is_bundle_read('{"cmd": "head -c 8000 NXz3x3fk.js"}')


# ---------------------------------------------------------------------------
# 2026-11-12 第三轮：body 数字一刀切抹平的误伤（IDOR/分页/数值盲注）
# ---------------------------------------------------------------------------


def test_numeric_only_body_difference_is_new_information() -> None:
    """只差一个正文的数，必须是新信息。

    旧实现把 body 里所有数字换成 ``#``：IDOR（user 1 的 balance 与
    user 2 的 balance）、分页（每页条目数）、数值盲注（逐字符提取的
    差值）这类真实进展被算成重复，守卫把正在收敛的枚举打断。
    """
    a = '[HTTP 200] GET <url> | 0.11s | 41B\n{"id": 1, "balance": 100}'
    b = '[HTTP 200] GET <url> | 0.11s | 41B\n{"id": 2, "balance": 250}'
    assert _obs_signature(a, "") != _obs_signature(b, ""), (
        "IDOR 的数字差异被抹掉——同一批用户枚举会被判成原地打转"
    )


def test_small_id_difference_is_new_information() -> None:
    """1-3 位数字（枚举 id、条目数）保留原值参与指纹。"""
    a = '[HTTP 200] GET <url> | 0.11s\n{"id": 41, "role": "user"}'
    b = '[HTTP 200] GET <url> | 0.11s\n{"id": 42, "role": "user"}'
    assert _obs_signature(a, "") != _obs_signature(b, "")


def test_epoch_timestamp_jitter_is_not_new_information() -> None:
    """10-13 位 epoch 残片是噪声：同一响应只差时间戳必须折叠。"""
    a = '[HTTP 200] GET <url>\n{"ok": true, "ts": 1731400000}'
    b = '[HTTP 200] GET <url>\n{"ok": true, "ts": 1731400123}'
    assert _obs_signature(a, "") == _obs_signature(b, "")


def test_pid_sized_decimal_jitter_is_not_new_information() -> None:
    """4 位以上十进制串（pid、短随机 id）折叠，不制造假新颖。"""
    a = "[HTTP 200] GET <url>\nref 58695 ok"
    b = "[HTTP 200] GET <url>\nref 52998 ok"
    assert _obs_signature(a, "") == _obs_signature(b, "")


def test_body_duration_jitter_is_not_new_information() -> None:
    """正文里的时长抖动（0.11s vs 0.94s）不算新信息。"""
    a = "[HTTP 200] GET <url>\nquery ok elapsed 0.11s rows 3"
    b = "[HTTP 200] GET <url>\nquery ok elapsed 0.94s rows 3"
    assert _obs_signature(a, "") == _obs_signature(b, "")


def test_body_size_jitter_is_not_new_information() -> None:
    """正文里的大小抖动（41B vs 42B）不算新信息。"""
    a = "[HTTP 200] GET <url>\nfile dumped 41B"
    b = "[HTTP 200] GET <url>\nfile dumped 42B"
    assert _obs_signature(a, "") == _obs_signature(b, "")
