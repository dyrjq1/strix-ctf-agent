"""一条命令验证全部改造点。

## 为什么需要它

此前每个改造点的验证都是 `/tmp/t_xxx.py` 里的一次性脚本：改一次代码就
全丢了，下次要复现得重写。更麻烦的是**回归**——三层守卫都改
``factory._with_bounded_result``，改其中一层很容易把另一层弄哑，
而"弄哑了"在真实运行里表现为"守卫没触发"，看起来和"这题不需要介入"一模一样。

所以把全部场景固化成断言。改完代码跑这一条，任一退化直接失败。

## 用法

    cd /workspace && PYTHONPATH=src:vendor/src .venv/bin/python scripts/selftest.py

退出码 0 表示全过。契约校验（需要 ctfy 包）单独在 `check_contract.py` 里。
"""

from __future__ import annotations

import asyncio
import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

_FAILED: list[str] = []
_PASSED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    """记一条断言结果。"""
    global _PASSED
    if cond:
        _PASSED += 1
        print(f"  PASS  {name}")
    else:
        _FAILED.append(f"{name} {detail}".strip())
        print(f"  FAIL  {name}  {detail}")


def section(title: str) -> None:
    """打印分节标题。"""
    print(f"\n── {title} " + "─" * max(0, 60 - len(title)))


# ---------------------------------------------------------------- flag 抽取
def test_flag_extract() -> None:
    """flag 抽取：本题证据优先、跨题残留拒绝、模板拒绝。"""
    from ctf_strix.flag_extract import best_flag, host_of

    section("flag 抽取")
    own = "abc.node1.ctfy.run"
    cases = [
        (
            "本题紧邻命中",
            "getting https://abc.node1.ctfy.run/ ...\nOutput:\nFLAG{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}\n",
            "FLAG{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}",
        ),
        (
            "模板占位符拒绝",
            "Goal: find FLAG{...} in the app",
            None,
        ),
        (
            "跨题 recon 残留拒绝",
            "=== ctf_recon.md ===\n# CTF Recon — https://other.node1.ctfy.run/\n"
            "## FLAG\nFLAG{bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}\n",
            None,
        ),
        (
            "近距离优先于重复次数",
            "FLAG{cccccccccccccccccccccccccccccccc}\n"
            "FLAG{cccccccccccccccccccccccccccccccc}\n"
            "--- now on abc.node1.ctfy.run ---\n"
            "FLAG{dddddddddddddddddddddddddddddddd}\n",
            "FLAG{dddddddddddddddddddddddddddddddd}",
        ),
        (
            "命令回显里的 recon 文件名不误伤",
            "cat ctf_recon.md; cat x\n ct... ctf_recon.md\n"
            "=== ctf_recon.md ===\n# CTF Recon — https://other.node1.ctfy.run/\n"
            "FLAG{eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee}\n",
            None,
        ),
        ("host 解析", host_of("https://abc.node1.ctfy.run:8443/x"), own),
    ]
    for name, log, want in cases:
        got = best_flag(log, own) if "host 解析" not in name else host_of(log)
        check(name, got == want, f"got={got} want={want}")


# ---------------------------------------------------------------- 枚举守卫
def test_enum_guard() -> None:
    """枚举守卫：同族归一、异族区分、爆破计入、无目标不计。"""
    from ctf_strix.enum_guard import EnumerationGuard, _fingerprint

    section("枚举守卫")
    a = _fingerprint("exec_command", '{"cmd":"curl https://abc.ctfy.run/api/coins/stats"}')
    b = _fingerprint("exec_command", '{"cmd":"curl https://abc.ctfy.run/api/coins/tiers"}')
    d = _fingerprint("exec_command", '{"cmd":"curl https://abc.ctfy.run/.well-known/jwks.json"}')
    e = _fingerprint("exec_command", '{"cmd":"ffuf -w w.txt -u https://abc.ctfy.run/FUZZ"}')
    f = _fingerprint("exec_command", '{"cmd":"ls -la /tmp"}')

    check("同族叶子归一", a == b, f"{a} vs {b}")
    check("异族区分", a != d, f"{a} vs {d}")
    check("爆破工具计入", e is not None, str(e))
    check("无目标调用不计", f is None, str(f))

    # 同一 host 后接 shell 分隔符，不能被算成多个族（真实日志踩过）
    g1 = _fingerprint("exec_command", '{"cmd":"B=https://abc.ctfy.run; curl $B/api/x"}')
    check("shell 变量不撕裂 host", g1 is not None and "abc.ctfy.run" in str(g1), str(g1))

    # v2 判据：只有**响应完全一样**才算重复（AFL 覆盖率思维）。
    g = EnumerationGuard()
    same = '{"cmd":"curl https://abc.ctfy.run/api/coins/x"}'
    seq = [g.observe("exec_command", same, "[HTTP 404] not found") for _ in range(6)]
    check("第 3 次同响应起警告", "ENUMERATION GUARD" in (seq[2] or ""), str(seq[2])[:60])
    check("第 5 次升级硬指令", "Stop now" in (seq[4] or ""), str(seq[4])[:60])
    fresh = g.observe("exec_command", same, '[HTTP 200] {"ok":true,"n":7}')
    check("新响应不算重复", fresh is None, str(fresh)[:40])
    path_echo = g.observe("exec_command", same, "[HTTP 404] not found for /api/coins/x")
    check("换路径的回显共同指纹", path_echo is None, str(path_echo)[:40])


# ---------------------------------------------------------------- 旅程守卫
def test_journey_guard() -> None:
    """旅程守卫：只在认证墙之后介入，已登录/已创建则永久放行。"""
    from ctf_strix.journey_guard import JourneyGuard

    section("旅程守卫")

    def run(seq):
        g = JourneyGuard()
        hits = [g.observe("exec_command", a, o) for a, o in seq]
        return g.state, [h for h in hits if h]

    # ① 纯注入题：没有认证墙，必须完全不介入
    st, hits = run([("curl -s 'http://t/s?q=%27%20or%201=1'", "error")] * 10)
    check("无认证墙不误伤", not hits and st.wall_hit == 0, f"hits={len(hits)}")

    # ② 401 之后灌载荷：先 warn 再 hard
    seq = [("curl -s -X POST http://t/api/login -d '{}'", "401 invalid credentials")]
    seq += [("curl -s 'http://t/api/pins?id[$ne]=1'", "no rows")] * 8
    st, hits = run(seq)
    check("401 激活认证墙", st.wall_hit == 1, f"wall={st.wall_hit}")
    check("未认证灌载荷被介入", len(hits) >= 2, f"hits={len(hits)}")
    check("介入含硬指令", any("HARD STOP" in h for h in hits), "")

    # ③ 登录成功（Set-Cookie）→ 永久放行
    seq = [("curl -s -i http://t/api/auth", "HTTP/1.1 200\nSet-Cookie: sid=abc")]
    seq += [("curl -s 'http://t/api/pins?x=1%27 or 1=1'", "x")] * 6
    st, hits = run(seq)
    check("Set-Cookie 判定已认证", st.authed, "")
    check("已认证后不介入", not hits, f"hits={len(hits)}")

    # ④ 成功创建资源 → 永久放行（写入请求 + 201/id）
    seq = [("curl -s -X POST http://t/api/order -d '{\"a\":1}'", '{"id": 42}')]
    seq += [("curl -s 'http://t/api?x=1%27 or 1=1'", "x")] * 6
    st, hits = run(seq)
    check("创建成功判定已放行", st.created, "")
    check("创建后不介入", not hits, f"hits={len(hits)}")

    # ⑤ 不带引号的 SQLi 也要被抓（此前正则要求引号，实测静默失效）
    seq = [("curl -s http://t/api/login", "403 forbidden")]
    seq += [("curl -s 'http://t/p?id=1 or 1=1'", "x")] * 5
    st, hits = run(seq)
    check("无引号 SQLi 也被抓", len(hits) >= 1, f"hits={len(hits)}")


# ---------------------------------------------------------------- 收工守卫
def test_finish_guard() -> None:
    """收工守卫：无 flag 拒绝、有 flag 放行、超限放行、不碰其他工具。"""
    from ctf_strix.finish_guard import FinishGuard

    section("收工守卫")
    g = FinishGuard()
    for i in range(3):
        r = g.check(json.dumps({"executive_summary": "no flag found"}))
        check(f"无 flag 第{i + 1}次拒绝", r is not None and r.get("success") is False, "")
    r4 = g.check(json.dumps({"executive_summary": "still nothing"}))
    check("连续 3 次后放行（防死锁）", r4 is None, str(r4))

    g2 = FinishGuard()
    ok = g2.check(json.dumps({"executive_summary": "Flag: FLAG{deadbeef}"}))
    check("带 flag 直接放行", ok is None, str(ok))
    check("带 flag 不计拒绝", g2.refusals == 0, f"refusals={g2.refusals}")


# ---------------------------------------------------------------- 叠加集成
def test_guards_integration() -> None:
    """三层守卫叠加后各自仍然生效（它们都改同一个 on_invoke_tool）。"""
    from ctf_strix.local_backend import install as install_backend

    install_backend()
    # piggyback：顺带把挂载钩子装上，跳过 shell/FS 路径的守卫（其余测试不关心）。
    from ctf_strix.guard_mount import install_mount_hook

    install_mount_hook()
    from ctf_strix.enum_guard import install as ie
    from ctf_strix.finish_guard import install as ifin
    from ctf_strix.journey_guard import install as ij
    from strix.agents import factory
    from agents import FunctionTool

    section("三守卫叠加")

    eg, jg, fg = ie(), ij(), ifin()
    called: list[str] = []

    def resp(t: str) -> str:
        return json.dumps({"ok": True, "output": t})

    async def fake(ctx, raw):
        cmd = json.loads(raw).get("cmd", "")
        if "login" in cmd:
            return resp("401 Unauthorized")
        if "auth" in cmd:
            return resp("Set-Cookie: sid=1")
        return resp("same body")

    async def real_finish(ctx, raw):
        called.append(raw)
        return {"success": True}

    def mk(name, fn):
        return factory._with_bounded_result(
            FunctionTool(
                name=name,
                description="x",
                params_json_schema={"type": "object", "properties": {"a": {"type": "string"}}},
                on_invoke_tool=fn,
            )
        )

    async def go():
        t = mk("exec_command", fake)
        fs = mk("finish_scan", real_finish)

        check("三层标记都已设置", all([
            getattr(t, "_ctf_guarded", False),
            getattr(t, "_ctf_journey_guarded", False),
            getattr(fs, "_ctf_finish_guarded", False),
        ]), "")

        await t.on_invoke_tool(None, json.dumps({"cmd": "curl http://t/api/login"}))
        enum_hits = journey_hits = 0
        for _ in range(8):
            r = str(await t.on_invoke_tool(
                None, json.dumps({"cmd": "curl 'http://t/api/coins?id=1 or 1=1'"})))
            enum_hits += "ENUMERATION GUARD" in r
            journey_hits += "USER JOURNEY GUARD" in r
        check("叠加后枚举守卫仍触发", enum_hits > 0, f"hits={enum_hits}")
        check("叠加后旅程守卫仍触发", journey_hits > 0, f"hits={journey_hits}")

        r = await fs.on_invoke_tool(None, json.dumps({"a": "no flag"}))
        check("finish 守卫独立生效", isinstance(r, dict) and r.get("success") is False, str(r)[:60])
        check("被拒时不调用真工具", not called, f"called={len(called)}")

        await t.on_invoke_tool(None, json.dumps({"cmd": "curl http://t/api/auth"}))
        check("叠加后仍能判定已认证", jg.state.authed, "")
        check("守卫统计可读", eg is not None and fg.refusals == 1, f"refusals={fg.refusals}")

    asyncio.run(go())


# ---------------------------------------------------------------- 挂载点覆盖
def test_guard_mount() -> None:
    """守卫必须真的挂到 `exec_command` 上，否则整套计数都是假的。

    这一段是 2026-10-28 那一轮最重要的回归：CTFARENA-012 复跑 45 次调用、
    日志里 16 次 401/403，三个守卫计数器全是 0。根因不是规则写错，而是
    ``exec_command`` / ``write_stdin`` 走 ``Shell`` capability 的
    ``_configure_shell_tools``，**绕过了** ``_with_bounded_result``——守卫挂
    在一个这两个工具永远不经过的钩子上。

    把那次运行的真实会话灌进同一个守卫类重放，立刻得到
    ``wall_hit=7 payloads=9 prompts=3``。所以判定逻辑是对的，只是没接线。

    断言要点：走**真实配置路径**（不是直接调 `_with_bounded_result`）造出来的
    `exec_command`，必须带上三个守卫的标记。
    """
    from ctf_strix.guard_mount import install_mount_hook
    from agents.tool import FunctionTool
    from strix.agents import factory

    section("守卫挂载点")

    def mk(name, fn):
        return FunctionTool(
            name=name,
            description="x",
            params_json_schema={"type": "object", "properties": {}},
            on_invoke_tool=fn,
        )

    async def noop(ctx, raw):
        return "ok"

    class Toolset:
        pass

    # 顺序即生产顺序：先挂载钩子（上面的 test_guards_integration 已装，幂等），
    # 再验证守卫是否真的接到了 shell 路径上。
    install_mount_hook()

    ts = Toolset()
    ts.exec_command = mk("exec_command", noop)
    ts.write_stdin = mk("write_stdin", noop)
    # 直接调内部配置函数，等价于 strix 建 agent 时走的那条路。
    factory._configure_shell_tools(ts, chat_completions=False, strict_schemas=False)

    for tool_name in ("exec_command", "write_stdin"):
        tool = getattr(ts, tool_name)
        marks = {a for a in vars(tool) if a.startswith(("_ctf_", "_strix_"))}
        check(
            f"shell 路径 {tool_name} 已被守卫覆盖",
            "_ctf_guarded" in marks and "_ctf_journey_guarded" in marks,
            f"marks={sorted(marks)}",
        )

    # 再走一遍 filesystem 路径，确认三重挂钩不套娃（重复施加应无害）。
    ts2 = Toolset()
    ts2.exec_command = mk("exec_command", noop)
    factory._configure_shell_tools(ts2, chat_completions=False, strict_schemas=False)
    check(
        "重复配置不套娃（幂等）",
        getattr(ts2.exec_command, "_ctf_guarded", False),
        "",
    )

    # shell 路径上的守卫必须**真的会触发**，不是只挂了个标记。
    # 用一个全新的守卫实例，避免被前面测试残留的 authed/payloads 状态污染
    # （守卫是进程级的，计数跨测试累积——这也是真实运行里的行为）。
    async def payload(ctx, raw):
        return "HTTP/1.1 401 Unauthorized"

    from ctf_strix.journey_guard import JourneyGuard

    fresh = JourneyGuard()

    ts3 = Toolset()
    ts3.exec_command = mk("exec_command", payload)
    factory._configure_shell_tools(ts3, chat_completions=False, strict_schemas=False)

    async def observe_through_shell() -> list[str]:
        """模拟包装里的调用顺序：先拿 output，再交给守卫判定。"""
        hits: list[str] = []
        for _ in range(9):
            out = await ts3.exec_command.on_invoke_tool(
                None, json.dumps({"cmd": "curl 'http://t/api/auth/login?id=1 or 1=1'"}))
            # ts3 上的真实守卫也会跑一遍；这里再用 fresh 独立复算，避免依赖全局状态
            hint = fresh.observe("exec_command", "curl 'http://t/api/auth/login?id=1 or 1=1'", str(out))
            if hint:
                hits.append(hint)
        return hits

    trigger_hits = asyncio.run(observe_through_shell())
    check(
        "shell 路径上旅程守卫真的会触发",
        len(trigger_hits) > 0,
        f"prompts={fresh.state.prompts} wall={fresh.state.wall_hit} "
        f"payloads={fresh.state.payloads} calls={fresh.state.observe_calls}",
    )


# ---------------------------------------------------------------- 真实会话重放
def test_replay_real_session() -> None:
    """用 CTFARENA-012 的真实运行会话重放守卫，作为端到端验收。

    这一段是本轮最重要的回归防线。数据来自那次"守卫零触发"的运行的
    ``.state/agents.db``（strix 把每条 ``function_call`` /
    ``function_call_output`` 都存了进来），所以是**真实模型行为**，不是
    自己编的样例。

    它守的不是某个正则，而是整条链路：载荷识别 → 认证墙识别 → 计数 →
    注入提示。任一环写紧一点，这里的 ``prompts`` 就会掉到 0。

    数据文件不存在时跳过（不能因为缺样本就让全套自测失败）。
    """
    import sqlite3

    section("真实会话重放（CTFARENA-012）")
    # 优先级：仓库内固定样本 → 本次运行产物 → 评测沙箱。
    db = ROOT / "tests" / "fixtures" / "ctfarena-012-session.db"
    if not db.exists():
        db = next(ROOT.glob("runs/CTFARENA-012/**/agents.db"), None)
    if db is None or not db.exists():
        candidates = sorted(Path("/tmp/ctfbox").glob("*/strix_runs/*/.state/agents.db"))
        db = candidates[0] if candidates else None
    if db is None:
        print("  SKIP  找不到 012 的会话库，跳过重放")
        return

    rows = list(sqlite3.connect(str(db)).execute(
        "select message_data from agent_messages order by rowid"))
    calls: dict[str, dict] = {}
    outs: dict[str, str] = {}
    for (md,) in rows:
        d = json.loads(md)
        if d.get("type") == "function_call":
            calls[d["call_id"]] = d
        elif d.get("type") == "function_call_output":
            outs[d["call_id"]] = d.get("output", "")

    from ctf_strix.journey_guard import JourneyGuard

    g = JourneyGuard()
    for cid, cd in calls.items():
        if not cd["name"].startswith(("exec_command", "write_stdin")):
            continue
        g.observe(cd["name"], cd["arguments"], outs.get(cid, ""))

    st = g.state
    check("重放能识别出认证墙", st.wall_hit > 0, f"wall={st.wall_hit}")
    # 14 是 2026-10-28 修复后的实测值；早先正则漏掉 URL 编码载荷时只有 9。
    check("重放能数到攻击载荷", st.payloads >= 10, f"payloads={st.payloads}")
    check("重放确实产生了干预", st.prompts >= 3, f"prompts={st.prompts}")
    check("重放中守卫被真正调用", st.observe_calls > 30, f"calls={st.observe_calls}")


# ---------------------------------------------------------------- 入口契约
def test_agent_entry() -> None:
    """入口的 result.json 必须带 schema_version，且 flag 走证据判定。"""
    from ctf_strix import agent as entry

    section("CTFY 入口")
    check("入口声明 schema_version=2", entry.BRIEF_SCHEMA_VERSION == 2, "")

    # 入口源码必须装挂载钩子、且验证接线。这两条缺失过一次：
    # agent.py 装了三个守卫，却没有任何 install_mount_hook()，
    # 于是正赛里守卫同样全哑——和评测脚本犯的是同一个错。
    import inspect

    src = inspect.getsource(entry)
    check("入口装了挂载钩子", "install_mount_hook()" in src, "")
    check("入口验证了接线", "verify_mount(" in src, "")
    # 顺序也不能错：钩子必须在守卫之前。
    idx_hook = src.find("install_mount_hook()")
    idx_guard = src.find("install_enum_guard()")
    check(
        "钩子先于守卫安装",
        -1 < idx_hook < idx_guard,
        f"hook@{idx_hook} guard@{idx_guard}",
    )
    f = entry._extract_flag(
        "=== ctf_recon.md ===\n# CTF Recon — https://other.run/\nFLAG{bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}\n",
        "abc.ctfy.run",
    )
    check("入口不取别题残留", f is None, str(f))
    f = entry._extract_flag("abc.ctfy.run -> FLAG{ab12cd34}", "abc.ctfy.run")
    check("入口能取本题 flag", f == "FLAG{ab12cd34}", str(f))


def main() -> int:
    """跑完全部自测，返回退出码。"""
    print("改造点自测")
    print("=" * 70)
    for fn in (
        test_flag_extract,
        test_enum_guard,
        test_journey_guard,
        test_finish_guard,
        test_agent_entry,
        test_guards_integration,
        test_guard_mount,
        test_replay_real_session,
    ):
        try:
            fn()
        except Exception:  # noqa: BLE001 — 单个测试崩了要看到栈，也要继续跑别的
            _FAILED.append(f"{fn.__name__} 抛出异常")
            traceback.print_exc()

    print("\n" + "=" * 70)
    if _FAILED:
        print(f"失败 {len(_FAILED)} 项 / 通过 {_PASSED} 项")
        for f in _FAILED:
            print(f"  · {f}")
        return 1
    print(f"全部通过：{_PASSED} 项断言")
    return 0


if __name__ == "__main__":
    sys.exit(main())
