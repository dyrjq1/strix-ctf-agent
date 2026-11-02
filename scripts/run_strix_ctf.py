"""Run one strix scan against a CTF target and dump what the agent produced.

Local verification harness for the TPCTF agent track. It reuses strix's own
runner (`strix.core.runner.run_strix_scan`) unchanged, so whatever this script
scores is strix's real behaviour — not a wrapper's approximation.

Credentials come from the environment, never from this file:
    LLM_API_KEY, LLM_API_BASE, STRIX_LLM

Run:
    PYTHONPATH=src:vendor/src STRIX_RUNTIME_BACKEND=local \
    LLM_API_KEY=... LLM_API_BASE=https://llmapi.paratera.com/v1 \
    STRIX_LLM=openai/DeepSeek-V4.1-Flash \
    .venv/bin/python scripts/run_strix_ctf.py --target https://... --turns 12
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--target",
        default="",
        help=(
            "Target for web (URL) or tcp (host:port) challenges. Empty for 'file' "
            "challenges, which have no network target."
        ),
    )
    p.add_argument("--turns", type=int, default=12, help="Max agent turns (cost cap)")
    p.add_argument("--name", default=None, help="Scan id; defaults to a timestamp")
    p.add_argument(
        "--instruction",
        default="",
        help="Extra instruction appended to strix's root task",
    )
    p.add_argument(
        "--trim-tools",
        action="store_true",
        help="兼容旧参数；记账工具现在默认就摘掉",
    )
    p.add_argument(
        "--keep-bookkeeping",
        action="store_true",
        help="保留 notes / coverage / threat_model / report 等记账工具（对照实验用）",
    )
    p.add_argument(
        "--target-kind",
        choices=("web", "tcp", "file"),
        default="web",
        help=(
            "What the agent is looking at. 'web' passes the URL as a web_application "
            "target; 'tcp' marks it as a raw TCP service; 'file' means there is no "
            "network target at all and everything is in --files-dir."
        ),
    )
    p.add_argument(
        "--soft-deadline",
        type=float,
        default=0.0,
        help=(
            "Seconds after which the agent is told (inside the next tool result) to stop "
            "exploring and converge. Does not terminate the run. 0 disables it."
        ),
    )
    p.add_argument(
        "--wall-deadline",
        type=float,
        default=0.0,
        help=(
            "Hard limit in seconds, only used to phrase the soft-deadline hint and to "
            "stop suppressing stall detection after an answer appears. The parent process "
            "is the one that actually kills the run."
        ),
    )
    p.add_argument(
        "--files-dir",
        default=None,
        help=(
            "Directory whose contents are copied into the agent's workspace. "
            "Used for artifact challenges (reverse/misc/crypto) so the agent does "
            "not have to fetch attachments itself."
        ),
    )
    p.add_argument(
        "--autosubmit",
        action="store_true",
        help=(
            "Submit the flag to the platform from inside finish_scan. Needs "
            "--platform and --instance. See ctf_strix/autosubmit.py for why this "
            "must live in the tool rather than in the parent process."
        ),
    )
    p.add_argument("--platform", default="", help="Platform base URL, e.g. https://ctfy.tsinghua.edu.cn")
    p.add_argument("--instance", default="", help="Instance id to submit against")
    return p.parse_args()


async def main() -> int:
    args = parse_args()

    from ctf_strix.local_backend import install

    install()

    # token 计量：统计本次 run 全部 LLM 调用的用量。批测里被墙钟杀掉是常态，
    # 计数器必须由当前进程持有，退出前打进 stdout 让父进程解析。
    from ctf_strix.usage_meter import install as install_usage_meter
    from ctf_strix.usage_meter import snapshot as usage_snapshot

    # 把快照路径也写进子进程环境，让 usage_meter 每次调用后原子落盘：
    # batch_eval 已经在父进程侧 export 了 CTF_USAGE_PATH，但直接跑
    # `run_strix_ctf.py`（调试/单题）时没有，这里补一个默认值。
    import os as _os

    if not _os.environ.get("CTF_USAGE_PATH"):
        _os.environ["CTF_USAGE_PATH"] = str(_os.path.join(_os.getcwd(), "usage.json"))
    install_usage_meter()

    # ⚠️ 必须在任何 guard install() 之前。三个守卫都是替换
    # factory._with_bounded_result 来挂 on_invoke_tool 的，而 exec_command /
    # write_stdin 走 Shell capability 的配置路径，绕过该函数。实测 CTFARENA-012
    # 45 次调用 / 16 次 401 / 守卫计数全 0，把真实会话灌进同一个守卫类重放却
    # 得到 wall=7 payloads=9 prompts=3——判定逻辑没问题，是接线没接上。
    from ctf_strix.guard_mount import install_mount_hook

    install_mount_hook()
    print("[guard] mount hook installed (exec_command/write_stdin now covered)")

    # 枚举收敛必须由程序强制，不能只写在 prompt 里。实测两版文字规则都没拦住
    # CTFARENA-018 反复刷同一族端点——上下文里的自我约束会随轮次衰减，计数器不会。
    from ctf_strix.enum_guard import install as install_enum_guard

    guard = install_enum_guard()
    print("[guard] enumeration guard installed (warn>=3 identical, hard>=5 identical, stall>=6)")

    # 同一类教训：只写在 prompt 里的行为约束会随轮次衰减。旅程守卫跟踪
    # "是否见过认证墙 / 是否已登录 / 是否创建过资源"，在未认证状态下灌载荷时介入。
    from ctf_strix.journey_guard import install as install_journey_guard

    journey = install_journey_guard()
    print("[guard] journey guard installed (activates only after a 401/403 on auth)")

    # 收工守卫：finish_scan 没有 flag 就拒绝。CTFARENA-013 只用了 260s/780s
    # 预算就收工，已注入成功却没去读 flag 文件——这是唯一能挡住它的手段。
    from ctf_strix.finish_guard import install as install_finish_guard
    from ctf_strix.sweep_guard import SWEEP_HARD, SWEEP_WARN

    finisher = install_finish_guard()
    print("[guard] finish guard installed (refuses flagless finish_scan, max 3)")

    # 单次调用内部的扫描守卫。`enum_guard` 按**调用**去重，对"把几万个候选
    # 塞进一条 exec_command 的 Python 循环"完全无能为力——CTFARENA-050 实测
    # 打了约 36,000 次路径变体，枚举守卫计数为 0，577 秒后失败。
    # 这个模块 2026-10-31 就写好了判定逻辑，但一直没有 install()，等于没装。
    from ctf_strix.sweep_guard import install as install_sweep_guard

    sweeper = install_sweep_guard()
    print(
        f"[guard] sweep guard installed "
        f"(warn>={SWEEP_WARN} distinct values in one call, hard>={SWEEP_HARD})"
    )

    # 收工时自动提交。顺序很关键：**必须在 finish guard 之后安装**，
    # 因为两者都包 finish_scan.on_invoke_tool，后装的是外层——
    # 外层先跑 = 先提交、再交给收工守卫判断该不该放行。
    autosub = None
    if args.autosubmit and args.platform and args.instance:
        from ctf_strix.autosubmit import install as install_autosubmit

        autosub = install_autosubmit(
            args.platform, args.instance, os.environ.get("CTF_PLATFORM_TOKEN", "")
        )
        print(f"[guard] autosubmit installed (instance {args.instance[:8]}...)")

    # 组合时限的"软截止"一半：到点不杀，只在工具结果里注入收敛指令。
    # 另一半（停滞/硬上限）由父进程 eval_sample 负责——子进程卡死时它自己
    # 已经没法执行任何代码了，必须由外部看门。
    deadline = None
    if args.soft_deadline > 0:
        from ctf_strix.deadline_guard import DeadlineGuard
        from ctf_strix.deadline_guard import install as install_deadline_guard

        stall = float(args.soft_deadline) / 3  # 仅用于提示里给出"还剩多久"
        deadline = install_deadline_guard(
            DeadlineGuard(
                wall=args.wall_deadline or args.soft_deadline * 2,
                soft=args.soft_deadline,
                stall=stall,
                grace=20.0,
                turns=args.turns,
            )
        )
        print(
            f"[guard] deadline guard installed (soft={args.soft_deadline:.0f}s, "
            f"wall={args.wall_deadline or args.soft_deadline * 2:.0f}s)"
        )

    # 三个守卫装完之后立刻验证接线。不做这一步，接线失败会表现为
    # "计数器恒为 0"，和"今天没触发"完全无法区分——CTFARENA-012 就是这样
    # 白烧了 1170 秒。宁可启动时打一行 WARNING。
    from ctf_strix.guard_mount import verify_mount

    wired = verify_mount(("_ctf_guarded", "_ctf_journey_guarded", "_ctf_sweep_guarded"))
    print(f"[guard] mount verified={wired} (exec_command reaches guards)")

    # Caido 工具必须无条件摘掉：本机没有 caido-cli，这 6 个调用必然报错。
    # 记账工具只在 --trim-tools 时摘，默认保留——评测与正赛要用同一工具面，
    # 否则评测出的轮次/token 不能用来推断正赛。
    from ctf_strix.tool_trim import install_ctf_toolset

    # 记账类默认摘掉：CTF 只认 flag，且 create_vulnerability_report 在 VM 上
    # 因缺 cvss 模块必然报错（009 复跑实测白烧 2 轮）。--trim-tools 保留
    # 为兼容开关，--keep-bookkeeping 可以恢复旧工具面。
    dropped = install_ctf_toolset(drop_bookkeeping=not args.keep_bookkeeping)
    print(f"[trim] dropped {len(dropped)} tools: {', '.join(dropped)}")

    # AI 安全能力（指纹 + CVE 匹配）。走 strix 官方扩展点 register_agent_tools，
    # 不改 _BASE_TOOLS，vendor 保持原样。
    # 规则库缺失时不注册——挂一个必然报错的工具只会浪费轮次。
    try:
        from ctf_strix.aisec import aig_probe
        from ctf_strix.aisec import tools as aisec_tools

        # 默认不注册。理由：旧总账里 "aisec 收益验证" 一栏的结论是
        # "本批全是传统 CTF 题，AI 组件指纹没用上"；而这 3 个工具 schema
        # 会常驻每次调用的 prompt。CTF 里 20 次调用 × ~500 token 不值。
        # 需要时 CTF_AISEC=1 打开。
        enabled = os.environ.get("CTF_AISEC", "").strip() in ("1", "true", "yes")
        if enabled and aig_probe.data_dir():
            registered = aisec_tools.register()
            print(f"[aisec] registered {len(registered)} tools: {', '.join(registered)}")
            print(f"[aisec] rules={aig_probe.data_dir()} allow={os.environ.get('CTF_AISEC_ALLOW', '(none)')}")
        elif enabled:
            print("[aisec] rules missing, AI-security tools NOT registered")
        else:
            print("[aisec] disabled by default (set CTF_AISEC=1 to enable)")
    except Exception as e:  # noqa: BLE001 — 增强能力失败不能让整题跑不动
        print(f"[aisec] registration failed: {type(e).__name__}: {e}")

    # Structured HTTP + route discovery.  Shared with the official entrypoint
    # (ctf_strix.agent) so the harness and the submitted image cannot drift
    # apart again.
    from ctf_strix.capabilities import install_web_capabilities

    web_tools, web_errors = install_web_capabilities()
    for capability, names in web_tools.items():
        print(f"[{capability}] registered {len(names)} tools: {', '.join(names) or '(already present)'}")
    for message in web_errors:
        print(f"[capability] registration failed: {message}")

    # 文件类题（rev/pwn/misc/crypto 的附件题）才装入口原语。
    #
    # 只在 target_kind == file 时注册，是因为它会往 system prompt 里多塞一段
    # schema；web 题每一轮都要为这段付 token，收益却是零。
    if args.target_kind in ("file", "tcp"):
        try:
            from ctf_strix import file_triage

            added = file_triage.register()
            print(f"[file] registered {len(added)} tools: {', '.join(added) or '(already present)'}")
        except Exception as e:  # noqa: BLE001
            print(f"[file] registration failed: {type(e).__name__}: {e}")

        # Same split as the official entrypoint: attachment primitives only on
        # file challenges, socket primitives only on tcp ones.  Registering both
        # would put ~2.5k chars of unused schema in front of the model on every
        # call of the other kind.
        try:
            from ctf_strix import nonweb

            added = nonweb.register(kind=args.target_kind)
            print(f"[nonweb] registered {len(added)} tools: {', '.join(added) or '(already present)'}")
        except Exception as e:  # noqa: BLE001
            print(f"[nonweb] registration failed: {type(e).__name__}: {e}")

    # CTF 技能包：12 个方向索引，走 strix 自带的 load_skill。
    #
    # 只注册索引、不注册整包，是因为 strix 会把注册目录里每个 <分类>/*.md
    # 都当成技能写进 system prompt——整包是 145 条、约 8.5k 字符，而其中 133 条
    # 是没有 frontmatter 的参考子文件，对模型零信息量。索引里的相对链接由
    # skillpack 插进去的路径提示兜住（指向 jail 内的 bind 挂载点）。
    try:
        from ctf_strix import skillpack

        names = skillpack.register()
        if names:
            print(f"[skills] registered {len(names)}: {', '.join(names)}")
            print(f"[skills] ref={skillpack.ref_root()}")
            # 分流约束必须写进 user_instructions：strix 的 <available_skills>
            # 只列名字，不会告诉模型"先 triage、再只挑一个方向"。
            hint = skillpack.prompt_hint(names)
            args.instruction = (hint + "\n\n" + args.instruction).strip()
        else:
            print("[skills] pack missing, routing hint NOT installed")
    except Exception as e:  # noqa: BLE001 — 技能装不上也要能把题跑完
        print(f"[skills] registration failed: {type(e).__name__}: {e}")

    # ── 上下文管理（2026-11-01）────────────────────────────────────────────
    # 与官方入口 ctf_strix.agent 共用同一实现，避免"评测跑的是新提示、
    # 提交镜像跑的是旧提示"那种测量/实现分裂（capabilities.py 就是为此存在）。
    try:
        from ctf_strix import context as ctf_context
        from ctf_strix import prompt as ctf_prompt

        ctf_prompt.install()
        capper = ctf_context.install()
        print(
            f"[ctx] prompt installed ({len(ctf_prompt.build({}))} chars); "
            f"content cap={capper.cap_chars} chars/output, {capper.arg_cap} chars/args"
        )
    except Exception as e:  # noqa: BLE001 — 失败必须回落到原来的行为
        print(f"[ctx] install failed: {type(e).__name__}: {e}")

    from strix.core.runner import run_strix_scan

    # strix's sink receives (agent_id, stream_event). We only care about tool
    # calls and tool outputs — that is where a CTF run either makes progress or
    # spins, and printing model token deltas would bury it.
    def sink(agent_id: str, event: object) -> None:
        item = getattr(event, "item", None)
        kind = getattr(item, "type", None)
        if kind == "tool_call_item":
            raw = getattr(item, "raw_item", None)
            name = getattr(raw, "name", "?")
            arguments = getattr(raw, "arguments", "")
            # 同理：finish_scan 的 executive_summary 里就写着 flag，切到 220
            # 字符会把答案切断（CTFARENA-013 的摘要只剩 "**Flag: FLAG{b9"）。
            arg_text = str(arguments)
            arg_limit = 4000 if "FLAG{" in arg_text else 400
            arg_body = arg_text if len(arg_text) <= arg_limit else arg_text[:arg_limit] + "… <truncated>"
            print(f"  [{agent_id}] TOOL {name} {arg_body}")
        elif kind == "tool_call_output_item":
            output = str(getattr(item, "output", ""))
            # A plain 300-char cut sliced a real flag in half (FLAG{b9 + newline),
            # which made the batch evaluator see a truncated, unsubmitable token.
            # Any output that mentions a flag is kept whole; the rest is trimmed
            # only to keep the log readable.
            limit = 4000 if "FLAG{" in output else 600
            body = output if len(output) <= limit else output[:limit] + f"… <truncated {len(output) - limit}B>"
            print(f"  [{agent_id}] OUT  {body}")

    scan_id = args.name or f"ctf-{int(time.time())}"

    # 目标描述必须和题型一致。strix 的 scan_config 里 target type 会影响 system
    # prompt 的措辞（web_application 会强调 URL 爬取），对 TCP/附件题是错的引导。
    if args.target_kind == "file":
        targets: list[dict[str, object]] = []
    elif args.target_kind == "tcp":
        host, _, port = args.target.partition(":")
        targets = [
            {
                "type": "network_service",
                "details": {
                    "host": host or args.target,
                    "port": int(port) if port.isdigit() else 0,
                    "protocol": "tcp",
                },
            }
        ]
    else:
        targets = [
            {"type": "web_application", "details": {"target_url": args.target}},
        ]

    scan_config = {
        "targets": targets,
        "user_instructions": args.instruction,
        "scan_mode": "quick",
    }

    # 附件直接塞进沙箱 workspace。让 agent 自己 curl 平台 API 下载是不可能
    # 成立的（它没有平台 token），而"把文件放好"本来就是 harness 的职责。
    #
    # ⚠️ ``workspace_path`` **必须是 /workspace 开头的绝对路径**
    # （``runtime/session_manager.py:91`` 的 ``_extra_file_rel_path`` 只认
    # ``/workspace/`` 前缀，其余一律静默丢弃）。第一版传的是裸相对路径
    # ``gatekeeper.py``，结果 strix 在内部日志里只留一行
    # ``WARNING Skipping invalid extra file entry``，主日志照样打印
    # "[files] 1 个附件将注入 sandbox"——**看起来注入成功，实际工作目录是空的**。
    # 直接后果：SAMPLE-002 / 001 的 agent 各花了 2-3 个 turn 满盘 find 一个
    # 根本不存在的附件，002 最终是从提示词里的附件名猜出逻辑才勉强做出来。
    extra_files: list[dict[str, object]] = []
    if args.files_dir:
        src = Path(args.files_dir)
        if src.is_dir():
            for f in sorted(src.rglob("*")):
                if not f.is_file():
                    continue
                rel = f.relative_to(src)
                try:
                    text = f.read_text(encoding="utf-8")
                    extra_files.append(
                        {"workspace_path": f"/workspace/{rel}", "content": text}
                    )
                except UnicodeDecodeError:
                    # 二进制（ELF / zip）必须走 base64，否则 content 字段塞不进去。
                    import base64

                    extra_files.append(
                        {
                            "workspace_path": f"/workspace/{rel}.b64",
                            "content": base64.b64encode(f.read_bytes()).decode(),
                        }
                    )
            print(f"[files] {len(extra_files)} 个附件将注入 sandbox: "
                  f"{[e['workspace_path'] for e in extra_files]}")

            # 注入路径必须自检。strix 对非法 workspace_path 是**静默丢弃**，
            # 主日志照样说"已注入"——SAMPLE-002/001 就是这样白跑了两题。
            # 用 strix 自己的校验函数逐条过一遍，不合法的当场报出来。
            from strix.runtime.session_manager import _extra_file_rel_path

            bad = [
                e["workspace_path"] for e in extra_files
                if _extra_file_rel_path(str(e["workspace_path"])) is None
            ]
            if bad:
                print(f"[files] ERROR 这些路径会被 strix 静默丢弃: {bad}")
            else:
                print(f"[files] 路径校验通过（均在 /workspace/ 下）")

    print(f"[scan] id={scan_id} kind={args.target_kind} target={args.target} turns={args.turns}")
    started = time.time()
    try:
        result = await run_strix_scan(
            scan_config=scan_config,
            scan_id=scan_id,
            image="unused-local",
            local_sources=[],
            extra_files=extra_files or None,
            max_turns=args.turns,
            cleanup_on_exit=True,
            event_sink=sink,
        )
    except Exception as exc:  # noqa: BLE001 — a turn cap is a normal outcome here
        result = None
        print(f"\n[stopped] {type(exc).__name__}: {exc}")
    elapsed = time.time() - started

    print(f"\n[done] {elapsed:.1f}s  result={type(result).__name__ if result else None}")

    # 守卫统计必须打出来：否则"装了但没生效"和"装了且生效"在日志里长得一样。
    # 上一轮枚举守卫就是靠这条信息才发现真实运行里一次都没触发。
    # ⚠️ 再往上一层：这一次的教训是"日志打印了 installed、计数器恒为 0"——
    # 光看计数器还不够，必须能看出**守卫到底有没有被调用过**。
    js = journey.state
    reached = guard.observe_calls + js.observe_calls
    print(
        f"[guard] reach={reached} (calls into guards) | enum keys={len(guard.counts)} "
        f"| journey: wall={js.wall_hit} authed={js.authed} created={js.created} "
        f"payloads={js.payloads} prompts={js.prompts} "
        f"| finish: refused={finisher.refusals} allowed={finisher.allowed}"
    )
    if reached == 0:
        print(
            "[guard] WARNING: no guard was ever invoked. The mount hook is not "
            "wired — this run's guard numbers are meaningless, not evidence of "
            "correct behaviour."
        )

    # 用量必须单独一行、固定格式，父进程用正则抓。放在最后是因为即使这次 run
    # 被异常中断，前面的 finally 也走到这里了。
    u = usage_snapshot()
    print(
        f"[usage] calls={u['llm_calls']} in={u['input_tokens']} "
        f"out={u['output_tokens']} total={u['total_tokens']}"
    )
    try:
        from ctf_strix import context as ctf_context

        print(f"[ctx] stats: {ctf_context.stats()}")
    except Exception as e:  # noqa: BLE001
        print(f"[ctx] stats unavailable: {type(e).__name__}: {e}")

    if deadline is not None:
        snap = deadline.snapshot()
        print(
            f"[deadline] elapsed={snap['elapsed']}s tools={snap['tool_calls']} "
            f"soft_injected={snap['soft_hit']} answer={snap['answer']}"
        )

    # strix writes its run artefacts under ~/.strix/runs/<scan_id>. Dump whatever
    # text we can find so a human can judge whether the agent got anywhere.
    run_dir = Path.home() / ".strix" / "runs" / scan_id
    print(f"[run dir] {run_dir} exists={run_dir.exists()}")
    if run_dir.exists():
        for path in sorted(run_dir.rglob("*")):
            if path.is_file() and path.stat().st_size < 200_000:
                print(f"  - {path.relative_to(run_dir)} ({path.stat().st_size}B)")

    if result is not None:
        for attr in ("final_output", "output", "text", "summary"):
            value = getattr(result, attr, None)
            if value:
                print(f"\n[{attr}]\n{str(value)[:4000]}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
