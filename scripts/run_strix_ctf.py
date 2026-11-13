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

#: 进程启动时刻（monotonic）。子进程墙钟预算从这里起算，而不是从 watchdog
#: 安装时刻——安装前的导入/工具注册耗时同样占父进程的墙钟（B-2）。
_T0 = time.monotonic()


def _stop_reason(exc: BaseException) -> str:
    """Map a guard's ``BaseException`` shutdown to the harness's stop reason.

    ``agent.py`` (the platform entry point) writes these reasons into
    ``result.json``; this script runs the scan through strix's own runner
    instead, so it has to emit the same vocabulary on stdout for the batch
    harness to read.  The strings must stay identical to ``agent.py``.
    """
    from ctf_strix.enum_guard import EnumExhausted
    from ctf_strix.progress_guard import NoProgress
    from ctf_strix.target_absent import TargetAbsent

    for cls, reason in (
        (NoProgress, "no_progress"),
        (EnumExhausted, "enum_exhausted"),
        (TargetAbsent, "target_absent"),
    ):
        if isinstance(exc, cls):
            return reason
    return "unknown"


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
        "--tags",
        nargs="*",
        default=None,
        help=(
            "Challenge tags as published by the platform. Used only to decide whether "
            "the AI-security tools are worth their schema; never used as a hint about "
            "how to solve the challenge."
        ),
    )
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
    p.add_argument(
        "--challenge-id",
        default="",
        help=(
            "Challenge id for the gated-question refresh (G1): the protocol "
            "asks us to re-read GET /api/v1/challenges/{id} after each "
            "correct answer so newly unlocked questions become visible "
            "within the round."
        ),
    )
    p.add_argument(
        "--guard-state",
        default=None,
        help=(
            "Where to persist the guard counters as JSON. The launcher passes an "
            "explicit per-run path; standalone runs default to guard_state.json "
            "in the current working directory (which is the run's own box)."
        ),
    )
    return p.parse_args()


def _guard_summary(guard: object, journey_state: object, finisher: object, reached: int) -> str:
    """Render the one-line guard summary, including mechanism-class counts.

    Mechanism counts are observational: they say which CAPEC classes the run
    actually exercised.  Without them the only way to recover that breakdown was
    to replay the transcript offline, so a run that stayed inside one class
    looked the same as one that never reached the guard at all.

    The suffix goes last on purpose: existing log parsers anchor on
    ``finish: refused=N`` and must keep matching.
    """
    counts = guard.mechanism_counts()
    mechanisms = ",".join(
        f"{name}={count}" for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ) or "(none)"
    return (
        f"[guard] reach={reached} (calls into guards) | enum keys={len(guard.counts)} "
        f"| journey: wall={journey_state.wall_hit} authed={journey_state.authed} "
        f"created={journey_state.created} payloads={journey_state.payloads} "
        f"prompts={journey_state.prompts} "
        f"| finish: refused={finisher.refusals} allowed={finisher.allowed} "
        f"| mechanisms: {mechanisms}"
    )


_EMPTY_ENDPOINTS: dict[str, int] = {
    "distinct_probe": 0,
    "distinct_exec": 0,
    "window_size": 0,
    "window_probe": 0,
    "window_exec": 0,
}


def _arg_display_limit(arg_text: str) -> int:
    """工具参数在 run.log 里的显示上限。

    默认 400 字符是为了日志可读；但只要参数里**带着答案**，就一个字符都
    不能切。答案有两条通道：flag 本身（``FLAG{``）和结构化答案标记
    （``ANSWER[<qid>]=<value>``，QA/选择题用）。

    2026-11-13 SECQA 实测：模型把 ``ANSWER[answer]=D`` 写在
    ``finish_scan(executive_summary=...)`` 里，摘要前 300 字符是解释、
    标记落在 400 字符之后，被切成 ``ANSWER[answer]… <truncated>``——父进程
    提取不到值，于是「答对了」在账本上记成「没作答」（3/6 假失败）。
    截断一个候选 token 会误导模型；截断带答案的参数则直接吞掉正确答案。
    """
    if "FLAG{" in arg_text or "ANSWER[" in arg_text:
        return 4000
    return 400


def _endpoint_sources() -> dict[str, int]:
    """Endpoint-source counters from the process-wide restart guard.

    ``guard`` in this payload is the enumeration guard (it owns the mechanism
    counts); the T3 window belongs to the restart guard singleton, which the
    mount hook has already connected to every tool.
    """
    try:
        from ctf_strix.restart_guard import current as current_restart_guard

        return current_restart_guard().endpoint_sources()
    except Exception:  # noqa: BLE001 - telemetry must never break the run
        return dict(_EMPTY_ENDPOINTS)


def _guard_state_payload(
    guard: object,
    journey_state: object,
    finisher: object,
    mount_verified: bool,
    negative: object | None = None,
) -> dict[str, object]:
    """State needed to rebuild the summary line after a SIGKILL.

    Keys mirror ``_parse_guard`` in ``batch_eval`` so the fallback produces the
    same fields as the log line.  ``mount_verified`` is recorded explicitly:
    a killed run has ``reach=0`` only if the guards really never ran, so
    "missing summary line" must no longer be read as "guard not mounted".
    """
    counts = guard.mechanism_counts()
    return {
        "reach": guard.observe_calls + journey_state.observe_calls,
        "enum_keys": len(guard.counts),
        "journey": {
            "wall": journey_state.wall_hit,
            "authed": bool(journey_state.authed),
            "created": bool(journey_state.created),
            "payloads": journey_state.payloads,
            "prompts": journey_state.prompts,
        },
        "finish": {
            "refused": finisher.refusals,
            "allowed": finisher.allowed,
        },
        "mechanisms": {name: int(count) for name, count in counts.items()},
        "mount_verified": bool(mount_verified),
        # v1.1: the frozen summary line stays byte-identical; new counters are
        # sidecar-only and read back by ``_parse_guard``.
        "endpoints": _endpoint_sources(),
        "negative": (
            negative.stats()
            if negative is not None
            else {"groups": 0, "injections": 0, "limit": 0, "truncation_pointers": 0}
        ),
    }


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

    # 零进展守卫必须紧跟在 mount hook 之后、negative_guard 之前装：观测签名
    # 要在 bounded 结果上单独算，任何一个守卫追加的建议文字都会把同一份
    # 观测变成两份不同的观测。装漏了，整窗零新观测的 run 就只能烧完轮次。
    from ctf_strix.progress_guard import _STALL_WINDOW as PROGRESS_STALL
    from ctf_strix.progress_guard import install as install_progress_guard

    progress_guard = install_progress_guard()
    print(
        f"[guard] progress guard installed "
        f"(stall>={PROGRESS_STALL} probes without a new observation, "
        f"markers={os.environ.get('CTFY_STALL_MARKERS') or 'in-memory only'})"
    )

    # G4/G5 live on the same seam, and are installed first so they see the
    # bounded (truncated) result before other guards append their advice: the
    # response signature must not drift when an unrelated hint fires.
    from ctf_strix.negative_guard import K as NEGATIVE_K
    from ctf_strix.negative_guard import LIMITS as NEGATIVE_LIMITS
    from ctf_strix.negative_guard import install as install_negative_guard

    negative = install_negative_guard()
    print(
        f"[guard] negative-evidence guard installed "
        f"(K={NEGATIVE_K}, L4={NEGATIVE_LIMITS['L4']}/run, truncation pointer on)"
    )

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
            args.platform,
            args.instance,
            os.environ.get("CTF_PLATFORM_TOKEN", ""),
            challenge_id=args.challenge_id,
        )
        print(f"[guard] autosubmit installed (instance {args.instance[:8]}...)")

    # 组合时限的"软截止"一半：到点不杀，只在工具结果里注入收敛指令。
    # 另一半（停滞/硬上限）由父进程 eval_sample 负责——子进程卡死时它自己
    # 已经没法执行任何代码了，必须由外部看门。
    deadline = None
    if args.soft_deadline > 0:
        from ctf_strix.deadline_guard import DeadlineGuard
        from ctf_strix.deadline_guard import install as install_deadline_guard

        deadline = install_deadline_guard(
            DeadlineGuard(
                wall=args.wall_deadline or args.soft_deadline * 2,
                soft=args.soft_deadline,
                turns=args.turns,
            )
        )
        print(
            f"[guard] deadline guard installed (soft={args.soft_deadline:.0f}s, "
            f"wall={args.wall_deadline or args.soft_deadline * 2:.0f}s)"
        )

    # B-2/P0#6（DEF-9）：进程内硬墙钟，与 agent.main() 同一实现（同源）。
    # 此前这条 harness 入口只有软截止注入，硬上限全靠父进程到点整组杀——
    # 被杀的那次 run 收尾行（[stop]/[usage]/[deadline]）全部打不出来，
    # 归因只能事后猜（45 题大测的墙钟死全走了这条路）。装两级 watchdog：
    # 软阶段在 sink 检查点抛 WallclockExceeded 干净收场（收尾照常打印、
    # exit 0），硬阶段 daemon 在预算+WALL_RESERVE 后 os._exit(0) 兜住
    # 卡死在 C 调用里的主线程。预算 = 父进程墙钟 - 启动耗时 - headroom
    # （agent 侧同一常量），保证子进程抢在父进程杀线之前收场。
    from ctf_strix import agent as agent_mod

    hard_watchdog = False
    if args.wall_deadline > 0:
        _since_start = time.monotonic() - _T0
        _hard_budget = max(
            int(args.wall_deadline)
            - int(_since_start)
            - int(agent_mod.DEADLINE_HEADROOM_SECONDS),
            1,
        )
        hard_watchdog = agent_mod._install_hard_deadline(
            _hard_budget, result_path=None
        )
        print(
            f"[guard] hard watchdog installed (budget={_hard_budget}s, "
            f"since_start={_since_start:.1f}s, "
            f"headroom={agent_mod.DEADLINE_HEADROOM_SECONDS:.0f}s, "
            f"armed={hard_watchdog})"
        )

    # 轮次预算守卫：与 deadline 守卫同一注入通道，但按**轮次**计数。
    # agent.py 的 attempt 循环里有它，而这个 harness 入口此前从未挂载——
    # 预算打满时 vendor 直抛 MaxTurnsExceeded、result=None，模型对
    # "我还剩几轮"零感知，一个字没交就结束。必须**晚于** deadline 守卫
    # 安装：两者替换同一个 factory._with_bounded_result，后装的在最外层，
    # 提示顺序才是 [SOFT DEADLINE] 在前、[TURN BUDGET] 在后（贴着决策）。
    from ctf_strix import turn_budget as turn_budget_mod

    tb_guard = turn_budget_mod.install()
    tb_guard.reset(args.turns)
    print(f"[guard] turn budget installed (budget={args.turns})")

    # 所有守卫装完之后立刻验证接线。不做这一步，接线失败会表现为
    # "计数器恒为 0"，和"今天没触发"完全无法区分——CTFARENA-012 就是这样
    # 白烧了 1170 秒。宁可启动时打一行 WARNING。
    from ctf_strix.guard_mount import verify_mount

    wired = verify_mount(
        (
            "_ctf_guarded",
            "_ctf_journey_guarded",
            "_ctf_sweep_guarded",
            "_ctf_negative_guarded",
            "_ctf_turn_budget",
        )
    )
    print(f"[guard] mount verified={wired} (exec_command reaches guards)")

    # 遥测也必须能在墙钟 SIGKILL 下存活：汇总行只在正常收尾时打印，被杀的那次
    # run 会把 reach 读成 0，看上去像守卫没装。照 usage_meter 的老办法——每次
    # LLM 调用后原子落盘（临时文件 + os.replace），父进程再从文件回退解析。
    from ctf_strix import guard_state as guard_state_mod

    guard_state_path = (
        Path(args.guard_state) if args.guard_state else Path.cwd() / "guard_state.json"
    )
    guard_writer = guard_state_mod.install(
        guard_state_path,
        lambda: _guard_state_payload(guard, journey.state, finisher, wired, negative),
    )
    print(f"[guard] state file {guard_state_path}")

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
    # 定义在 try 之外：import 失败时后面 if aisec_registered 不能 NameError。
    aisec_registered = False
    try:
        from ctf_strix.aisec import aig_probe
        from ctf_strix.aisec import tools as aisec_tools

        # One rule for both entrypoints (capabilities.wants_aisec): CTF_AISEC
        # overrides, otherwise the challenge's own metadata decides.  Before
        # this, the harness defaulted off and the submitted image defaulted on,
        # so the measured tool surface was not the delivered one.
        from ctf_strix.capabilities import aisec_offline
        from ctf_strix.capabilities import wants_aisec

        # This script receives the challenge description as text (--instruction),
        # not as task.json, so the metadata the official entrypoint reads is
        # reconstructed here from what the caller did pass.
        aisec_task = {
            "challenge": {"description": args.instruction or ""},
            "tags": [t for t in (args.tags or [])],
        }
        enabled, reason = wants_aisec(args.target_kind, aisec_task)
        offline, offline_reason = aisec_offline(args.target_kind, aisec_task)
        if enabled and aig_probe.data_dir():
            registered = aisec_tools.register()
            aisec_registered = True
            print(f"[aisec] registered {len(registered)} tools: {', '.join(registered)} ({reason})")
            # Same wiring as the official entrypoint: without it the allowlist
            # is empty and every private target is refused (AI-1).
            allowed = aisec_tools.allow_targets([args.target])
            print(
                f"[aisec] rules={aig_probe.data_dir()} "
                f"allow={','.join(allowed) or '(none)'}"
            )
        elif offline and aig_probe.data_dir():
            registered = aisec_tools.register_offline()
            aisec_registered = True
            print(
                f"[aisec] offline registered {len(registered)} tools: "
                f"{', '.join(registered)} ({offline_reason})"
            )
        elif enabled or offline:
            reason = reason if enabled else offline_reason
            print(f"[aisec] wanted ({reason}) but rules missing, tools NOT registered")
        else:
            print(f"[aisec] off ({reason})")
    except Exception as e:  # noqa: BLE001 — 增强能力失败不能让整题跑不动
        print(f"[aisec] registration failed: {type(e).__name__}: {e}")

    # Structured HTTP + route discovery.  Shared with the official entrypoint
    # (ctf_strix.agent) so the harness and the submitted image cannot drift
    # apart again: both gate it on args.target_kind, no unconditional install.
    from ctf_strix.capabilities import install_web_capabilities

    # Same gate as the official entrypoint: HTTP primitives only where there is
    # an HTTP surface.  Keeping the harness unconditional would re-create the
    # very drift this change removes -- a run measured with four extra schemas
    # is not the run the platform will make.
    groups: list[str] = ["base"]
    # The aisec tools registered above belong to the "aisec" catalogue group;
    # without this the Tools section describes fewer tools than the run actually
    # has (the same registration/prompt drift as the web primitives).  The
    # official entrypoint gets it for free: _measured_groups reads the registry.
    if aisec_registered:
        groups.append("aisec")
    if args.target_kind in ("web", "checker", "engagement"):
        web_tools, web_errors = install_web_capabilities()
        groups.append("web")
        for capability, names in web_tools.items():
            print(f"[{capability}] registered {len(names)} tools: {', '.join(names) or '(already present)'}")
        for message in web_errors:
            print(f"[capability] registration failed: {message}")
    else:
        print(f"[web] skipped (kind={args.target_kind})")

    # 文件类题（rev/pwn/misc/crypto 的附件题）才装入口原语。
    #
    # 只在 target_kind == file 时注册，是因为它会往 system prompt 里多塞一段
    # schema；web 题每一轮都要为这段付 token，收益却是零。
    if args.target_kind in ("file", "tcp"):
        try:
            from ctf_strix import file_triage

            added = file_triage.register()
            groups.append("file")
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
            groups.append("tcp" if args.target_kind == "tcp" else "file")
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
        from ctf_strix.capabilities import live_tool_names

        names = skillpack.register()
        if names:
            print(f"[skills] registered {len(names)}: {', '.join(names)}")
            print(f"[skills] ref={skillpack.ref_root()}")
        else:
            print("[skills] pack missing, routing hint NOT installed")
        # 分流约束必须写进 user_instructions：strix 的 <available_skills>
        # 只列名字，不会告诉模型"先 triage、再只挑一个方向"。
        # 方法卡按 tags 选，与技能包无关；过滤用的是上面装完的工具面（AI-5），
        # 所以这一段必须排在所有安装器之后。
        hint = skillpack.prompt_hint(
            names,
            kind=args.target_kind,
            tags=list(args.tags or []),
            available=live_tool_names() or None,
        )
        if hint:
            args.instruction = (hint + "\n\n" + args.instruction).strip()
    except Exception as e:  # noqa: BLE001 — 技能装不上也要能把题跑完
        print(f"[skills] registration failed: {type(e).__name__}: {e}")

    # ── 上下文管理（2026-11-01）────────────────────────────────────────────
    # 与官方入口 ctf_strix.agent 共用同一实现，避免"评测跑的是新提示、
    # 提交镜像跑的是旧提示"那种测量/实现分裂（capabilities.py 就是为此存在）。
    try:
        from ctf_strix import context as ctf_context
        from ctf_strix import prompt as ctf_prompt

        # Filter by measured tool names, not by group: one installer can fail
        # halfway through its group, and a promised tool that cannot be called
        # is exactly the drift this change exists to remove.  Same rule as the
        # official entrypoint (agent.registered_names).
        present: frozenset[str] = frozenset()
        try:
            from strix.agents import factory

            present = frozenset(getattr(tool, "name", "") for tool in factory.registered_agent_tools())
        except Exception as e:  # noqa: BLE001
            print(f"[ctx] registry probe failed: {type(e).__name__}: {e}")

        ctf_prompt.activate(args.target_kind, tuple(groups), present)
        ctf_prompt.install()
        capper = ctf_context.install()
        print(
            f"[ctx] prompt installed kind={args.target_kind} groups={','.join(groups)} "
            f"({len(ctf_prompt.build({}))} chars); "
            f"content cap={capper.cap_chars} chars/output, {capper.arg_cap} chars/args"
        )
    except Exception as e:  # noqa: BLE001 — 失败必须回落到原来的行为
        print(f"[ctx] install failed: {type(e).__name__}: {e}")

    from strix.core.runner import run_strix_scan

    # 守卫的收场异常继承 BaseException（故意不让 except Exception 吞掉），
    # 所以这里要显式接住并翻译成父进程能读的 stop_reason。
    from ctf_strix.enum_guard import EnumExhausted
    from ctf_strix.progress_guard import NoProgress
    from ctf_strix.target_absent import TargetAbsent

    # strix's sink receives (agent_id, stream_event). We only care about tool
    # calls and tool outputs — that is where a CTF run either makes progress or
    # spins, and printing model token deltas would bury it.
    def sink(agent_id: str, event: object) -> None:
        # 进程内墙钟的软阶段检查点（B-2）：SIGALRM 只在主线程执行 Python
        # 时直接抛；主线程挂在 await 上时只剩 watchdog 的旗子，这里把旗子
        # 翻译成异常。事件回调是主线程最频繁的检查点（agent.main 的 sink
        # 同款接线）。
        if hard_watchdog:
            agent_mod._check_soft_timeout()
        item = getattr(event, "item", None)
        kind = getattr(item, "type", None)
        if kind == "tool_call_item":
            raw = getattr(item, "raw_item", None)
            name = getattr(raw, "name", "?")
            arguments = getattr(raw, "arguments", "")
            # 同理：finish_scan 的 executive_summary 里就写着 flag，切到 220
            # 字符会把答案切断（CTFARENA-013 的摘要只剩 "**Flag: FLAG{b9"）。
            arg_text = str(arguments)
            arg_limit = _arg_display_limit(arg_text)
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
    except agent_mod.WallclockExceeded as exc:
        # 墙钟软着陆（B-2）：到点收场不算崩溃——照常走下面的 [usage]/守卫
        # 汇总，exit 0。机器可读行 reason=wallclock 不在父进程的重开集合
        # （预算问题重开只是重复烧钱），也不再被记成 rc=-9 硬杀或
        # 「error=None 的正常失败」。
        result = None
        print(f"\n[stopped] {type(exc).__name__}: {exc}")
        print("[stop] reason=wallclock")
    except (NoProgress, EnumExhausted, TargetAbsent) as exc:
        # 这三种不是崩溃，是「有证据的收场」：整窗零新观测（NoProgress）、
        # 同一族被硬拒后还在重试（EnumExhausted）、靶面全是同一份非应答
        # （TargetAbsent）。它们都继承 BaseException——故意的，`except
        # Exception` 遍布 runner 和工具包装层，被吞一次就回到了这些守卫
        # 要打断的那条重试循环。所以这里必须显式接住。
        #
        # 接住之后只做一件事：给父进程一条机器可读的收场行，然后照常走完
        # 下面的 [usage] / 守卫汇总，退出码 0。要不要用剩下的样本重开、
        # 换哪种策略，是外层 harness（batch_eval --max-samples）的决定。
        result = None
        reason = _stop_reason(exc)
        print(f"\n[stopped] {type(exc).__name__}: {exc}")
        extra = ""
        if isinstance(exc, NoProgress):
            # 停滞事实带出去：上一轮死在哪（host / path family / 机制类）是
            # 下一轮换策略唯一的输入。签名只是观测指纹，不含响应正文。
            extra = (
                f" host={exc.host or '-'} family={exc.family or '-'}"
                f" mechanism={exc.mechanism or '-'} signature={exc.signature or '-'}"
            )
        print(f"[stop] reason={reason}{extra}")
    except Exception as exc:  # noqa: BLE001 — a turn cap is a normal outcome here
        result = None
        print(f"\n[stopped] {type(exc).__name__}: {exc}")
        # 父进程（batch_eval）不解析 [stopped]——那行连 MaxTurnsExceeded 这种
        # 正常收场都包含，没法当错误信号。这里单独给一条带完整限定名的
        # 机器可读行，传输层崩溃（断流/网关重置）才能进结果表的 error 字段，
        # 否则表现成 error=None 的"正常失败"，非能力损失被计成能力损失。
        print(f"[run-error] {type(exc).__module__}.{type(exc).__name__}: {exc}")
    # 守卫置位不会自己抛异常：``ProgressGuard.install()`` 只写标记、置
    # ``tripped``，run 照常返回。``agent.py`` 在轮次边界查 ``tripped`` 并
    # ``raise NoProgress``；本脚本走的是 strix 自己的 runner，没有那一段，
    # 所以这里补同一条收场。漏了它，"深挖耗尽结束 run"在 batch 路径上就只剩
    # 一个标记文件，run 继续烧轮次——正是这条机制要打断的形态。
    if result is not None and progress_guard.tripped:
        host, family, mechanism, signature = progress_guard.last_probe
        print(f"\n[stopped] NoProgress: {progress_guard.trip_detail()}")
        # 行格式与异常分支完全一致，父进程只认 ``[stop] reason=`` 一条正则。
        print(
            f"[stop] reason=no_progress host={host or '-'} family={family or '-'}"
            f" mechanism={mechanism or '-'} signature={signature or '-'}"
        )
        result = None
    if hard_watchdog:
        # 收尾汇总阶段解除自家 watchdog（agent.main 同款顺序：先解除再
        # 清理），避免 alarm 打断 [usage]/守卫汇总的打印；父进程的墙钟
        # 仍然兜底这一段的极端挂死。
        agent_mod._cancel_hard_deadline()
    elapsed = time.time() - started

    print(f"\n[done] {elapsed:.1f}s  result={type(result).__name__ if result else None}")

    # 守卫统计必须打出来：否则"装了但没生效"和"装了且生效"在日志里长得一样。
    # 上一轮枚举守卫就是靠这条信息才发现真实运行里一次都没触发。
    # ⚠️ 再往上一层：这一次的教训是"日志打印了 installed、计数器恒为 0"——
    # 光看计数器还不够，必须能看出**守卫到底有没有被调用过**。
    js = journey.state
    reached = guard.observe_calls + js.observe_calls
    guard_writer.persist()
    print(_guard_summary(guard, js, finisher, reached))
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
        # B-5 日志卫生：run.log 会被 harness 归档、复盘时整份共享，答案
        # 明文不进这一行；父进程（eval_sample）只消费 soft_injected=。
        print(
            f"[deadline] elapsed={snap['elapsed']}s tools={snap['tool_calls']} "
            f"soft_injected={snap['soft_hit']} "
            f"answer_seen_at={snap['answer_at_s']}s"
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
    # 最后一道网（B-2）：SIGALRM 打在挂起的协程上时，WallclockExceeded
    # 从 asyncio.run 逃逸，main 里的 except 接不住（Windows 无此路径，
    # VM/Linux 是常态）。同样翻译成机器可读的 wallclock 收场 + exit 0，
    # 与 deadline.HARD_EXIT_CODE 的 CTFY-0001 契约一致。
    from ctf_strix.agent import WallclockExceeded as _WallclockExceeded

    try:
        _exit_code = asyncio.run(main())
    except _WallclockExceeded as exc:
        print(f"\n[stopped] {type(exc).__name__}: {exc}", flush=True)
        print("[stop] reason=wallclock", flush=True)
        _exit_code = 0
    sys.exit(_exit_code)
