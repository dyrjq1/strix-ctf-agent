"""CTF 专用系统提示：替换 strix 内置的通用渗透测试提示。

## 为什么必须换掉（不是"省 token"这么简单）

实测（GLM-5.3-EV，paratera）：``render_system_prompt()`` 输出 **103,541 字符 /
22,817 token**。40 轮下来光系统提示就是 **913k token**，占 043 那道题
（2,239,568）的 41%。

更重要的是它**含三处与本镜像不符的事实**，每一处都会直接把模型带偏：

1. ``<multi_agent_system>``："MANDATORY INITIAL PHASES — ROOT AGENT …
   you MUST accomplish them by delegating to reconnaissance subagents — do NOT
   run recon … in your own turns."
   而 ``tool_trim`` 已经把 ``create_agent`` / ``send_message_to_agent`` /
   ``wait_for_agents`` / ``view_agent_graph`` 全部摘掉（默认
   ``CTF_ALLOW_SUBAGENTS`` 未开）。模型被要求执行一个**工具面里不存在**的动作。
   043 的日志里 root 反复自称 coordinator，正是这段话的产物。

2. ``<environment>``：声称装了 ``nuclei`` / ``subfinder``，并且
   "Caido CLI … already running"。镜像里这三样都不存在（``tool_trim`` 摘 Caido
   工具的理由就是"无 caido-cli"），模型据此规划扫描器，一次就是一个白烧的轮次。
   ``nmap`` / ``sqlmap`` / ``ffuf`` 则是真的装了（``docker/check_toolchain.sh``
   每次构建都探测），所以本文件的 Environment 段逐条列出装了什么、没装什么——
   **只有一处工具事实来源**，不再和 ``config/goal_preamble.txt`` 各说一套。

3. ``<vulnerability_focus>`` / ``create_vulnerability_report``：整段讲
   "漏洞必须用 reporting agent 提交报告才算发现"，而 CTF 的交付物是 flag 字符串。
   043 最后 3 次 ``finish_scan`` 被收工守卫拒绝，就是在写这种报告体。

## 保留什么

短提示不是"少写点话"，而是**把稀疏的注意力预算花在真会决定成败的判据上**。
依据 Anthropic《Effective context engineering for AI agents》：系统提示要
"specific enough to guide behavior effectively, yet flexible enough"，
并且"最小"指**信息量最小**，不是字最少。

所以保留四类：环境硬事实、工具语义、证据判据、收工判据。
删掉的是：报告工作流、子 agent 编排、工具清单、渗透方法论长文。

## 合规

纯静态文本，不联网、不改工具面、不改变单实例/单模型约束。
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: 覆盖文件（存在则用它，缺省用内置版本）。改提示不必改代码。
OVERRIDE = Path(__file__).resolve().parents[2] / "config" / "prompt_ctf.md"

#: One discipline shared by every challenge kind: falsify, close, switch.
_HYPOTHESIS = """\
## Hypothesis discipline

Before each step, state the mechanism you are betting on in one line: what
causes the wrong result, and what single check should expose it.

- **Try to falsify it.** At least one action in the next step must be designed
  to prove the hypothesis false, not to confirm it: rerun the same input under
  a changed premise, or alter one variable that should be irrelevant and see
  whether the output still matches the prediction.
- **Close it explicitly.** After N consecutive failures on the same hypothesis
  (pick N small and fixed before the series), or when fresh parameters keep
  failing in the same shape, declare it closed and write one line saying why.
  A closed hypothesis stays closed in later turns; reopen it only with new
  evidence.
- **Change mechanism.** After closure, the next step must test a different
  exploitation mechanism or attack surface. Do not scale the closed one with
  more names of the same kind or a larger input set -- that is the same
  mechanism, not a new attempt.

"""

#: ``scan_mode="quick"`` 的收敛段。strix 原实现用它选 ``scan_modes/<mode>``
#: 技能（``vendor/src/strix/agents/prompt.py:54``），产物里就是多一份
#: 「先收敛、后扩展」的指令。我们替换的是整个 ``render_system_prompt``，所以
#: 这段只能由我们自己渲染，否则 ``scan_mode`` 就只是被扔掉的一个参数。
#: 只写机制、不写工具名 —— ``## Environment`` 是工具事实的单一来源。
_SCAN_QUICK = """\
## Scan mode: quick (converge first)

Reconnaissance is time-boxed: collect only what you need to name one mechanism,
then drive that mechanism to a read before opening a second surface. When it
fails in the same shape twice, change mechanism -- a larger payload set or
wordlist is the same hypothesis at bigger size, not a new one. Depth beats
breadth: one request that reads the secret is worth more than a map of
everything else.

"""

#: What "solved" means.  It differs by challenge kind and cannot be left to the
#: goal file: the goal file is appended *below* this text, so a core prompt that
#: says "there is no report to write" argues against the deliverable an
#: engagement is graded on.  A flag challenge is scored on one answer string; an
#: engagement on the report it saves, so an unsaved finding is worth zero.
_DELIVERABLE_FLAG = (
    "The only thing\nthat scores is the answer string, graded exactly. There is "
    "no report to write."
)
_DELIVERABLE_REPORT = (
    "There is no single answer string: what scores is the report you save, and "
    "only what has been written down can score. Give each finding the exact "
    "request, the response you got back, and the data you should not have seen "
    "— and write them down as you go, because an unsaved finding is worth zero."
)

#: Same split for the stop condition: a flag challenge waits for one quoted
#: string, an engagement for findings that each carry their own evidence.
_FINISH_FLAG = (
    "Call `finish_scan` only when the answer string is in front of you, quoted\n"
    "verbatim (case and braces matter). Before calling it, answer honestly: do I "
    "have\nexecution/file/DB read, and did I actually read the secret — or only "
    "a schema?\n"
    "Deliver each answer on its own line as ANSWER[<question_id>]=<value> —\n"
    "that line is what the submission layer submits, verbatim."
)
_FINISH_REPORT = (
    "Call `finish_scan` when the report covers what you found and every finding\n"
    "carries its own request and response. Before calling it, answer honestly: is\n"
    "each claim backed by a request I actually sent and a response I actually "
    "read,\nor am I writing from memory?"
)

#: Third instance of the same defect: the costliest-failure paragraph is aimed at
#: a run that has a flag to read.  For an engagement the exploit *is* the finding,
#: and the failure is not writing it down.
_PROOF_FLAG = (
    "**Proof is not the deliverable.** If you have code execution, file read, or DB\n"
    "read, spend the same turn reading the answer: `find / -iname '*flag*'`,\n"
    "`cat /flag*`, `SELECT * FROM <table>`. A demonstrated vulnerability that you "
    "did\nnot exploit is zero points."
)
_PROOF_REPORT = (
    "**An unwritten finding is not a finding.** If you have code execution, file\n"
    "read, or DB read, capture the exact request, the response, and the data you\n"
    "should not have seen — then put it in the report in the same turn. A\n"
    "demonstrated vulnerability you did not write down is zero points."
)

_CORE = """\
You are the solver for one CTF challenge on the CTFY platform. {deliverable}

## Environment (verified facts, not guesses)

- CLIs: `nmap` `sqlmap` `ffuf` `smbclient` `curl` `nc` `file` `strings` `xxd`
  `readelf` `objdump` `gdb` `ROPgadget` `r2` `binwalk` `exiftool` `7z` `tshark`
  `tcpdump` `fls` `steghide` `upx` `checksec` `impacket` `flask-unsign` `RsaCtfTool`.
- No nuclei, Caido, Docker, gobuster, volatility; use a listed CLI instead of
  hand-writing it, and `command -v NAME` once if unsure. HTTP via `requests` or
  `curl`.
- `python3` has: `requests` `Crypto` `Cryptodome` `z3` `PIL` `pwn` `numpy`
  `sympy` `gmpy2` `scipy` `matplotlib` `pefile` `yara` `segno` `dnslib`
  `capstone` `unicorn` `paramiko` `rpyc` `plumbum`.
- Internet: **none**; anything else cannot be installed; don't try.
- Evidence: results must be **printed by a script**, not reasoned.
- >30s: not inline (partial output). `nohup python3 x.py > log 2>&1 &`, poll
  `cat log` or `write_stdin`.
- Stop on `curl` 000, `Connection refused`, proxy errors.

{tools}

{turns}

{mode}{race}
{hypothesis}## The failure mode that costs the most

**A new name is not a new hypothesis.** A path, id or param in one attack
class is one guess; a breadth scan answers each, so "same response twice"
never fires. Count classes, not names: adding no untried class means the
mechanism is wrong. One endpoint, many payloads, two shapes is blind
extraction -- progress while you can name the value it reads.

{proof}

## Finish

{finish}
"""

#: ``How to spend turns`` differs by challenge kind.  A file challenge has no
#: root page to probe and no accounts to register; telling it to do both burns
#: two turns before it opens the attachment.  The file text points at the
#: per-family ``next:`` table inside ``file_triage``: the model should run
#: that table instead of loading a skill just to decide the direction.
#: The web text is the original one, unchanged, so the measured web
#: behaviour does not move.
_TURNS_WEB = """\
## How to spend turns

1. Probe the root once, map routes once. Do not re-fetch a page you already have.
2. If the app has accounts or login, register and log in **before** attacking.
   Access-control bugs live behind a session you have not created yet. Two
   accounts beat any wordlist.
3. Attack the specific thing you found. Name the mechanism before you send:
   "id param is trusted server-side, swap it for another user's id".
"""

_TURNS_FILE = """\
## How to spend turns

1. `file_triage` the attachment once. Do not run `file` and `strings` by hand
   first: the triage answer already contains both, plus the family guess.
2. Run its `next:` table in order (1 then 2 then 3). The table is per family and
   every command is installed in this image; a deep-read skill line is a last
   resort, not the first step. Do not substitute a command from another family.
3. When the trail is a string rather than a file, `decode_blob` before writing
   your own decoder — it reports which layer was which. An archive goes through
   `unpack_archive`; a binary stays static in `elfpeek` until you have a reason
   to run it.
4. Name the mechanism before each step: "the flag is in the PNG IDAT after the
   LSB plane", "the second gzip member holds the key".
"""

_TURNS_TCP = """\
## How to spend turns

1. `file_triage` the attachment first when there is one, then `tcp` once to read
   the banner. The banner usually names the binary and its protections.
2. `elfpeek` the binary before connecting again: checksec-style results, symbols
   and gadgets come from the file, not from the service.
3. Probe with `tcp_batch`, not a hand-written loop. One call, many payloads,
   one line per response — that is how an offset is found.
4. Name the crash before you weaponise it: which input, which offset, which
   register or return address it overwrites.
5. Plain `tcp` connected but no bytes came back (or only a lone `0x15`/`0x16`
   byte) => the port speaks TLS. Retry with `tls=True`; `sni` defaults to the
   host. This platform's TCP access is TLS-SNI, so `pwn.remote(..., ssl=True)`
   is the equivalent. Never conclude "the service ignores input" from an empty
   plain reply.
"""

_TURNS: dict[str, str] = {
    "web": _TURNS_WEB,
    "checker": _TURNS_WEB,
    "engagement": _TURNS_WEB,
    "file": _TURNS_FILE,
    "tcp": _TURNS_TCP,
}

#: The only situation in which splitting the work pays for itself: after recon,
#: two mutually exclusive directions remain and both can be checked from the
#: evidence already collected.  Everything else is faster single-threaded.
_RACE = """\
## Parallel hypothesis race (opt-in)

The agent-graph tools are present for this run. They are not a general
invitation to delegate: the default is still to solve the challenge yourself.

- **Spawn only after recon, and only with two directions.** Before spawning,
  list the candidate directions in `think`. Spawn only when that list contains
  at least two directions that (a) are mutually exclusive -- confirming one
  rules the other out -- and (b) can each be checked with the evidence you
  already have. Then spawn **one** child per direction, at most **two**
  children for the whole run.
- **Do not spawn** when a direction is already ahead on evidence, when the
  challenge is small enough to finish in a few calls, when the candidates are
  variations of one mechanism, or when you cannot name what would falsify a
  direction. In those cases keep working yourself; `finish_scan` is closer
  than `create_agent`.
- **One child, one direction.** Every `create_agent` brief must contain:
  1. the single hypothesis and the exact check that would falsify it;
  2. the facts already established (paths, credentials/session state, files,
     commands that already failed);
  3. what is out of bounds: no other direction, no re-running known-failed
     probes, no spawning more agents, no `finish_scan` (that is the root's
     call).
  A child must report the answer it retrieved, or the evidence that closed its
  direction, and call `agent_finish`. Children do not report prose-only.
- **Race end.** The first retrieved answer or platform verdict wins. When a
  child retrieves a flag -- or a shell call it made returns a passing verdict
  from the challenge's own check endpoint -- stop sending work: the run ends
  with that result. Do not spawn a replacement or restart the search. If the
  root retrieves it, call `finish_scan` once and carry the exact string.
- **Budget is shared.** Children run on the same turn, wall-clock and memory
  budget as you; two children does not mean two budgets. Keep briefs short and
  avoid duplicate reconnaissance.

"""

#: Challenge kind and the installer groups that actually registered.  Set by
#: :func:`activate` from the entrypoint, before the first prompt is rendered.
#: ``None`` means "not told yet": the renderer then offers every row for
#: ``web``, which is the pre-2026-11-02 behaviour and keeps unit tests working.
_ACTIVE_KIND: str = "web"
_ACTIVE_GROUPS: tuple[str, ...] | None = None
_ACTIVE_NAMES: frozenset[str] | None = None


def activate(
    kind: str,
    groups: tuple[str, ...] | None = None,
    names: frozenset[str] | set[str] | None = None,
) -> None:
    """Tell the prompt which challenge kind is running and what was installed.

    Why this is a module-level switch rather than a render argument: strix's
    ``render_system_prompt`` signature is fixed and is rebound at import time in
    three modules.  Passing the kind through it would mean changing vendor code,
    and vendor stays untouched.

    Args:
        kind: ``web`` / ``file`` / ``tcp`` / ``checker`` / ``engagement``.
        groups: installer groups that registered successfully.  ``None`` keeps
            every group, which is only correct when nothing was asked to skip.
        names: tool names measured in the registry.  ``None`` means "trust the
            groups", which is right for unit tests and wrong for a live run --
            see ``catalogue.for_kind``.
    """
    global _ACTIVE_KIND, _ACTIVE_GROUPS, _ACTIVE_NAMES
    _ACTIVE_KIND = kind or "web"
    _ACTIVE_GROUPS = groups
    _ACTIVE_NAMES = names


def active() -> tuple[str, tuple[str, ...] | None]:
    """Return ``(kind, groups)`` currently in effect; used by tests and logs."""
    return _ACTIVE_KIND, _ACTIVE_GROUPS


def _targets_block(ctx: dict[str, Any] | None) -> str:
    """把本次 run 的授权目标渲染进提示（原 scope.jinja 的核心信息）。"""
    if not ctx:
        return ""
    targets = ctx.get("authorized_targets") or []
    if not targets:
        return ""
    lines = ["## Target (the only in-scope asset)"]
    for target in targets:
        if isinstance(target, dict):
            kind = target.get("type") or "url"
            value = target.get("value") or ""
            if value:
                lines.append(f"- {kind}: {value}")
        elif isinstance(target, str):
            lines.append(f"- {target}")
    if len(lines) == 1:
        return ""
    lines.append(
        "- There is no second host, no internal DNS you can reach, and no other "
        "port worth scanning. Host-header tricks and subdomain guessing return nothing."
    )
    return "\n".join(lines)


#: 只暴露技能包自己的分类。上游 strix 自带 65 条 ``vulnerabilities/*`` /
#: ``frameworks/*`` / ``tooling/*`` —— 它们是给**完整工具链**写的（ffuf、
#: nuclei、Caido、browser sidecar），而本容器里这些工具一个都没有。实测
#: 022 加载了 ``vulnerabilities/prototype_pollution``、028 加载了
#: ``frameworks/nextjs``，两份内容都在教"用不存在的工具做扫描"。
#:
#: 这不是"少给点知识"，是**不让索引指向走不通的路**。技能包自己的 14 个
#: 方向索引是按本容器能力写的，只有它们该出现在这里。
_SKILL_PREFIX = "ctf-"

#: 在本容器里**必然走不通**的方向索引。
#:
#: ``ctf-similar-search`` 的正文是 ``pip install tavily`` +
#: ``POST https://api.tavily.com/search``：外网被禁、包也装不上，加载它只会
#: 让模型去试一个注定失败的动作。索引里放走不通的方向，比不放更糟——它把
#: "我没有这个能力"伪装成"我该往这走"。
#:
#: 注意这里只筛**完全不可用**的。``ctf-osint`` 虽然常要联网，但本地文件
#: 元数据、EXIF、日志时间线这类题离线可做，所以保留并加一句限定。
_UNUSABLE_OFFLINE: frozenset[str] = frozenset({"ctf-similar-search"})

#: 从描述里抽出"什么时候该选我"。技能描述本身就带这句（``Use when ...``），
#: 直接取用比另写一份路由表稳——另写一份必然与技能内容漂移。
_USE_WHEN = re.compile(r"\bUse (?:when|for)\s+(.+?)(?:\.\s|\.$|$)", re.IGNORECASE | re.DOTALL)

#: 索引行里每条触发条件的字符上限。14 条 × 130 ≈ 1.8k 字符，与原来的
#: 纯名字清单（2.3k）量级相当，但多了"选我/别选我"的信息。
_ROUTE_CHARS = 130


def _route_hint(description: str) -> str:
    """把一条技能描述压成一行触发条件。

    Args:
        description: ``get_available_skills()`` 给出的原始描述。

    Returns:
        单行、无换行、不超过 ``_ROUTE_CHARS`` 字符的触发条件；抽不出时给空串。
    """
    match = _USE_WHEN.search(description or "")
    text = match.group(1) if match else (description or "")
    text = " ".join(text.split())
    if not text:
        return ""
    if len(text) > _ROUTE_CHARS:
        cut = text.rfind(";", 0, _ROUTE_CHARS)
        if cut < _ROUTE_CHARS // 2:
            cut = text.rfind(",", 0, _ROUTE_CHARS)
        if cut < _ROUTE_CHARS // 2:
            cut = _ROUTE_CHARS
        text = text[:cut].rstrip(" ,;:")
    return text


def _skills_block() -> str:
    """按已注册技能生成**带触发条件**的方向索引。

    这里刻意不列上游 strix 的非 ``ctf-*`` 技能（理由见 ``_SKILL_PREFIX``），
    也不在 ``_CORE`` 里另抄一份名单——清单只有一个来源，就不会漂移。实测
    ``_CORE`` 的手写名单漏了 ``ctf-agentic-ai`` 与 ``ctf-supply-chain``
    两个方向，正好是本项目最强的 AI 安全线。
    """
    try:
        from strix.skills import get_available_skills

        available = get_available_skills()
    except Exception:  # noqa: BLE001 - 技能索引失败不该阻止跑题
        return ""

    lines: list[str] = []
    for category in sorted(available):
        if not category.startswith(_SKILL_PREFIX):
            continue
        if category in _UNUSABLE_OFFLINE:
            continue
        for entry in available[category]:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not name:
                continue
            hint = _route_hint(str(entry.get("description") or ""))
            if category == "ctf-osint":
                hint = "local artifacts only (EXIF, metadata, logs, files); there is no internet"
            lines.append(f"- `{category}/{name}`" + (f" \u2014 {hint}" if hint else ""))
    if not lines:
        return ""
    return (
        "## Skill indexes\n\n"
        "Load at most one. Each line says **when**; subfiles: `exec_command`\n"
        "(`cat`/`sed -n`), images `view_image`; not `load_skill`.\n\n"
        + "\n".join(lines)
    )


def _render_core(
    kind: str,
    groups: tuple[str, ...] | None,
    names: frozenset[str] | set[str] | None = None,
    *,
    is_root: bool = True,
    scan_mode: str = "deep",
) -> str:
    """Fill the Tools and How-to-spend-turns sections for one challenge kind.

    Both come from the single catalogue (``ctf_strix.catalogue``) and from the
    per-kind turn plan, so a tool that is registered but undescribed -- or
    described but not registered -- is impossible by construction.

    Args:
        kind: challenge kind from ``agent._challenge_kind``.
        groups: installer groups that actually registered.
        names: tool names measured in the registry; ``None`` trusts the groups.
        scan_mode: strix's ``scan_mode`` from ``scan_config``; ``"quick"``
            injects :data:`_SCAN_QUICK`, anything else renders exactly the
            pre-existing text. ``"deep"`` must stay a byte-for-byte no-op for
            every kind except ``"engagement"``: two size budgets and the
            measured web/checker/file/tcp prompts depend on it, while
            engagement's deliverable sentence is corrected on purpose.

    Returns:
        The core prompt text, ready to concatenate.
    """
    from ctf_strix import catalogue
    from ctf_strix.tool_trim import subagents_allowed

    tools = catalogue.prompt_block(kind, groups, names)
    turns = _TURNS.get(kind, _TURNS_WEB)
    mode = _SCAN_QUICK if str(scan_mode or "").strip().lower() == "quick" else ""
    # `names` only carries the extra tools registered through
    # `register_agent_tools`; `create_agent` lives in the vendor base tuple,
    # so testing membership here would silently hide the protocol.
    #
    # Children render this same prompt.  Only the root may spawn, so a child
    # that received this section would be told to do something its runtime
    # guard refuses -- and on a long run it would burn turns trying.
    race = _RACE if (is_root and subagents_allowed()) else ""
    # The deliverable and the stop condition are the two sentences that name
    # what the run is for.  Both are wrong for an engagement -- there is no
    # answer string to quote, and the report *is* the deliverable -- and the
    # goal file sits below this text, so it cannot retract them.
    engagement = kind == "engagement"
    return _CORE.format(
        tools=tools,
        turns=turns,
        hypothesis=_HYPOTHESIS,
        race=race,
        mode=mode,
        deliverable=_DELIVERABLE_REPORT if engagement else _DELIVERABLE_FLAG,
        finish=_FINISH_REPORT if engagement else _FINISH_FLAG,
        proof=_PROOF_REPORT if engagement else _PROOF_FLAG,
    ).strip()


def build(
    system_prompt_context: dict[str, Any] | None = None,
    *,
    is_root: bool = True,
    scan_mode: str = "deep",
) -> str:
    """拼出 CTF 系统提示。

    Args:
        system_prompt_context: strix 传入的 per-run 上下文（含 authorized_targets）。
        is_root: 是否根 agent；只有根会拿到 ``## Parallel`` 段。
        scan_mode: strix 的扫描模式。``"quick"`` 追加收敛段；
            ``"deep"``/未知值渲染结果与改动前逐字节相同。

    Returns:
        提示全文。
    """
    if os.environ.get("CTF_PROMPT_OFF", "").strip().lower() in ("1", "true", "yes"):
        # 回滚 / A/B 对照：退回 strix 原始的 103,541 字符通用提示。
        # 模式照传：退回原样应连 scan_mode 的语义一起退，而不是钉死 deep。
        from strix.agents.prompt import render_system_prompt as original

        return original(
            scan_mode=scan_mode, system_prompt_context=system_prompt_context
        )

    env_text = os.environ.get("CTF_PROMPT_OVERRIDE", "").strip()
    if env_text and Path(env_text).is_file():
        return Path(env_text).read_text(encoding="utf-8")
    if OVERRIDE.is_file():
        return OVERRIDE.read_text(encoding="utf-8")

    core = _render_core(
        _ACTIVE_KIND,
        _ACTIVE_GROUPS,
        _ACTIVE_NAMES,
        is_root=is_root,
        scan_mode=scan_mode,
    )
    parts = [core, _targets_block(system_prompt_context), _skills_block()]
    return "\n\n".join(part for part in parts if part) + "\n"


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    is_diff_scoped: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    include_scope: bool = True,
) -> str:  # noqa: ARG001 - 其余参数只为与 strix 原签名一致
    """strix ``render_system_prompt`` 的替身。

    签名逐字对齐 vendor（``strix/agents/prompt.py``），因为
    ``strix.core.runner`` 按关键字调用它。**``scan_mode`` 必须透传**：strix
    原本用它选 ``scan_modes/<mode>`` 技能，是我们唯一能拿到的「本次要收敛
    还是铺开」的信号；早先的实现把它丢掉，quick 语义就静默失效了。

    ``build`` 是模块级名字，测试里 monkeypatch 它即可直接观察透传。
    """
    return build(system_prompt_context, is_root=is_root, scan_mode=scan_mode)


def install() -> bool:
    """用本模块替换 strix 的 ``render_system_prompt``。

    注意：``strix.agents.factory`` 与 ``strix.core.runner`` 在导入时就把函数名
    绑进了自己的命名空间，只改 ``strix.agents.prompt`` 不会生效。三个绑定都要
    一起换，否则不同的 agent 会拿到不同的提示（这本身就是最难查的一类失效）。

    Returns:
        是否安装成功。
    """
    import strix.agents.factory as factory
    import strix.agents.prompt as prompt_mod
    import strix.core.runner as runner

    if os.environ.get("CTF_PROMPT_OFF", "").strip().lower() in ("1", "true", "yes"):
        logger.info("ctf-ctx: CTF prompt disabled by CTF_PROMPT_OFF")
        return False

    if getattr(prompt_mod, "_ctf_prompt_installed", False):
        return True

    prompt_mod.render_system_prompt = render_system_prompt  # type: ignore[assignment]
    factory.render_system_prompt = render_system_prompt  # type: ignore[assignment]
    runner.render_system_prompt = render_system_prompt  # type: ignore[assignment]
    prompt_mod._ctf_prompt_installed = True  # type: ignore[attr-defined]
    logger.info("ctf-ctx: CTF system prompt installed")
    return True


def measure() -> int:
    """返回当前提示的 token 数（GLM 实测口径，失败时退回字符/3）。"""
    text = build({"authorized_targets": [{"type": "url", "value": "https://x.test/"}]})
    try:
        from strix.llm.context_budget import count_tokens

        return count_tokens("openai/GLM-5.3-EV", text)
    except Exception:  # noqa: BLE001
        return len(text) // 3
