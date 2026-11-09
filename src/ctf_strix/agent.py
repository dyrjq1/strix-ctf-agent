"""CTFY 合规入口：读 task.json → 跑 strix → 写 result.json → exit 0。

合规要点（来自 ctfy 0.7.0 源码 core/agent_brief.py:690-800）：

1. **stdout 不被读取**，只有 `result.path` 指向的文件被收集。
2. `no_result_file` 是 blocking 级判据 —— 文件必须存在，哪怕 `answers` 是空的。
3. 所以本模块的核心承诺是：**无论解题成功、超时、还是崩溃，都写出 result.json 并 exit 0**。
   把失败伪装成成功是错的，但把"跑完了、没解出"伪装成"进程崩溃"更错 ——
   前者让平台知道我们的 agent 尽力了，后者让平台以为镜像坏了。

`answers` 的填法有两种合法路径（源码原话 "both are graded the same"）：
- 边做边 POST `/api/v1/submissions`（autosubmit 走这条，因为能拿到即时反馈）
- 把答案塞进 `answers` map，平台在 run 结束时替你提交

两条都走会让同一题消耗两次 attempt，所以默认只走 `answers`；评测脚本可以
另外挂 autosubmit 做即时提交。engagement 题没有 flag，交付物是报告，见
:mod:`ctf_strix.engagement`。

Idle watchdog (2026-11-06, a memory-poisoning run): strix.log showed 121 turns and 120
LLM requests but only 6 tool calls.  After concluding the target was dead,
the model wrote "I'll wait for the hard stop" and idled for roughly 20
minutes until the 1380s wall clock expired.  A long stretch without any
tool call means the run is not learning anything, so :class:`IdleWatchdog`
ends it early and ``main`` writes ``stop_reason="agent_idle"``.  The limit
is ``CTF_IDLE_SECONDS`` (default 150; non-positive disables the watchdog).

Target-absent fast fail (2026-11-06, dead-host and placeholder runs):
a host that answers one identical uninformative body to every path is not a
target to keep enumerating.  :mod:`ctf_strix.target_absent` counts distinct
paths per identical body hash, and the sink ends the run as
``stop_reason="target_absent"`` so the serial rotation moves on.
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

from ctf_strix import deadline
from ctf_strix import error_policy
from ctf_strix import platform_attach as attach
from ctf_strix.success_stop import RecoveryExhausted
from ctf_strix.success_stop import SolvedStop
from ctf_strix.enum_guard import EnumExhausted
from ctf_strix.success_stop import SuccessLedger
from ctf_strix.target_absent import TargetAbsent
from ctf_strix.usage_meter import begin_run as begin_usage_run
from ctf_strix.usage_meter import OutputBudgetExceeded
from ctf_strix.usage_meter import raise_if_tripped
from ctf_strix.usage_meter import trip_info as usage_trip_info


def _enable_local_cost_map() -> None:
    """Keep LiteLLM from downloading its model-price table at import time.

    LiteLLM fetches ``model_prices_and_context_window.json`` on first import
    unless this flag is set; in a locked-down container that is a ~15s
    connect/retry before the run even starts.  ``setdefault`` leaves an
    operator-provided value alone.
    """
    os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")


_enable_local_cost_map()

#: 兜底 flag 形态（抽取器不可用时用）。与 ``flag_extract`` 的正则同源：
#: CTFY 的 flag 可能是 ``FLAG{…}`` / ``ctfy{…}`` / ``flag{…}``。
FLAG_PATTERN = re.compile(r"(?:FLAG|flag|CTF|ctf|CTFY|ctfy)\{[0-9a-zA-Z_\-]{4,}\}")

#: 题型 → goal 文件。缺失文件时用 ``_FALLBACK_GOALS`` 里的最小版本。
GOAL_FILES: dict[str, str] = {
    "web": "ctf_goal.txt",
    "tcp": "goal_tcp.txt",
    "file": "goal_file.txt",
    "checker": "goal_checker.txt",
    "engagement": "ctf_goal_engagement.txt",
}

#: 自动保存报告的间隔（工具输出条数）。engagement 题边做边存，平台每次保存
#: 都会从正文抽证据计分，攒到最后再交等于中途一分不拿。
_REPORT_EVERY = 8

#: 收集的工具输出上限，防止长 run 把内存吃光。
_CAPTURE_LIMIT = 400

_TRUTHY = {"1", "true", "yes", "on"}

#: Attachment list/download timeout. Short on purpose: the old no-target
#: path is better than stalling on an unreachable platform.
_ATTACHMENT_TIMEOUT = 20

_FALLBACK_GOALS: dict[str, str] = {
    "web": (
        "THIS IS A CTF CHALLENGE. Success is exactly one answer string matching "
        "FLAG{...} (or the platform's declared form). Do not write reports. Once "
        "you have code execution or file read, immediately use it to find and "
        "read the target file."
    ),
    "tcp": (
        "THIS IS A CTF CHALLENGE against a raw TCP service. Success is the flag "
        "string. Keep one connection open, read the service's behaviour, and "
        "exploit it until you can read the flag. Do not stop at a crash."
    ),
    "file": (
        "THIS IS A CTF CHALLENGE. The attachments are in your working directory. "
        "Analyse them and recover the flag string. Do not stop at an intermediate "
        "plaintext that still needs a final transformation."
    ),
    "checker": (
        "THIS IS A CTF CHALLENGE WITHOUT A FLAG. Success is a real side effect on "
        "the target that an external judge verifies. Cause it, then re-read the "
        "target's state to confirm the change is visible."
    ),
    "engagement": (
        "THIS IS A PENETRATION-TEST ENGAGEMENT. There is no single flag. Deliver a "
        "report of concrete, reproducible findings with the exact request, the "
        "response you got back, and the data you read. Save the report as you go."
    ),
}


def _truthy(value: object) -> bool:
    """把 ``True`` / ``"1"`` / ``"true"`` 之类统一判真，``"false"`` 判假。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in _TRUTHY


def _work_dir() -> Path:
    """定位 CTFY 注入的工作目录。

    平台通过 ``CTFY_WORK_DIR`` 传；本地自测时退回当前目录（entrypoint 会先
    ``cd`` 到工作目录），这样没有平台也能跑通"读 task.json → 写 result.json"。
    """
    raw = os.environ.get("CTFY_WORK_DIR")
    if raw:
        return Path(raw)
    return Path.cwd()


def _read_task(work: Path) -> dict[str, Any]:
    """读 task.json。缺失时返回空 dict，让主流程走降级分支而不是直接崩。"""
    path = work / "task.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _result_path(work: Path, task: dict[str, Any]) -> Path:
    """解析 result 文件路径。

    ``task.json`` 的 ``result.path`` 是权威来源（平台可能改路径）；
    缺失时退回约定的 ``result.json``。
    """
    declared = (task.get("result") or {}).get("path")
    if declared:
        path = Path(declared)
        return path if path.is_absolute() else work / path
    return work / "result.json"


def _raw_scope(task: dict[str, Any]) -> list[str]:
    """``task.json`` 里声明的原始 scope 字符串，原样保留（含 CIDR）。"""
    return [str(entry).strip() for entry in (task.get("scope") or []) if str(entry).strip()]


def _is_cidr(entry: str) -> bool:
    """是否是 ``10.20.0.0/16`` 这种网段。"""
    return bool(re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", entry))


def _target_endpoints(task: dict[str, Any]) -> list[dict[str, str]]:
    """协议 v3 公布的靶面地址：``target_endpoints`` 与 ``CTFY_TARGET_URL``。

    为什么要单独一支：v3 起 ``scope`` 只留给 engagement（主机名 + 网段），
    jeopardy 题的靶址搬到 ``target_endpoints``，单一 web 端点还会重复成
    ``CTFY_TARGET_URL``。只读 ``scope`` 的客户端在 v3 上会拿到空目标，
    然后把这题记成"没有可扫描目标"——看着像题目坏了，其实是版本没跟上。

    Returns:
        ``[{"url": ..., "type": ..., "label": ...}]``；没有时返回空列表。
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    declared = task.get("target_endpoints")
    if isinstance(declared, list):
        for item in declared:
            if isinstance(item, dict):
                url = str(item.get("url") or "").strip()
                kind = str(item.get("type") or "").strip().lower()
                label = str(item.get("label") or "").strip()
            elif isinstance(item, str):
                url, kind, label = item.strip(), "", ""
            else:
                continue
            if not url or url in seen:
                continue
            seen.add(url)
            out.append({"url": url, "type": kind, "label": label})

    # 平台在只有一个 web 端点时也会写这个变量。它和 target_endpoints 是
    # 同一份事实的两种写法，去重而不是当成第二个目标。
    env_url = str(os.environ.get("CTFY_TARGET_URL") or "").strip()
    if env_url and env_url not in seen:
        out.append({"url": env_url, "type": "http", "label": "env"})
    return out


def _is_web_endpoint(entry: dict[str, str]) -> bool:
    """这条端点是不是 HTTP 面。"""
    if entry.get("type") in {"http", "https"}:
        return True
    return entry.get("url", "").startswith(("http://", "https://"))


def _targets_from(task: dict[str, Any]) -> list[str]:
    """从 task.json 解析出可当 web 目标打的 URL。

    三种形态差别很大，不能混：

    - **instance（v3）**：靶址在 ``target_endpoints``，单一 web 端点还会同时出现在
      ``CTFY_TARGET_URL``；``scope`` 在这类题里是空的。
    - **instance（v2 及更早）**：``scope`` 里是起好的实例 URL
      （``https://xxx.node2.ctfy.run:443``）。仍要认，旧的 dry-run 样本与本地
      task.json 都是这个形状。
    - **engagement**：``scope`` 里是**主机名和网段**（``edge.meridian.test``、
      ``10.20.0.0/16``），靶场已经起来了，``target_instance`` 非空就说明平台先起好了。
      网段交给 agent 自己用 nmap 摸，别硬拼成 URL——``https://10.20.0.0/16`` 是个
      合法但无意义的地址，会让 strix 在探测阶段白烧 turn。

    Args:
        task: 已解析的 task.json。

    Returns:
        目标 URL 列表。解析不出任何可用目标时返回空列表。
    """
    run_mode = str(task.get("run_mode") or "instance")
    raw = _raw_scope(task)

    urls = [entry for entry in raw if entry.startswith(("http://", "https://"))]
    # v3：jeopardy 的靶址在 target_endpoints / CTFY_TARGET_URL，不在 scope。
    for endpoint in _target_endpoints(task):
        if _is_web_endpoint(endpoint) and endpoint["url"] not in urls:
            urls.append(endpoint["url"])
    if urls:
        return urls

    if run_mode == "engagement":
        # 只取单主机名：带 "/" 的是 CIDR，交给 agent 扫描而不是当 web 目标。
        hosts = [entry for entry in raw if "://" not in entry and "/" not in entry]
        return [f"https://{host}" for host in hosts]

    return []


def _target_specs(task: dict[str, Any]) -> list[dict[str, Any]]:
    """把 scope 翻译成 strix 的 ``scan_config["targets"]``。

    除了 web URL（scope 与 ``target_endpoints`` 两个来源），还保留两类语义：

    - **CIDR** 作为 ``ip_address`` 目标进 scope，让 agent 知道整段都在授权范围内，
      而不是从 prompt 里那串 ``10.20.0.0/16`` 里猜。
    - **``host:port``** 作为 ``ip_address`` 原样加进 scope（含端口）。strix 的
      target schema 没有裸 TCP 类型，但 ``target_ip`` 只是一个字符串；剥掉端口
      会让 agent 少一条"服务在哪"的信息，TCP 题尤其吃亏。

    Returns:
        去重后的 target 列表；一个都解析不出时返回空列表。
    """
    urls = _targets_from(task)
    specs: list[dict[str, Any]] = [
        {"type": "web_application", "details": {"target_url": url}} for url in urls
    ]
    seen = {url for url in urls}

    # v3 的非 HTTP 端点（``type: tcp`` 等）不在 scope 里，只在
    # ``target_endpoints``。丢掉它们，TCP 题就只剩一个空目标列表。
    for endpoint in _target_endpoints(task):
        url = endpoint["url"]
        if not url or url in seen or _is_web_endpoint(endpoint):
            continue
        specs.append({"type": "ip_address", "details": {"target_ip": url}})
        seen.add(url)
    # 已经作为 web 目标出现过的主机名不要再按 ip_address 加一遍：同一个主机
    # 在 prompt 里出现两次会让 agent 以为是两台机器，多花轮次去区分。
    covered_hosts = {_host_of(url) for url in urls}

    for entry in _raw_scope(task):
        if entry in seen:
            continue
        if entry in covered_hosts or _host_of(entry) in covered_hosts:
            continue
        if _is_cidr(entry):
            specs.append({"type": "ip_address", "details": {"target_ip": entry}})
            seen.add(entry)
            continue
        if "://" in entry:
            continue
        if not entry or entry in seen:
            continue
        specs.append({"type": "ip_address", "details": {"target_ip": entry}})
        seen.add(entry)
    return specs


def _scope_note(task: dict[str, Any]) -> str:
    """把原始 scope（含 CIDR）写进指令。

    只给 web URL 的旧实现会让 engagement 的网段信息彻底丢失：agent 看不到
    ``10.20.0.0/16``，于是只能扫题面里那一两个主机名。这里保留**原文**，
    并明确整段都在授权范围内。
    """
    raw = _raw_scope(task)
    if not raw:
        return ""
    urls = set(_targets_from(task))
    interesting = len(raw) > 1 or any(entry not in urls for entry in raw)
    if not interesting:
        return ""
    lines = "\n".join(f"- {entry}" for entry in raw)
    return (
        "\n\n## Scope (exact strings from the task)\n\n"
        "Everything listed here is authorized and in scope. CIDR ranges mean you "
        "discover hosts yourself; do not assume a single web URL.\n\n"
        f"{lines}"
    )


def _question_ids(task: dict[str, Any]) -> list[str]:
    """List every question id that is visible in this round.

    ``answers`` is a map keyed by question id: the platform matches each key
    against its own record, so an id that is missing from the map is a
    question that was never answered -- even when the flag was found.  A
    challenge whose ``questions`` lists two visible ids used to collect one
    key and score one question (ledger 4.9: a two-question run kept
    ``my_fully_solved=false`` after a correct flag).

    Gated questions are not listed here: the protocol says their prompt does
    not exist yet, so they cannot be in ``task.json`` either.

    Args:
        task: parsed task.json.

    Returns:
        Declared ids in declaration order; ``["flag"]`` when the task has no
        questions (engagement / awd).
    """
    out: list[str] = []
    for question in task.get("questions") or []:
        if isinstance(question, dict):
            declared = question.get("id")
            if declared and str(declared) not in out:
                out.append(str(declared))
    return out or ["flag"]


def _question_id(task: dict[str, Any]) -> str:
    """取本次要回答的 question id（第一个）。

    Kept as the narrow accessor for callers that need one id (the ledger key,
    the prompt line).  Written answers must go through :func:`_question_ids`
    so every visible question gets its own key.

    Args:
        task: 已解析的 task.json。

    Returns:
        第一个 question 的 id；没有 questions（engagement / awd）时退回 ``"flag"``。
    """
    return _question_ids(task)[0]


#: Wording the platform uses in the per-round briefing (protocol §3.3) for the
#: verdicts of the previous round.  Presence of any of these means the README
#: carries state we would otherwise re-derive from scratch.
_ROUND_VERDICTS = ("correct", "wrong", "not answered", "newly unlocked")
_ROUND_NUMBER = re.compile(r"\bround\s+(\d+)\b", re.IGNORECASE)


def _round_note(work: Path) -> str:
    """Point the model at the platform briefing, and quote it when it has state.

    ``README.md`` exists from the **first** round -- it is ``task.json``
    rendered as prose -- so its presence alone says nothing about rounds.  What
    matters is whether it carries a verdict list: the protocol states that from
    round two it names the round and gives each question of the last round
    ``correct`` / ``wrong`` / ``not answered`` / ``newly unlocked``, and that
    ``/ctfy/work`` survives between rounds.  Without reading that, a restart
    re-derives everything and repeats paths already known to be wrong.

    Args:
        work: the CTFY work directory.

    Returns:
        An instruction block; on the first round it is one line (read the file),
        on later rounds it also quotes the briefing, capped.
    """
    readme = work / "README.md"
    head = (
        "## Read the platform briefing first\n\n"
        "`README.md` in your working directory is the platform's own briefing; "
        "it is generated from the same contract as `task.json`. Read it before "
        "the first tool call."
    )
    if not readme.is_file():
        return ""
    try:
        body = readme.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return head
    if not body:
        return head

    match = _ROUND_NUMBER.search(body)
    later = bool(match and int(match.group(1)) > 1) or any(
        word in body.lower() for word in _ROUND_VERDICTS
    )
    if not later:
        return head

    if len(body) > 1800:
        body = body[:1800] + "\n...(truncated; read the file for the rest)"
    return (
        head
        + "\n\nThis is **not** the first round: the briefing below names the round "
        "and gives each question of the last round a verdict. Do not repeat a "
        "path recorded as **wrong**, continue from the ones marked **newly "
        "unlocked**, and note that whatever you left in the working directory "
        "is still there.\n\n"
        f"```\n{body}\n```"
    )


#: 平台自己写进工作目录的文件，永远不算题目附件。
#:
#: ``README.md`` 是平台放的选手 API 说明（``test_attachment_fetch`` 的 fixture
#: 就是这个形态），不是题目材料；题目真的只发一份 README 时应当在
#: ``task.json.attachments`` 里显式声明。``.txt`` 不在此列——纯附件题的
#: ``README.txt`` 就是货真价实的附件。
_RESERVED_WORK_FILES = frozenset({"task.json", "result.json", "mcp.json", "README.md"})


def _has_bare_artifacts(work: Path) -> bool:
    """工作目录根上有没有「不是平台控制文件」的普通文件。

    只看根上的**文件**：子目录 ``attachments/`` / ``files/`` 由调用方先判，
    其它目录可能是本地调试时的仓库目录，误判成附件会让题型走错分支。

    Args:
        work: ``CTFY_WORK_DIR``。

    Returns:
        至少有一个非控制文件时返回 True；目录不可读时返回 False。
    """
    try:
        for entry in work.iterdir():
            if entry.is_file() and entry.name not in _RESERVED_WORK_FILES:
                return True
    except OSError:
        return False
    return False


def _challenge_kind(task: dict[str, Any], work: Path | None = None) -> str:
    """判断题型：``web`` / ``tcp`` / ``file`` / ``checker`` / ``engagement``。

    判据全部来自 task.json 的显式字段：

    - ``run_mode == "engagement"`` → engagement（交付物是报告）；
    - 只有 checker 类 question → checker（没有 flag，收工守卫必须让路）；
    - scope 全是 ``host:port`` 且无 scheme → tcp；
    - 没有网络目标但声明了附件 → file；
    - 其余 → web。

    Returns:
        题型字符串，供 :func:`_read_goal` 选 prompt。
    """
    if str(task.get("run_mode") or "").strip().lower() == "engagement":
        return "engagement"

    modes = {
        str(q.get("mode")).strip().lower()
        for q in (task.get("questions") or [])
        if isinstance(q, dict) and q.get("mode")
    }
    if modes and modes <= {"checker"}:
        return "checker"

    raw = _raw_scope(task)
    # v3 的端点类型是明说的，不用猜；scope 为空时它是唯一线索。
    endpoint_types = {e.get("type") for e in _target_endpoints(task)}
    if endpoint_types & {"tcp", "udp", "ssh"} and not endpoint_types & {"http", "https"}:
        return "tcp"
    if raw and all("://" not in entry and not _is_cidr(entry) for entry in raw):
        if any(re.fullmatch(r"[^/\s]+:\d{1,5}", entry) for entry in raw):
            return "tcp"

    declared_attachments = task.get("attachments") or task.get("files")
    if not _targets_from(task) and declared_attachments:
        return "file"
    if not _targets_from(task) and work is not None:
        # 平台可能只把附件丢进工作目录，不写进 task.json。看目录是否存在，
        # 免得把"没给目标"误判成附件题、又或者反过来漏掉附件题。
        if any((work / name).is_dir() for name in ("attachments", "files")):
            return "file"
        # 2026-11-06：有些投递方式把附件直接放在工作目录**根**上，既没有
        # ``attachments/`` 子目录、也没写进 ``task.json.attachments``。
        # 只看子目录会让这类纯附件题落到 web 分支 → 没有 target → no_target，
        # 一回合都不跑（纯附件题实测）。根上的非控制文件就是附件。
        if _has_bare_artifacts(work):
            return "file"

    if not _targets_from(task) and all(_is_cidr(entry) for entry in raw):
        # 纯网段的 instance 题：当作 file 处理会误导，仍按 web/network 跑。
        return "web"
    return "web"


def _host_of(url: str) -> str:
    """从 URL 剥出 host（去 scheme、端口、路径），供 flag 证据判定用。"""
    s = url.split("://", 1)[-1]
    return s.split("/", 1)[0].split(":", 1)[0]


def _extract_flag(blob: str, own_host: str | None = None) -> str | None:
    """从 agent 输出里抽出 flag，带证据校验。

    ⚠️ 这里**不能**简单地取最后一个。实测踩过两次：
      · 子 agent 会 cat 到本机上别的题留下的 recon 笔记，末尾那个 flag 是别题的；
      · 同一个输出里既有真 flag 又有诱饵时，最后一个不一定是答案。
    所以委托给 ``flag_extract``，它按"离本题靶机最近 + 排除 recon 残留"打分。

    Args:
        blob: 工具输出或全部输出的拼接。
        own_host: 本题靶机 host。为空时退化为"取最可信的一个"，仍会剔除模板占位符。

    Returns:
        可信的 flag；没有可信候选时返回 None。
    """
    try:
        from ctf_strix.flag_extract import best_flag

        return best_flag(blob, own_host or "")
    except Exception:  # noqa: BLE001 — 抽取器不可用时不能拖垮整条链路
        # 降级：至少剔除 FLAG{...} 这种模板占位符。
        from ctf_strix.flag_extract import is_placeholder

        found = [f for f in FLAG_PATTERN.findall(blob) if not is_placeholder(f)]
        # Take the FIRST, not the last: the docstring above says the last one is
        # exactly the wrong choice (stale recon notes from another challenge,
        # or a decoy in the same output).  Mechanical fix of a comment/code
        # contradiction found by the 2026-11-02 external review.
        return found[0] if found else None


def _extract_args_flags(raw: str) -> list[str]:
    """Return flag-shaped strings from a lifecycle call's arguments.

    A child cannot make a claim true by writing it: the value stays a guess in
    ``arg_claims`` until a tool output from this run proves it.  An output that
    merely echoes the same literal back from the call's own arguments does not
    count (see :meth:`ctf_strix.evidence.EvidenceLedger.echoed_only`).  This
    exists so ``agent_finish`` gets the same provenance gate as ``finish_scan``.
    """
    from ctf_strix.parallel import flags_in_text

    return flags_in_text(raw)


def _parallel_flag(text: str, own_host: str) -> str | None:
    """Extract a child's flag against the run's success rules.

    ``flag_extract`` needs a host for its proximity rule; child tool output is
    the same text the root receives, so the same extractor applies.  A child
    on a host-less challenge (attachments) still uses its fallback.
    """
    return _extract_flag(text, own_host)


_SUCCESS_STOP_REASONS = frozenset({"solved"})


def _answer_is_empty(value: Any) -> bool:
    """Whether an answers-map value carries no answer."""
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    return False


def _read_previous_result(path: Path) -> dict[str, Any] | None:
    """Read an existing result file for merge, treating damage as absence.

    A half-written or hand-edited file must never block the new write: the
    platform can only grade what is on disk now, and refusing to write because
    the old bytes are unparseable would turn a recoverable run into no result
    at all.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _merge_result_payload(
    previous: dict[str, Any] | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Merge answers from a previous run into the new payload.

    A platform restart starts a fresh run with an empty ``answers`` map.  The
    old file is the only place the earlier run's flags survive, so replacing it
    wholesale silently downgrades a solved challenge.  Both runs may also have
    found different things, so the per-key rule is: a non-empty new value wins;
    a missing/empty new value leaves the old value in place.

    Non-answer fields follow the new run, with one guard: when the old file
    held answers and this run found none, a success ``stop_reason`` must not be
    rewritten as an unsolved/unclean one.  The previous reason is always kept
    in ``previous_stop_reason`` for triage.
    """
    merged = dict(payload)
    if previous is None:
        return merged

    old_answers = previous.get("answers")
    new_answers = payload.get("answers")
    old_map = old_answers if isinstance(old_answers, dict) else {}
    new_map = new_answers if isinstance(new_answers, dict) else {}

    merged_answers = dict(old_map)
    for key, value in new_map.items():
        if _answer_is_empty(value) and not _answer_is_empty(merged_answers.get(key)):
            continue
        merged_answers[key] = value
    merged["answers"] = merged_answers

    old_had_answers = any(not _answer_is_empty(v) for v in old_map.values())
    new_has_answers = any(not _answer_is_empty(v) for v in new_map.values())
    if old_had_answers and not new_has_answers:
        old_stop = previous.get("stop_reason")
        merged["previous_stop_reason"] = old_stop
        if old_stop in _SUCCESS_STOP_REASONS and merged.get("stop_reason") not in _SUCCESS_STOP_REASONS:
            merged["stop_reason"] = old_stop

    return merged


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    """原子写 result.json，并合并上一版 answers。

    先写临时文件再 rename：中途被杀不会留下半截 JSON —— 半截 JSON 比没有文件更糟，
    因为平台会尝试解析它然后再报错，把"超时"变成"格式错误"。

    平台重启后的新 run 从空 answers 起步；若直接覆盖，上一轮已经找到的 flag
    会随文件一起消失。合并只发生在 answers 上，其余字段仍以本次 payload 为准。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = _merge_result_payload(_read_previous_result(path), payload)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


#: ``finish_scan`` is a local strix tool with an SDK-level 60 s timeout.  Bound
#: each call below that so a platform-side stall becomes a model-visible result
#: we can count, instead of an SDK timeout message the wrapper never sees.
_FINISH_DEGRADE_TIMEOUT_SECONDS = 50.0
#: Consecutive timeouts before the tool is bypassed and answers are persisted.
_FINISH_DEGRADE_STREAK = 2


def _has_answers(answers: dict[str, Any]) -> bool:
    return any(not _answer_is_empty(value) for value in answers.values())


class _FinishDegradationState:
    """Consecutive-timeout counter for the finish_scan degradation path."""

    __slots__ = ("consecutive_timeouts", "degraded")

    def __init__(self) -> None:
        self.consecutive_timeouts = 0
        self.degraded = False


def _persist_degraded_finish(
    result_path: Path,
    answers: dict[str, Any],
    *,
    reason: str,
) -> None:
    """Write the known answers before the run can be restarted.

    This is deliberately a minimal payload: ``main``'s ``finally`` writes the
    full one.  The point is that a process killed after a hung finish_scan
    leaves a graded file behind, and ``_write_result`` merges it with any
    earlier run's answers.
    """
    tokens = _usage_snapshot()
    solved = _has_answers(answers)
    payload: dict[str, Any] = {
        "schema_version": BRIEF_SCHEMA_VERSION,
        "answers": dict(answers),
        "turns": 0,
        "input_tokens": tokens["input_tokens"],
        "output_tokens": tokens["output_tokens"],
        "stop_reason": "solved" if solved else "completed",
        "writeup": reason,
    }
    try:
        _write_result(result_path, payload)
        print(f"[ctfy] degraded finish persisted to {result_path}", flush=True)
    except OSError as exc:  # noqa: BLE001 -- degradation must not raise
        print(f"[ctfy] degraded finish write failed: {exc}", flush=True)


def _finish_timeout_message(*, attempt: int, degraded: bool, has_answers: bool) -> str:
    if degraded and has_answers:
        instruction = (
            "FINISH_SCAN IS UNAVAILABLE after two consecutive timeouts. Your "
            "known answers were already written to result.json. Do not call "
            "finish_scan again; end the run now."
        )
    elif degraded:
        instruction = (
            "FINISH_SCAN IS UNAVAILABLE after two consecutive timeouts. Keep "
            "working with the other tools; result.json is written at run end."
        )
    else:
        instruction = (
            f"finish_scan timed out (attempt {attempt} of "
            f"{_FINISH_DEGRADE_STREAK}). Your known answers are unchanged. "
            "Retry finish_scan once; after the next timeout it is bypassed and "
            "the answers already in result.json are kept."
        )
    return json.dumps(
        {"success": False, "scan_completed": False, "error": instruction},
        ensure_ascii=False,
    )


def install_finish_degradation(
    answers: dict[str, Any],
    result_path: Path,
    *,
    diag: dict[str, Any] | None = None,
) -> _FinishDegradationState:
    """Bypass a hung ``finish_scan`` after two consecutive timeouts.

    The tool is strix's own (not a platform MCP tool) and the SDK's 60 s limit
    is a property of that local tool, so the agent side can control this.  The
    wrapper sits outermost and waits less than the SDK limit; a timeout becomes
    a normal tool observation we can count.  On the second consecutive timeout
    it persists the known answers and tells the model the tool is unavailable.
    A later finish call then raises ``SolvedStop`` when there is an answer, so
    the process exits cleanly through ``main`` instead of being restarted.
    """
    import asyncio

    from strix.agents import factory

    state = _FinishDegradationState()
    original = factory._with_bounded_result

    def patched(tool: Any) -> Any:
        tool = original(tool)
        if getattr(tool, "name", "") != "finish_scan":
            return tool
        if getattr(tool, "_ctf_finish_degraded", False):
            return tool
        inner = tool.on_invoke_tool

        async def invoke(ctx: Any, raw_input: str) -> Any:
            if state.degraded:
                if _has_answers(answers):
                    _persist_degraded_finish(
                        result_path,
                        answers,
                        reason=(
                            "finish_scan timed out twice; known answers were "
                            "persisted and the run exited through the normal "
                            "SolvedStop path."
                        ),
                    )
                    raise SolvedStop(
                        "finish_scan unavailable after repeated timeouts; "
                        "answers already persisted"
                    )
                return _finish_timeout_message(
                    attempt=state.consecutive_timeouts,
                    degraded=True,
                    has_answers=False,
                )

            try:
                result = await asyncio.wait_for(
                    inner(ctx, raw_input),
                    timeout=_FINISH_DEGRADE_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                state.consecutive_timeouts += 1
                if state.consecutive_timeouts >= _FINISH_DEGRADE_STREAK:
                    state.degraded = True
                    _persist_degraded_finish(
                        result_path,
                        answers,
                        reason=(
                            "finish_scan timed out twice; the known answers "
                            "were written before the run could be restarted."
                        ),
                    )
                    if diag is not None:
                        diag["finish_degradation"] = "degraded"
                return _finish_timeout_message(
                    attempt=state.consecutive_timeouts,
                    degraded=state.degraded,
                    has_answers=_has_answers(answers),
                )
            except asyncio.CancelledError:
                # The SDK's own 60 s limit fired before ours.  Count it too,
                # then let the SDK produce its standard timeout observation.
                state.consecutive_timeouts += 1
                raise

            state.consecutive_timeouts = 0
            return result

        tool.on_invoke_tool = invoke
        tool._ctf_finish_degraded = True  # type: ignore[attr-defined]
        return tool

    factory._with_bounded_result = patched  # type: ignore[assignment]
    return state


def _goal_dirs() -> list[Path]:
    """goal 文件的候选目录：镜像里的 ``/app/config`` 与本地仓库的 ``config/``。"""
    here = Path(__file__).resolve()
    parents = [here.parents[2] / "config"] if len(here.parents) > 2 else []
    return [*parents, Path.cwd() / "config", here.parent / "config"]


def _read_goal(kind: str = "web") -> str:
    """读对应题型的 goal。

    为什么按题型切：``ctf_goal.txt`` 里写着"不要写报告"，对 engagement 是
    反向指令；checker 题没有 flag，"拿到 flag 才算完成"会把它推向错误方向。

    Args:
        kind: :func:`_challenge_kind` 的返回值。

    Returns:
        完整 goal 文本：preamble + 题型正文；文件缺失时退回内置最小版本。
    """
    name = GOAL_FILES.get(kind, GOAL_FILES["web"])
    parts: list[str] = []
    preamble = _read_goal_file("goal_preamble.txt")
    if preamble:
        parts.append(preamble)
    body = _read_goal_file(name)
    parts.append(body or _FALLBACK_GOALS.get(kind, _FALLBACK_GOALS["web"]))
    return "\n\n".join(parts)


def _read_goal_file(name: str) -> str:
    """在候选目录里找第一个存在的 goal 文件。"""
    for base in _goal_dirs():
        candidate = base / name
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return ""


def _first_int(*values: object) -> int:
    """取第一个能转成正整数的值；全都没有/非法时返回 0。"""
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            continue
        if number > 0:
            return number
    return 0


def _turn_budget(task: dict[str, Any]) -> int:
    """解析 turn 预算。

    协议是 ``absent means no budget``：``task.json`` 与
    ``CTFY_EVAL_MAX_TURNS`` 都没有时**不设上限**。上游
    ``run_strix_scan`` 需要一个正整数，所以退回 strix 自己的
    ``DEFAULT_MAX_TURNS``（500），而不是过去硬编码的 25——25 会在难题上
    提前砍掉 agent，且和"没有预算"矛盾。
    """
    declared = _first_int(
        task.get("max_turns"),
        os.environ.get("CTFY_EVAL_MAX_TURNS"),
        os.environ.get("CTF_MAX_TURNS"),
    )
    if declared:
        return declared
    try:
        from strix.config.settings import DEFAULT_MAX_TURNS

        return int(DEFAULT_MAX_TURNS)
    except Exception:  # noqa: BLE001 — 运行时缺失时给一个足够大的值
        return 500


#: Default idle limit.  Long enough for normal tool-call gaps, far below
#: the 1380s hard wall clock that a dead-target run spent idling.
_IDLE_DEFAULT_SECONDS = 150.0


class IdleTimeout(BaseException):
    """No tool call arrived for longer than the idle limit.

    ``BaseException`` for the same reason as :class:`WallclockExceeded`:
    the runner and the tool wrappers are full of ``except Exception``, and
    a swallowed stop would hand control back to the idle loop this exists
    to break.

    Evidence: a dead-target run on 2026-11-06 spent 121 turns / 120 LLM requests
    on 6 tool calls, then idled ~20 minutes waiting for the wall clock.
    """


class IdleWatchdog:
    """Pure clock arithmetic for the idle check (no threads, no sleeping).

    Two states, and the difference is the whole point:

    * **unarmed** (``_last is None``): the clock has not started.  Nothing
      can expire, because no model or tool event has been seen yet.  A run
      spends up to a minute in sandbox boot plus the first LLM response
      before its first event; counting that as "idle" (that run's
      watchdog reported ``turns=0`` on a cold start) kills a healthy run.
    * **armed** (``_last`` is a timestamp): the last *tool* event.  The sink
      arms once on the first model/tool event of an attempt
      (:meth:`arm`), then refreshes on every tool call *and its output*
      (:meth:`note_activity`).  Long prose alone never refreshes it, so a
      model that stops calling tools still trips at a round boundary.

    The sink only *checks* :meth:`expired` at round boundaries; streaming
    deltas are not a decision point.  Keeping the arithmetic here lets unit
    tests pass explicit timestamps instead of sleeping.
    """

    __slots__ = ("limit", "_last")

    def __init__(self, limit: float, *, now: float | None = None) -> None:
        self.limit = float(limit)
        self._last = None if now is None else float(now)

    @property
    def armed(self) -> bool:
        """True once the clock has seen its first model or tool event."""
        return self._last is not None

    def arm(self, now: float) -> None:
        """Start the clock if it is not started; later calls are no-ops."""
        if self._last is None:
            self._last = float(now)

    def reset(self) -> None:
        """Return to the unarmed state (used at every attempt boundary)."""
        self._last = None

    def note_activity(self, now: float) -> None:
        """Remember that a tool call or tool output was seen at ``now``."""
        self._last = float(now)

    def expired(self, now: float) -> bool:
        """True when ``now`` is at least ``limit`` past the last activity.

        An unarmed clock never expires; so does a non-positive limit,
        matching ``CTF_IDLE_SECONDS=0`` and the wall-clock budget contract.
        """
        if self.limit <= 0 or self._last is None:
            return False
        return (float(now) - self._last) >= self.limit


def _idle_limit_seconds() -> float:
    """Parse ``CTF_IDLE_SECONDS``; default 150, non-positive disables.

    A malformed value falls back to the default instead of disabling the
    watchdog: a typo in an operator env file must not silently restore the
    dead-target failure mode.
    """
    raw = os.environ.get("CTF_IDLE_SECONDS")
    if raw is None:
        return _IDLE_DEFAULT_SECONDS
    try:
        return float(str(raw).strip())
    except (TypeError, ValueError):
        return _IDLE_DEFAULT_SECONDS


#: Run-item types that count as *tool* activity for the idle clock.  Both the
#: call and its output are progress: a tool that runs for minutes is exactly
#: the case the old call-only clock killed.
_TOOL_ACTIVITY_TYPES: tuple[str, ...] = ("tool_call_item", "tool_call_output_item")

#: Run-item types that may *start* the clock.  They are all model or tool
#: output (``openai-agents`` item types), so sandbox-boot or MCP setup traffic
#: -- which is neither -- cannot arm it.  ``message_item`` is kept alongside
#: the SDK spelling for older fakes in the test suite.
_MODEL_ITEM_TYPES: tuple[str, ...] = (
    "message_item",
    "message_output_item",
    "reasoning_item",
    "tool_call_item",
    "tool_call_output_item",
    "handoff_call_item",
    "handoff_output_item",
    "tool_search_call_item",
    "tool_search_output_item",
)

#: Raw provider event that closes one model round.  ``openai-agents`` puts a
#: :class:`RawResponsesStreamEvent` on the sink for every provider chunk; only
#: this terminal one (``ResponseCompletedEvent``) means "the model finished
#: speaking, the runner is about to act".  Tool-call run items are emitted at
#: ``response.output_item.done``, i.e. *before* this event, so a long
#: generation that ends in a tool call refreshes the clock first and is never
#: mistaken for idling.
_ROUND_END_EVENT = "response.completed"


def _is_round_boundary(event: object) -> bool:
    """True for the event that ends one LLM round of the streamed run."""
    if getattr(event, "type", None) != "raw_response_event":
        return False
    data = getattr(event, "data", None)
    return getattr(data, "type", None) == _ROUND_END_EVENT


class WallclockExceeded(BaseException):
    """Run 的墙钟预算耗尽。

    故意继承 ``BaseException``：strix 与本模块内部到处是 ``except Exception``，
    普通异常会被吞成一条工具错误然后继续跑；alarm 只响一次，被吞掉就没有
    第二次机会。必须像 ``KeyboardInterrupt`` 一样直达 ``main`` 的收尾，
    让 finally 把 result.json 写出来。
    """


#: 容器路径的墙钟分层（秒），与 ``scripts/batch_eval.py`` 的难度分层同源
#: （easy=1x / medium=1.5x / hard=2.3x，基准 600s）。task.json 不下发墙钟
#: （协议只有 ``max_turns``），评测 harness 的进程组 SIGKILL 也只存在于内部
#: 跑批：正式赛/部署验证走本入口，此前没有任何墙钟，一次挂死的 run 既烧
#: 比赛窗口又写不出 result.json（``no_result_file`` 是 blocking 判据）。
#: 难度未知取 hard 档：成功题 p90=253s、失败题 max=815s，1380s 已是实测
#: 失败上限的 1.7 倍，再紧只会误伤还在推进的题。
_WALL_TIERS: dict[str, int] = {"easy": 600, "medium": 900, "hard": 1380}


def _wall_budget(task: dict[str, Any]) -> int:
    """解析容器路径的墙钟预算（秒）；0 表示关闭。

    优先级：``CTFY_WALL_DEADLINE`` 环境变量（运维显式控制，非法值视为关）
    > task.json 难度分层 > hard 档默认。
    """
    raw = os.environ.get("CTFY_WALL_DEADLINE")
    if raw is not None:
        try:
            return max(int(str(raw).strip()), 0)
        except (TypeError, ValueError):
            return 0
    difficulty = str((task.get("challenge") or {}).get("difficulty") or "").strip().lower()
    return _WALL_TIERS.get(difficulty, _WALL_TIERS["hard"])


def _wallclock_handler(wall_seconds: int, *, guard: Any = None) -> Any:
    """Build the ``SIGALRM`` handler that unwinds ``main`` cleanly.

    Args:
        wall_seconds: Budget used in the exception text.
        guard: Optional predicate checked before raising.  The installed
            handler passes :func:`deadline.armed`; a signal that was already
            in flight when ``main`` entered its ``finally`` block arrives
            after :func:`_cancel_hard_deadline` cleared that flag, and must
            not unwind the cleanup that is writing ``result.json``.
    """

    def _fire(signum: int, frame: Any) -> None:  # noqa: ARG001
        if guard is not None and not guard():
            return
        raise WallclockExceeded(f"wall budget {wall_seconds}s spent")

    return _fire


def _check_soft_timeout() -> None:
    """Raise on the flag-only soft path used where ``SIGALRM`` is absent.

    Called from the event sink, which is the main thread's most frequent
    checkpoint during a run.  A main thread stuck in one C call never reaches
    it; that case is what the daemon's hard exit covers.
    """
    if deadline.soft_timeout_flag.is_set():
        raise WallclockExceeded("wall budget spent (watchdog flag)")


#: 「止损」终止（以下异常类）：都继承 ``BaseException``，会绕过 ``main`` 里的普通收尾。
#: 统计必须在抛出点挂到异常上，否则 result.json 只能写 ``turns=0``、诊断全空。
_STOP_TYPES: tuple[type[BaseException], ...] = (
    SolvedStop,
    RecoveryExhausted,
    WallclockExceeded,
    OutputBudgetExceeded,
    IdleTimeout,
    TargetAbsent,
    EnumExhausted,
)


def _attach_stop_state(exc: BaseException, turns: int, diag: dict[str, Any]) -> None:
    """把 ``_run_agent`` 的轮次与诊断挂到止损异常上。

    用属性而不是构造参数：这些异常在 sink、恢复守卫、用量表等多个位置抛出，
    改构造签名要波及每一处调用，也盖不住将来新增的抛出点。挂载失败不影响
    异常本身继续向上抛——止损语义不能被诊断拖累。
    """
    try:
        exc.stop_turns = max(int(turns), 0)  # type: ignore[attr-defined]
        exc.stop_diag = dict(diag)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return


def _take_stop_state(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """取回 :func:`_attach_stop_state` 挂上的快照；没有时给 ``(0, {})``。"""
    raw_turns = getattr(exc, "stop_turns", 0)
    try:
        turns = max(int(raw_turns), 0)
    except (TypeError, ValueError):
        turns = 0
    raw_diag = getattr(exc, "stop_diag", None)
    return turns, dict(raw_diag) if isinstance(raw_diag, dict) else {}


#: Whether :func:`_install_hard_deadline` created the shared deadline itself.
#: If it did, :func:`_cancel_hard_deadline` must clear it: otherwise an
#: in-process test/embedded caller leaves the next run already out of clock.
_deadline_owned = False

#: Whether this process currently has the ``SIGALRM`` handler installed.  A
#: run with no wall budget must not rewrite a caller's signal disposition.
_signal_installed = False


def _install_hard_deadline(
    wall_seconds: int,
    *,
    result_path: Path | None = None,
    schema_version: int | None = None,
) -> bool:
    """Install the two-stage wall-clock watchdog.

    Stage one is a signal/fast-flag request to unwind ``main`` so its normal
    cleanup writes ``result.json`` (``stop_reason="wallclock"``).  Stage two
    is a daemon thread that survives a main thread stuck in a C call: after
    the shared shutdown reserve it writes a fallback file and calls
    ``os._exit``.  Windows has no ``SIGALRM``; there the daemon still runs.

    The absolute deadline lives in :mod:`error_policy`.  When the caller has
    not set one yet (unit tests, embedded callers), this creates it from the
    same ``monotonic`` clock rather than introducing a second one.

    Args:
        wall_seconds: Run wall budget; non-positive disables the watchdog.
        result_path: Destination for the hard-path fallback file.
        schema_version: Protocol schema version for that fallback.

    Returns:
        ``True`` when the watchdog (daemon thread and/or signal handler) is
        armed.
    """
    if wall_seconds <= 0:
        # Documented contract: a non-positive budget disables the watchdog.
        # That must also stop an earlier in-process watchdog; merely declining
        # to install a new one would leave the old deadline armed.
        deadline.cancel()
        return False

    global _deadline_owned  # noqa: PLW0603 - process-wide run state
    if _deadline_owned:
        # An earlier run created the deadline and never cleaned up (hard kill
        # superseded it, or a unit test aborted).  Rebase it on this run's
        # budget: a stale past deadline would fire the new watchdog at once.
        error_policy.set_wall_deadline(_llm_wall_deadline(wall_seconds))
    if error_policy.remaining_wall() is None:
        error_policy.set_wall_deadline(_llm_wall_deadline(wall_seconds))
        _deadline_owned = True

    global _signal_installed  # noqa: PLW0603 - process-wide run state
    armed = False
    try:
        signal.signal(
            signal.SIGALRM,
            _wallclock_handler(wall_seconds, guard=deadline.armed),
        )
        armed = True
        _signal_installed = True
    except (AttributeError, ValueError, OSError):
        # No SIGALRM (Windows) or not the main thread: the daemon's flag is
        # the only soft channel, and the hard exit is the real guarantee.
        pass

    try:
        installed = deadline.install(
            wall_seconds,
            result_path=result_path,
            schema_version=BRIEF_SCHEMA_VERSION
            if schema_version is None
            else schema_version,
            signal_armed=armed,
        )
    except BaseException as exc:  # noqa: BLE001 - install must not escape main
        # ``main`` calls this before its try/finally.  An exception here used
        # to escape without writing result.json; nothing below needs it.
        installed = False
        print(
            f"[ctfy] warning: watchdog install failed: {type(exc).__name__}: {exc}",
            flush=True,
        )
    if not installed:
        # There is no ``signal.alarm`` anymore: an armed handler with no
        # daemon never fires.  Reporting the signal arm as success would be a
        # lie, so fail loudly and let the caller see that timeouts are off.
        print(
            "[ctfy] warning: watchdog not installed (no live deadline); "
            "the wall-clock hard stop is OFF",
            flush=True,
        )
    return installed


def _cancel_hard_deadline() -> None:
    """Stop the watchdog before cleanup writes ``result.json``.

    Cancelling only invalidates the daemon: a late ``SIGALRM`` would still
    unwind the very cleanup that is writing the file.  POSIX therefore also
    points ``SIGALRM`` at ``SIG_IGN`` for the remainder of the process; the
    next run reinstalls its handler.
    """
    global _deadline_owned, _signal_installed  # noqa: PLW0603 - run state
    # Disarm first: a handler dispatched by an in-flight signal between these
    # lines must see the flag and return instead of raising into cleanup.
    deadline.cancel()
    if not _signal_installed:
        # Nothing of ours is armed.  Leave a caller-installed SIGALRM (or the
        # platform default) alone.
        if _deadline_owned:
            error_policy.clear_wall_deadline()
            _deadline_owned = False
        return
    alarm = getattr(signal, "SIGALRM", None)
    if alarm is not None:
        # Block first: a signal already in flight must not interrupt the
        # transition below.  It is discarded once the disposition is IGN.
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {alarm})
        except (AttributeError, OSError, ValueError):
            pass
    try:
        signal.alarm(0)
    except (AttributeError, ValueError, OSError):
        pass
    try:
        signal.signal(signal.SIGALRM, signal.SIG_IGN)
    except (AttributeError, ValueError, OSError):
        pass
    if alarm is not None:
        try:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {alarm})
        except (AttributeError, OSError, ValueError):
            pass
    _signal_installed = False
    if _deadline_owned:
        error_policy.clear_wall_deadline()
        _deadline_owned = False


def _attempt_count() -> int:
    """How many sequential attempts to allow (1-3).

    Three is the platform's agent-concurrency ceiling; sequential attempts
    stay within it.  Default 1 keeps the old behavior unless explicitly
    enabled, because a second attempt roughly doubles wall-clock demand.
    """
    try:
        value = int(str(os.environ.get("CTF_ATTEMPTS", "1")).strip())
    except (TypeError, ValueError):
        return 1
    return max(1, min(value, 3))


def _attempt_turns(total: int, attempts: int, split: float) -> list[int]:
    """Split a turn budget across attempts, giving the first one `split`."""
    if attempts <= 1:
        return [total]
    first = max(1, int(round(total * split)))
    first = min(first, total - (attempts - 1))
    rest = total - first
    base, extra = divmod(rest, attempts - 1)
    return [first] + [base + (1 if i < extra else 0) for i in range(attempts - 1)]


def _is_turn_exhausted(exc: BaseException) -> bool:
    """这次异常是不是「turn 预算用尽」，而不是「运行时没起来」。

    两者都是异常，但在 result.json 里的含义完全相反：前者说明模型整整跑了
    一个预算却没交生命周期调用（失败但健康），后者说明一次 run 都没启动。
    2026-11-06 v6 冒烟里 ``max_turns=3`` 走了前者，却被记成 ``error`` +
    「所有 attempt 都未能启动运行时」，把失败率的口径污染了。
    """
    # 名字先判：vendor 的 ``_exhausted_recovery`` 与 SDK 用的是同名异类，
    # 一旦 import 路径变了，靠 isinstance 会静默退化成 "error"。
    if type(exc).__name__ == "MaxTurnsExceeded":
        return True
    try:
        from agents.exceptions import MaxTurnsExceeded
    except Exception:  # noqa: BLE001 - 运行时不在时按普通异常处理
        return False
    return isinstance(exc, MaxTurnsExceeded)


def _llm_wall_deadline(wall_seconds: int) -> float | None:
    """Absolute ``monotonic`` deadline for the LLM retry policy.

    ``0`` means the run is unbounded (see :func:`_wall_budget`); the policy
    then falls back to its attempt cap.  A positive budget is measured from
    process start, matching the alarm installed in :func:`main`.
    """
    if wall_seconds <= 0:
        return None
    return time.monotonic() + wall_seconds


def _local_attachments(work: Path) -> list[dict[str, str]]:
    """把工作目录里的附件读成 strix 的 ``extra_files``。

    平台可能把附件直接放在 ``$CTFY_WORK_DIR``（或 ``attachments/`` /
    ``files/`` 子目录）。strix 的 sandbox 是私有临时目录，不注入的话 agent
    看不见这些文件。找不到任何文件时返回空列表，行为与改造前一致。

    **所有题型都要注入**，不只是附件题：web 题也常带附件（一次 web 题的
    admin slug 就写在 ``setup.txt`` 里），漏注入等于把题目的一半线索丢掉。

    Returns:
        ``[{"workspace_path": "/workspace/<name>", "content": ...}]``。
    """
    roots = [work, work / "attachments", work / "files"]
    found: list[Path] = []
    # ``attachments/`` 既会被 work 的 rglob 扫到，也会被它自己的 root 扫到；
    # 不去重就会把同一个文件注入两次，strix 会静默丢掉后一份。
    seen: set[Path] = set()
    # 平台自己写进工作目录的文件不是附件。混进去只会浪费 sandbox 的注入配额，
    # 还会让 agent 把 result.json 当成题目材料读。
    # ``mcp.json`` is the platform's own client configuration, not a
    # challenge file: injecting it would both waste an ``extra_files`` slot
    # and put the endpoint/token header in front of the model.
    reserved = _RESERVED_WORK_FILES
    # 本地调试时 ``CTFY_WORK_DIR`` 常常没设，cwd 是仓库根。不排掉这些目录的话
    # 会把整个源码树当成附件打包（50 个文件配额一次就满），还会让 agent 读到
    # 评测脚本里的常量——有一次就是这么把套题 id 当 flag 交上去的。
    skip_dirs = {
        ".git", ".venv", "__pycache__", ".pytest_cache", "node_modules",
        "src", "vendor", "tests", "docs", "reports", "scripts", "docker",
        "skills_strix", "aisec", "config", "LICENSES",
    }
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if any(part in skip_dirs for part in path.relative_to(root).parts[:-1]):
                continue
            if not path.is_file() or path.name in reserved:
                continue
            if path.suffix in {".tmp", ".log", ".pyc"} or path.name.startswith("."):
                continue
            if path in seen:
                continue
            seen.add(path)
            found.append(path)

    import base64

    out: list[dict[str, str]] = []
    for path in found[:50]:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        # 用相对工作目录的路径当 workspace 路径：子目录里的同名附件（很常见：
        # 多个 challenge 各有一个 README）不会互相覆盖。
        try:
            rel = path.relative_to(work).as_posix()
        except ValueError:
            rel = path.name
        try:
            out.append({"workspace_path": f"/workspace/{rel}", "content": data.decode("utf-8")})
        except UnicodeDecodeError:
            out.append(
                {
                    "workspace_path": f"/workspace/{rel}.b64",
                    "content": base64.b64encode(data).decode(),
                }
            )
    return out


def _local_attachment_path(work: Path, name: str) -> Path | None:
    """Where ``name`` already sits locally, if anywhere.

    Only bare file names are probed.  A ``../`` from a hostile task.json must not
    make the fetch believe the file is present (or probe outside ``work``).
    """
    safe = _safe_attachment_name(name)
    if safe is None:
        return None
    for base in (work, work / "attachments", work / "files"):
        candidate = base / safe
        if candidate.is_file():
            return candidate
    return None


def _safe_attachment_name(raw: object) -> str | None:
    """Return a bare file name, or None when the platform supplied a path."""
    name = str(raw or "").strip()
    if not name or name in {".", ".."}:
        return None
    if "/" in name or "\\" in name or ":" in name:
        return None
    if Path(name).name != name:
        return None
    return name


def _declared_attachment_names(task: dict[str, Any]) -> list[str]:
    """File names task.json explicitly declares as attachments."""
    out: list[str] = []
    for value in (task.get("attachments"), task.get("files")):
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, str):
                name = item.strip()
            elif isinstance(item, dict):
                name = str(item.get("name") or item.get("filename") or "").strip()
            else:
                continue
            if name and name not in out:
                out.append(name)
    return out


def _declared_specs(task: dict[str, Any]) -> dict[str, "attach.FileSpec"]:
    """Attachment names task.json declares, in declaration order.

    Sizes are not declared there, so these entries carry ``size=None`` and a
    download is validated against whatever the channel's own listing said.
    """
    specs: dict[str, "attach.FileSpec"] = {}
    for name in _declared_attachment_names(task):
        safe = attach.safe_attachment_name(name)
        if safe is not None:
            specs.setdefault(safe, attach.FileSpec(name=safe))
    return specs


def _fetch_platform_attachments(task: dict[str, Any], work: Path) -> list[Path]:
    """Download this challenge's attachments, one channel at a time per file.

    The challenge-level REST endpoint is authoritative when it answers, but a
    run token can be refused there (403) while the platform's own MCP endpoint
    still serves the same bytes.  Degrading per *file* rather than per channel
    matters because a listing can succeed while one download fails: treating
    the channel as all-or-nothing leaves that file missing and the challenge
    on the ``no_target`` path.

    Order: the instance-level listing when the task names an instance (it is
    the only source for per-team artifacts), then the challenge-level REST
    listing, then MCP for anything still missing.  A listing is always asked
    for -- a directory holding one old file must not hide the two the platform
    now ships -- but a name already on disk is never downloaded twice.

    Best effort by contract: an unreachable platform, 403, malformed JSON or a
    timeout leaves the caller on its previous path.  Nothing is raised, and no
    token or authorization header reaches the log.

    Args:
        task: Parsed task.json (``platform_url`` / ``challenge.id``).
        work: Challenge working directory.

    Returns:
        Paths written by this call; empty when nothing was fetched.
    """
    token = _platform_token(task)
    # MCP may authenticate with a different variable than the REST token; its
    # expanded Authorization header is collected below and redacted too.
    secrets: list[str] = [token] if token else []
    try:
        declared = _declared_specs(task)
        # task.json names every file and every one is already on disk: no
        # request is worth making.  (A directory with *some* file is not the
        # same thing; then the listing still has to decide what is missing.)
        if declared and all(_local_attachment_path(work, name) for name in declared):
            return []

        targets = dict(declared)
        instances = _attachment_instance(task)
        platform = _platform_url(task)
        challenge_id = _challenge_id(task)

        deadline = time.monotonic() + _ATTACHMENT_TIMEOUT
        # A hanging REST call would otherwise spend the whole budget and leave
        # the MCP channel 0.1s: reserve half for that hop.
        rest_deadline = time.monotonic() + _ATTACHMENT_TIMEOUT / 2
        written: list[Path] = []
        used: list[str] = []

        def have(name: str) -> bool:
            return _local_attachment_path(work, name) is not None

        def skip(name: str) -> bool:
            # A file already on disk is never fetched twice.
            return have(name)

        def absorb(result: "attach.ChannelResult") -> None:
            """Record a channel's listing and write whatever it fetched."""
            used.append(result.channel)
            for spec in result.files:
                safe = attach.safe_attachment_name(spec.name)
                if safe is not None:
                    # A real size beats "not declared in task.json".
                    known = targets.get(safe)
                    if known is None or known.size is None:
                        targets[safe] = attach.FileSpec(
                            name=safe, size=spec.size, per_team=spec.per_team
                        )
            for name, blob in result.blobs.items():
                if have(name):
                    continue
                # The REST listing's size is authoritative even when the bytes
                # arrive from MCP: one channel must not be able to smuggle in a
                # different file than the one the first channel described.
                claimed = targets.get(name)
                if claimed is not None and claimed.size is not None:
                    if len(blob) != claimed.size:
                        print(
                            f"[ctfy] attachment {name} not saved: size mismatch "
                            f"(listed {claimed.size}, got {len(blob)})",
                            flush=True,
                        )
                        continue
                try:
                    _write_bytes_atomic(work / "attachments" / name, blob)
                except OSError as exc:
                    print(
                        f"[ctfy] attachment {name} not saved: "
                        f"{type(exc).__name__}: {attach.redact(exc, secrets)}",
                        flush=True,
                    )
                    continue
                written.append(work / "attachments" / name)
            if result.errors:
                detail = "; ".join(attach.redact(e, secrets) for e in result.errors[:4])
                print(f"[ctfy] {result.channel}: {detail}", flush=True)
            print(f"[ctfy] {result.status()}", flush=True)

        rest_listed = False

        # 1. Instance-level REST first: per-team files have no other source.
        if platform and instances and token:
            result = attach.fetch_rest_instance(
                platform,
                instances[0],
                token,
                names=None,
                should_skip=skip,
                deadline=rest_deadline,
            )
            rest_listed = result.listed or rest_listed
            absorb(result)

        # 2. Challenge-level REST listing.  It supplies sizes, which then let
        #    every later channel validate length.
        if platform and challenge_id:
            result = attach.fetch_rest_challenge(
                platform,
                challenge_id,
                token,
                names=None,
                should_skip=skip,
                deadline=rest_deadline,
            )
            rest_listed = result.listed or rest_listed
            absorb(result)

        # 3. MCP for whatever is still missing: the same platform config the
        #    model may already be using, so its endpoint and header stay
        #    authoritative.  When REST listed, it already named every file and
        #    MCP only has to download the remainder.
        missing = [name for name in targets if not have(name)]
        need_listing = not targets and not rest_listed
        if missing or need_listing:
            config, why = attach.load_mcp_config(work)
            if config is not None:
                secrets.extend(config.secrets)
            if config is None:
                print(f"[ctfy] mcp attachment channel skipped: {why}", flush=True)
            elif not challenge_id:
                print(
                    "[ctfy] mcp attachment channel skipped: no challenge id",
                    flush=True,
                )
            else:
                result = attach.fetch_mcp(
                    config,
                    challenge_id,
                    names=None if need_listing else missing,
                    should_skip=skip,
                    deadline=deadline,
                )
                absorb(result)

        if written:
            print(
                f"[ctfy] fetched {len(written)} attachment(s) from platform "
                f"(channels: {', '.join(dict.fromkeys(used)) or 'none'})",
                flush=True,
            )
        elif targets:
            print(
                "[ctfy] attachment fetch incomplete: "
                f"{len([n for n in targets if not have(n)])} file(s) still missing",
                flush=True,
            )
        return written
    except Exception as exc:  # noqa: BLE001 - last-resort guard for the caller
        print(
            f"[ctfy] attachment fetch failed: {type(exc).__name__}: "
            f"{attach.redact(exc, secrets)}",
            flush=True,
        )
        return []


def _attachment_instance(task: dict[str, Any]) -> list[str]:
    """Instance ids this run can address for attachment downloads."""
    raw = os.environ.get("CTFY_EVAL_TARGET_INSTANCE") or task.get("target_instance")
    out: list[str] = []
    if isinstance(raw, str) and raw.strip():
        out.append(raw.strip())
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, str) and entry.strip() and entry.strip() not in out:
                out.append(entry.strip())
    return out


def _write_bytes_atomic(path: Path, blob: bytes) -> None:
    """Write bytes via a temp sibling plus ``os.replace`` (no half files)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_bytes(blob)
        os.replace(tmp, path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass


def _platform_url(task: dict[str, Any]) -> str:
    """Platform root URL from the environment or task.json (no hardcoding)."""
    raw = (
        os.environ.get("CTFY_PLATFORM_URL")
        or task.get("platform_url")
        or task.get("platform")
        or ""
    )
    return str(raw).strip().rstrip("/")


def _challenge_id(task: dict[str, Any]) -> str:
    """Challenge id from the environment or task.json."""
    raw = (
        os.environ.get("CTFY_EVAL_CHALLENGE_ID")
        or task.get("challenge_id")
        or (task.get("challenge") or {}).get("id")
        or ""
    )
    return str(raw).strip()


def _platform_token(task: dict[str, Any]) -> str:
    """Bearer token the platform injected for player API calls."""
    return (
        os.environ.get("CTFY_TOKEN")
        or os.environ.get("CTF_PLATFORM_TOKEN")
        or str(task.get("token") or "")
    ).strip()


#: CTFY-0001 v3 的 ``schema_version``（规范版本号 == wire schema 版本）。
#: ⚠️ 必须写进 result.json：`inspect_probe` 会因为缺它而报 `no_schema_version`
#: （advisory，不 blocking，但白送的告警没有理由留着）。
#: 2026-10-30 修订把协议从 2 提到 3（平台替你起靶、scope 只留 engagement），
#: 写 2 等于自报一个不认识 ``target_endpoints`` 的旧客户端。
BRIEF_SCHEMA_VERSION = 3


def main() -> int:
    """执行一次 CTFY run。

    Returns:
        恒为 0。CTFY 用 result.json 判断成败，进程退出码只表示"框架跑完了"。
        返回非 0 会被记为崩溃，掩盖真正的解题结果。
    """
    work = _work_dir()
    task = _read_task(work)
    result_path = _result_path(work, task)

    # 必须最先做：平台给的是 LLM_BASE_URL / LLM_MODEL，strix 读的是
    # LLM_API_BASE / STRIX_LLM。晚一步，模型请求就打到默认端点上去了。
    from ctf_strix.platform_env import normalise as normalise_env

    env_applied = normalise_env()
    if env_applied:
        print(f"[ctfy] env bridged: {env_applied}", flush=True)

    started = time.time()
    # 墙钟兜底（接线修复，背景见 _WALL_TIERS）：此前时间限制只在评测
    # harness 里生效，本入口没有。软截止同步设为墙钟的 75%（与 harness
    # ``_deadline_args`` 同口径）；已显式设置的 CTFY_SOFT_DEADLINE 不覆盖。
    wall_budget = _wall_budget(task)
    error_policy.set_wall_deadline(_llm_wall_deadline(wall_budget))
    if wall_budget > 0:
        os.environ.setdefault("CTFY_SOFT_DEADLINE", str(max(int(wall_budget * 0.75), 1)))
        if _install_hard_deadline(
            wall_budget,
            result_path=result_path,
            schema_version=BRIEF_SCHEMA_VERSION,
        ):
            print(f"[ctfy] wall budget {wall_budget}s installed", flush=True)
    answers: dict[str, str] = {}
    error: str | None = None
    stop_reason = "completed"
    turns_used = 0
    all_qids = _question_ids(task)
    qid = all_qids[0]
    # Ids whose value came from mirroring a sibling answer rather than from the
    # target. Kept here so a real answer found later can replace the guess.
    mirrored: set[str] = set()
    diag: dict[str, Any] = {}
    # 平台请求放在 try 里面：墙钟 ``WallclockExceeded`` 继承 BaseException，
    # 在 try 外等待网络会让它直接逃出 main，连 result.json 都写不出来。
    kind = "web"
    attachments: list[dict[str, str]] = []
    publisher = None

    try:
        if _truthy(task.get("dry_run")) or _truthy(os.environ.get("CTFY_EVAL_DRY_RUN")):
            # 平台在 dry run 里只验两件事：容器能起、能按地址写出 result 文件。
            # 真去打靶机既浪费时间（DRY_RUN_BUDGET_S=180s 后被标记
            # dry_run_ignored），又会在没有评分的情况下消耗模型调用。
            # 源码原话：写这个文件并 exit 0 就算通过。
            stop_reason = "dry_run"
            error = None
        else:
            # 平台不一定把附件投进工作目录，task.json 的 ``attachments`` 也可能是
            # 空数组。先按题从选手 API 拉一遍，让 kind 判定能看到附件；失败只是
            # warning，维持原来的 no_target 路径。
            _fetch_platform_attachments(task, work)
            kind = _challenge_kind(task, work)
            # 附件只读一次：main 要用它判断"附件题是不是空的"，_run_agent 要把它
            # 注入 sandbox。读两遍等于把同一批文件从磁盘搬两遍。
            #
            # ⚠️ **所有题型**都要收集，不只是 file：web 题也常带附件（一次 web 题
            # 的 admin slug 就写在 setup.txt 里），漏注入等于把题目的一半线索丢掉。
            attachments = _local_attachments(work)
            specs = _target_specs(task)
            scope = _raw_scope(task)
            if not specs and not (kind == "engagement" and scope) and kind != "file":
                # 写清楚是"模式不匹配"，不是"agent 傻了"。
                #
                # v3 起靶机由平台负责（``target_instance``），客户端调
                # ``POST /api/v1/instances`` 会被 403。所以这里不再有
                # "自己起靶机"这一步可选；目标为空只能是 task.json 没给地址。
                error = (
                    f"无可扫描目标：run_mode={task.get('run_mode')} "
                    f"scope={task.get('scope')} "
                    f"target_endpoints={task.get('target_endpoints')} "
                    f"target_instance={task.get('target_instance')}"
                )
                stop_reason = "no_target"
            elif kind == "file" and not specs and not attachments:
                error = "附件题但没有可读附件（工作目录为空）"
                stop_reason = "no_target"
            else:
                if kind == "engagement":
                    # 报告投递在进运行时**之前**建好：运行时起不来时，
                    # result.json 里仍然有"投递是否配置齐全"这条诊断。
                    publisher = _make_publisher(task)
                    print(
                        f"[ctfy] report delivery configured={publisher.configured()}",
                        flush=True,
                    )
                turns_used, diag = _run_agent(
                    task,
                    answers,
                    qid,
                    kind=kind,
                    attachments=attachments,
                    publisher=publisher,
                    qids=all_qids,
                    derived=mirrored,
                )
                if (
                    stop_reason == "completed"
                    and (diag.get("success") or {}).get("solved")
                ):
                    # Same spelling as the exception path, so downstream
                    # analysis can count solves without knowing which route
                    # ended the run.
                    stop_reason = "solved"
                if diag.get("llm_errors"):
                    # The key was rejected: no amount of retrying this run
                    # can help, and "error" would hide that from triage.
                    error = "LLM credentials rejected: " + "; ".join(
                        f"{item.get('reason')} status={item.get('status_code')}"
                        for item in diag["llm_errors"]
                    )
                    stop_reason = "credential_failure"
                if diag.pop("no_attempt_ran", False):
                    # 每个 attempt 都抛异常：这不是"跑了没解出"，是"根本没跑"。
                    # 两者在成功率统计里必须分开，否则根因分析全被污染。
                    # A credential failure above is already the more specific
                    # reason; do not overwrite it with the generic one.
                    if stop_reason != "credential_failure":
                        error = error or "所有 attempt 都未能启动运行时"
                        stop_reason = "error"
                if diag.pop("turns_exhausted", 0) and stop_reason == "completed":
                    # 轮次跑到上限、一次生命周期调用都没交：这是"恢复耗尽"，
                    # 不是崩溃。和 RecoveryExhausted 用同一个 stop_reason，
                    # 下游统计不必再区分异常是从哪一层抛出来的。
                    error = error or (
                        f"turn budget exhausted after {turns_used} turns "
                        "without a lifecycle call"
                    )
                    stop_reason = "recovery_exhausted"

    except SolvedStop as exc:
        # Confirmed success: nothing more to extract, and restarting the run
        # would only risk losing the answer.  Keep any answers already found
        # and write a distinct stop_reason so success is not read as "error".
        error = None
        stop_reason = "solved"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] solved, stopping: {exc}", flush=True)
    except RecoveryExhausted as exc:
        # The runner kept ending turns without a lifecycle call.  This is a
        # failed solve, but it is not a crash: the process is still healthy
        # and result.json must say so.
        error = str(exc)
        stop_reason = "recovery_exhausted"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] {exc}", flush=True)
    except IdleTimeout as exc:
        # Not a crash and not wall-clock exhaustion: the agent stopped
        # calling tools.  A separate reason keeps triage able to tell an
        # idle reasoning loop from slow-but-progressing work.
        error = str(exc)
        stop_reason = "agent_idle"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] {exc}", flush=True)
    except WallclockExceeded as exc:
        # 墙钟到点不是崩溃：已抽到的答案照常进 result.json，归档口径
        # 用 stop_reason 区分开，避免污染"error"的根因分析。
        error = str(exc)
        stop_reason = "wallclock"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] {exc}", flush=True)
    except TargetAbsent as exc:
        # The target answered every probed path with the same non-answer, so
        # no further probing of it can succeed.  Distinct from "error" and
        # from "wallclock": the run stopped on evidence, not on a clock or a
        # crash.  The serial rotation reads this reason and moves on.
        error = str(exc)
        stop_reason = "target_absent"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] {exc}", flush=True)
    except EnumExhausted as exc:
        # The model kept retrying a family that was already hard-blocked
        # instead of changing mechanism.  Every retry used to return fast and
        # still produced a tool call (which refreshed the idle clock), so the
        # run burned its whole turn budget silently.  Same pipeline as
        # TargetAbsent: a stop reason of its own, answers and diagnostics
        # still land in result.json.
        error = str(exc)
        stop_reason = "enum_exhausted"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        print(f"[ctfy] {exc}", flush=True)
    except OutputBudgetExceeded as exc:
        # 单次 LLM 调用输出失控。和墙钟一样是「止损」，不是崩溃：已经
        # 抽到的 answers 照常落盘，但归咎口径必须独立，否则无法从失败
        # 统计里区分「模型想太多」和「代码炸了」。
        error = str(exc)
        stop_reason = "output_budget"
        stop_turns, stop_diag = _take_stop_state(exc)
        turns_used = max(turns_used, stop_turns)
        diag.update(stop_diag)
        info = usage_trip_info() or {}
        diag["output_budget"] = {
            "output_tokens": exc.output_tokens,
            "cap": exc.cap,
            "call": info.get("call"),
            "cumulative_output_tokens": info.get("cumulative_output_tokens"),
            "agent_id": info.get("agent_id"),
        }
        print(f"[ctfy] {exc}", flush=True)
    except BaseException as exc:  # noqa: BLE001 - every failure must land in result.json
        error = f"{type(exc).__name__}: {exc}"
        # A credential rejection can escape the attempt loop when it happens
        # outside a model call (for example during provider setup).  Mark it
        # the same way, so a dead key is never reported as a generic crash.
        if error_policy.classify_error(exc) == "credential_failure":
            stop_reason = "credential_failure"
            detail = error_policy.credential_failure(exc)
            if detail is not None:
                diag.setdefault("llm_errors", []).append(detail)
        else:
            stop_reason = "error"
            traceback.print_exc()

    finally:
        # 先撤看门狗：alarm 在收尾途中响起会把 result.json 也一起带走。
        _cancel_hard_deadline()
        # The retry deadline belongs to this run.  Leaving it set would make
        # the next in-process run start already out of wall clock (tests and
        # embedded callers execute main() more than once per process).
        error_policy.clear_wall_deadline()

        tokens = _usage_snapshot()
        payload: dict[str, Any] = {
            "schema_version": BRIEF_SCHEMA_VERSION,
            "answers": answers,
            # solved 由平台按 submissions 记录自己写，镜像不自称（§3 明确）。
            "turns": turns_used,
            # 规范字段是 input_tokens / output_tokens，不是笼统的 tokens。
            "input_tokens": tokens["input_tokens"],
            "output_tokens": tokens["output_tokens"],
            "stop_reason": stop_reason,
            "writeup": _writeup(task, answers, error, time.time() - started, diag),
        }
        llm_errors = diag.get("llm_errors") if isinstance(diag, dict) else None
        if llm_errors:
            # Top-level so a platform-side triage query can find a dead key
            # without parsing the free-text writeup.
            payload["llm_errors"] = llm_errors
        output_budget = diag.get("output_budget") if isinstance(diag, dict) else None
        if output_budget:
            # Same reason as llm_errors: a stop caused by one runaway call must
            # be queryable without parsing the writeup.
            payload["output_budget"] = output_budget
        success_diag = diag.get("success") if isinstance(diag, dict) else None
        if success_diag:
            # 止损终止与正常收尾共用同一份：只看 stop_reason 分不出"平台确认
            # 已解出"和"跑完没解出"，这条诊断必须能自证。
            payload["success"] = success_diag
        enum_diag = diag.get("enum_guard") if isinstance(diag, dict) else None
        if enum_diag:
            # The counters used to exist only on stdout: a platform-side triage
            # could not see that a family was hard-blocked, how many calls it
            # refused, or that the guard escalated to a stop.  The value is a
            # dict of scalars and lists, so it serialises as-is.
            payload["enum_guard"] = enum_diag
        parallel_diag = diag.get("parallel") if isinstance(diag, dict) else None
        if parallel_diag:
            # Keep the race accounting next to the top-level turns/token totals
            # so an A/B can tell a parallel run from a single-threaded one
            # without parsing the human-readable writeup.
            payload["parallel"] = parallel_diag
        # result.json is the graded artifact: land it before any network I/O.
        # ``publisher.publish`` is synchronous (DNS, redirects, unreachable
        # endpoints) and can burn the whole shutdown reserve; if it ran first,
        # the platform could collect the process with no result file at all.
        # Delivery is best-effort and never mutates the payload.
        try:
            _write_result(result_path, payload)
            print(f"[ctfy] result written to {result_path}")
        except OSError as exc:
            # 连文件都写不出去时，stdout 是最后的通道。虽然平台不读它，
            # 但在本地调试和 CTFY 的 stdout fallback 模式下仍然有意义。
            print(json.dumps(payload, ensure_ascii=False))
            print(f"[ctfy] FATAL: cannot write result file: {exc}", file=sys.stderr)

        # 运行时半路崩掉时，_run_agent 的收尾保存不会执行。这里补一手：只要
        # agent 真的写过报告，就把最后一版再保存一次——报告是唯一交付物，
        # "写好了但没发出去"与"没写"在评分上完全等价。
        if publisher is not None and getattr(publisher, "authored", False):
            try:
                ok, note = publisher.publish(
                    publisher.last_text, force=True, source="agent"
                )
                print(f"[ctfy] report final ok={ok}: {note}", flush=True)
            except Exception as exc:  # noqa: BLE001 — 收尾失败不能影响 result.json
                print(f"[ctfy] report final failed: {type(exc).__name__}: {exc}", flush=True)

    return 0


def _make_publisher(task: dict[str, Any]) -> Any:
    """构造 engagement 的报告投递器。

    放在 ``main`` 里而不是 ``_run_agent`` 里，是为了让投递能力不依赖运行时：
    strix / agents 装不上时，报告仍能先交付一版，`result.json` 里也能写出
    "投递配置是否齐全"这条诊断。

    Args:
        task: 已解析的 task.json。

    Returns:
        :class:`ctf_strix.engagement.ReportPublisher`；import 失败时返回 None。
    """
    try:
        from ctf_strix.engagement import ReportPublisher
        from ctf_strix.engagement import challenge_id_of
        from ctf_strix.engagement import competition_id_of
        from ctf_strix.engagement import platform_of
    except Exception:  # noqa: BLE001 — 投递模块坏了也不能阻止写 result.json
        return None

    # token 的变量名在协议里是 CTFY_TOKEN；评测脚本用 CTF_PLATFORM_TOKEN
    # 转发同一把钥匙。两个都认，避免"报告静默没发"这种最难查的失败。
    token = (
        os.environ.get("CTFY_TOKEN")
        or os.environ.get("CTF_PLATFORM_TOKEN")
        or str(task.get("token") or "")
    )
    return ReportPublisher(
        platform=platform_of(task),
        token=token,
        competition_id=competition_id_of(task),
        challenge_id=challenge_id_of(task),
        min_interval=20.0,
    )


def _new_coordinator() -> Any:
    """Create the coordinator that owns one attempt's agent graph.

    The parallel guard needs the same object the vendored runner registers
    children in.  Returning ``None`` falls back to the runner creating one;
    the guard then cannot observe the graph until a tool call binds it, which
    is still safe but loses the ability to stop children from an event.
    """
    try:
        from strix.core.agents import AgentCoordinator

        return AgentCoordinator()
    except Exception:  # noqa: BLE001 - parallelism must not gate the run
        return None


def _usage_snapshot() -> dict[str, int]:
    """读 token 计量；没装计量器时返回 0（不编数字）。"""
    try:
        from ctf_strix.usage_meter import snapshot

        snap = snapshot()
        return {
            "llm_calls": int(snap.get("llm_calls", 0)),
            "input_tokens": int(snap.get("input_tokens", 0)),
            "output_tokens": int(snap.get("output_tokens", 0)),
        }
    except Exception:  # noqa: BLE001 — 计量失败不能影响结果文件
        return {"llm_calls": 0, "input_tokens": 0, "output_tokens": 0}


def _writeup(
    task: dict[str, Any],
    answers: dict[str, str],
    error: str | None,
    elapsed: float,
    diag: dict[str, Any] | None = None,
) -> str:
    """生成人类可读的运行摘要，进 result.json 的 writeup 字段。"""
    challenge = (task.get("challenge") or {}).get("name", "<unknown>")
    lines = [
        f"challenge: {challenge}",
        f"run_mode: {task.get('run_mode', '<unknown>')}",
        f"elapsed_s: {elapsed:.1f}",
        f"answers: {json.dumps(answers, ensure_ascii=False) if answers else '(none)'}",
    ]
    report = (diag or {}).get("report")
    if report:
        lines.append(f"report_delivery: {json.dumps(report, ensure_ascii=False)}")
    evidence = (diag or {}).get("evidence")
    if evidence:
        # Visible after the fact: a dropped claim is a modelling problem worth
        # reading, not noise to swallow.
        lines.append(f"evidence: {json.dumps(evidence, ensure_ascii=False)}")
    parallel = (diag or {}).get("parallel")
    if parallel:
        lines.append(f"parallel: {json.dumps(parallel, ensure_ascii=False)}")
    if (diag or {}).get("guard_mount") == "failed":
        # Missing guards are not "nothing fired today": the wiring is broken and
        # every later conclusion about guard behaviour is void. Log loudly.
        lines.append("guard_mount: FAILED (guards inert -- see stderr/logs)")
    llm_errors = (diag or {}).get("llm_errors")
    if llm_errors:
        lines.append(f"llm_errors: {json.dumps(llm_errors, ensure_ascii=False)}")
    if error:
        lines.append(f"error: {error}")
    return "\n".join(lines)


def _registered_names() -> frozenset[str]:
    """Return the tool names really present in the scan-agent registry.

    Returns:
        The registered names, or an empty set when the registry is not
        importable (unit tests and the dry-run path do not need it).
    """

    try:
        from strix.agents import factory

        return frozenset(getattr(tool, "name", "") for tool in factory.registered_agent_tools())
    except Exception:  # noqa: BLE001
        return frozenset()


def _measured_groups(kind: str) -> list[str]:
    """Return the catalogue groups whose tools are really in the registry.

    The installer used to report the groups it *tried* to install, so a partial
    failure left the prompt promising a tool that was not there -- the same
    class of drift this whole change removes.  Reading the registry closes it:
    only a name that can actually be called is described.

    Args:
        kind: challenge kind, used to ignore tools not offered to this kind.

    Returns:
        Group names in prompt order, ``base`` excluded (it is always present).
    """

    from ctf_strix import catalogue

    try:
        from strix.agents import factory

        present = {getattr(tool, "name", "") for tool in factory.registered_agent_tools()}
    except Exception:  # noqa: BLE001 — no registry means nothing to promise
        return []

    found = {
        info.group
        for info in catalogue.for_kind(kind)
        if info.group != "base" and info.name in present
    }
    # ``skills`` only appears when skill_route really registered: the
    # rollback env and a failed registration must both remove the prompt
    # promise together with the tool, not leave one behind.
    return [
        group
        for group in ("web", "file", "tcp", "aisec", "skills")
        if group in found
    ]


def _autosubmit_target(task: dict[str, Any]) -> tuple[str, str, str] | None:
    """Resolve ``(platform, instance, token)`` for in-run submissions.

    The protocol guarantees all three on a scored run: ``CTFY_PLATFORM_URL`` and
    ``CTFY_TOKEN`` in the environment, ``target_instance`` in ``task.json``
    (mirrored as ``CTFY_EVAL_TARGET_INSTANCE``).  A dry run has none of them,
    which is why this returns ``None`` instead of guessing -- submitting to an
    empty URL would show up in the log as a network error that looks like the
    platform's fault.

    Returns:
        The three values, or ``None`` when this run has no instance to submit
        against (dry run, qa item, or a local smoke test).
    """
    try:
        from ctf_strix.engagement import platform_of
    except Exception:  # noqa: BLE001 -- a broken report module must not stop scoring
        return None
    platform = platform_of(task)
    instance = str(
        os.environ.get("CTFY_EVAL_TARGET_INSTANCE")
        or task.get("target_instance")
        or ""
    ).strip()
    token = (
        os.environ.get("CTFY_TOKEN")
        or os.environ.get("CTF_PLATFORM_TOKEN")
        or str(task.get("token") or "")
    ).strip()
    if not (platform and instance and token):
        return None
    return platform, instance, token


def _qa_target(task: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """解析 QA 轨的 ``(platform, token, challenge_id, competition_id)``。

    ``run_mode == "qa"`` 的题没有 ``target_instance``：平台按
    ``(challenge_id, competition_id, question_id)`` 记账，提交走
    ``POST /api/v1/qa/submissions``。四个字段缺一个都组装不出合法请求体，
    所以这里要么全给、要么不武装 —— 半成品请求只会换回 422，看起来像平台故障。

    Returns:
        四元组；不是 qa 题或字段不全时返回 ``None``。
    """
    if str(task.get("run_mode") or "").strip().lower() != "qa":
        return None
    try:
        from ctf_strix.engagement import challenge_id_of
        from ctf_strix.engagement import competition_id_of
        from ctf_strix.engagement import platform_of
    except Exception:  # noqa: BLE001 -- a broken report module must not stop scoring
        return None
    platform = platform_of(task)
    token = (
        os.environ.get("CTFY_TOKEN")
        or os.environ.get("CTF_PLATFORM_TOKEN")
        or str(task.get("token") or "")
    ).strip()
    challenge = challenge_id_of(task)
    competition = competition_id_of(task)
    if not (platform and token and challenge and competition):
        return None
    return platform, token, challenge, competition


def install_toolset(task: dict[str, Any], kind: str) -> tuple[str, list[str]]:
    """Register every capability this challenge kind is entitled to.

    Args:
        task: parsed task.json; AI-security gating reads its metadata.
        kind: challenge kind from _challenge_kind.

    Returns:
        (skill routing hint, installer groups that registered).  The groups
        are what prompt.activate describes, which is how registration and
        the Tools section stay in step.
    """

    from ctf_strix.capabilities import install_soft_deadline
    from ctf_strix.capabilities import install_web_capabilities
    from ctf_strix.capabilities import wants_aisec

    # Only kinds with a live web surface pay for the HTTP primitives.  A file or
    # tcp challenge used to register all four unconditionally: 3,829 chars of
    # schema (~843 tokens) on every call, for tools whose target does not exist.
    if kind in ("web", "checker", "engagement"):
        installed, cap_errors = install_web_capabilities()
        print(
            f"[ctfy] web capabilities: "
            f"http_probe={len(installed.get('http_probe', []))} "
            f"discovery={len(installed.get('discovery', []))} "
            f"variants={len(installed.get('variants', []))}",
            flush=True,
        )
        for message in cap_errors:
            print(f"[ctfy] capability failed: {message}", flush=True)
    else:
        print(f"[ctfy] web capabilities skipped (kind={kind})", flush=True)

    # Soft deadline is opt-in: the platform does not publish a per-challenge
    # wall clock, so inventing one would cut hard challenges short.
    soft_seconds = float(os.environ.get("CTFY_SOFT_DEADLINE", "0") or 0)
    if install_soft_deadline(soft_seconds, _turn_budget(task)) is not None:
        print(f"[ctfy] soft deadline {soft_seconds:.0f}s installed", flush=True)

    # 附件题（rev/pwn/misc/crypto）才装文件入口原语；web 题不为它付 schema token。
    if kind in ("file", "tcp"):
        try:
            from ctf_strix import file_triage

            added = file_triage.register()
            print(f"[file] registered {len(added)} tools: {', '.join(added) or '(already present)'}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[file] registration failed: {type(exc).__name__}: {exc}", flush=True)

        # Non-web primitives (decode chain / safe unpack / hex view / raw TCP /
        # batched TCP / ELF peek).  Split by kind: an attachment challenge must
        # not pay for socket schemas and a remote-service challenge must not pay
        # for archive ones.  Kept separate from file_triage on purpose --
        # file_triage answers "what is this?", these answer "what does it say?".
        try:
            from ctf_strix import nonweb

            added = nonweb.register(kind=kind)
            print(f"[nonweb] registered {len(added)} tools: {', '.join(added) or '(already present)'}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[nonweb] registration failed: {type(exc).__name__}: {exc}", flush=True)

    # token 计量：result.json 的 input_tokens / output_tokens 必须是真实值。
    # 计量失败不影响解题，只退化成 0。
    try:
        from ctf_strix.usage_meter import install as install_usage_meter

        install_usage_meter()
    except Exception as exc:  # noqa: BLE001
        print(f"[ctfy] usage meter unavailable: {type(exc).__name__}: {exc}", flush=True)

    # 技能包：12 个方向索引，走 strix 自带的 load_skill。只注册索引、不注册
    # 整包——整包 145 条进 system prompt，其中 133 条是没有 frontmatter 的参考
    # 子文件，对模型零信息量。
    hint = ""
    try:
        from ctf_strix import skillpack

        names = skillpack.register()
        if names:
            hint = skillpack.prompt_hint(names, kind=kind)
            print(f"[ctfy] skills registered={len(names)} ref={skillpack.ref_root()}", flush=True)
        else:
            print("[ctfy] skills pack missing, routing hint not installed", flush=True)
        # skill_route：把观测文本变成确定性方向排名（与 routing 表同一信号
        # 词表、同一优先序），注册失败只少一个工具，不影响解题。
        from ctf_strix import skill_router

        routed = skill_router.register()
        print(f"[ctfy] skill_route registered={len(routed)}", flush=True)
    except Exception as exc:  # noqa: BLE001 — 技能装不上也要能把题跑完
        print(f"[ctfy] skills registration failed: {type(exc).__name__}: {exc}", flush=True)

    # AI 安全能力（指纹 + CVE 匹配）：走官方 register_agent_tools，不改 vendor。
    # 规则库缺失时不注册——挂一个必然报错的工具只会浪费轮次。
    # 2026-11-02: this used to register whenever the rule data was on disk, while
    # the eval harness defaulted CTF_AISEC=0.  The submitted image therefore had
    # three schemas the measured one never had -- the same drift as the web
    # primitives and sweep_guard before it.  One rule now lives in
    # capabilities.wants_aisec and both entrypoints call it.
    aisec_on, aisec_reason = wants_aisec(kind, task)
    try:
        from ctf_strix.aisec import aig_probe
        from ctf_strix.aisec import tools as aisec_tools

        if not aisec_on:
            print(f"[ctfy] aisec off ({aisec_reason})", flush=True)
        elif not aig_probe.data_dir():
            print(f"[ctfy] aisec wanted but rules missing ({aisec_reason})", flush=True)
        else:
            registered = aisec_tools.register()
            print(f"[ctfy] aisec tools={len(registered)} ({aisec_reason})", flush=True)
    except Exception as exc:  # noqa: BLE001 — 增强能力失败不能让整题跑不动
        print(f"[ctfy] aisec registration failed: {type(exc).__name__}: {exc}", flush=True)

    # ── 上下文管理（2026-11-01）────────────────────────────────────────────
    # 两处改动都挂在框架已有的接缝上，vendor 不动：
    #   1) prompt.install()  替换 103,541 字符的通用渗透提示（实测 22,813 token）
    #   2) context.install_history_elision()  每次 LLM 请求前裁剪旧工具输出
    #
    # 依据：043/047 两道 hard 题都在 40 轮用尽时失败，input 2.24M token，
    # 且 strix 自带的 maybe_compact 阈值 180k 在单轮峰值 54k 下永不触发。
    # 详见 src/ctf_strix/context.py 与 src/ctf_strix/prompt.py 的模块注释。
    groups = ["base"]
    try:
        from ctf_strix import context as ctf_context
        from ctf_strix import prompt as ctf_prompt

        # Tell the prompt which kind is running *before* the first render, so
        # the Tools section describes what was actually registered: a file
        # challenge is not told about route_map, and is told about decode_blob.
        groups = ["base", *_measured_groups(kind)]
        ctf_prompt.activate(kind, tuple(groups), _registered_names())
        ctf_prompt.install()
        capper = ctf_context.install()
        print(
            f"[ctx] prompt installed kind={kind} groups={','.join(groups)} "
            f"({len(ctf_prompt.build({}))} chars); "
            f"content cap={capper.cap_chars} chars/output, {capper.arg_cap} chars/args",
            flush=True,
        )
    except Exception as exc:  # noqa: BLE001 — 上下文改造失败必须回落到原行为
        print(f"[ctx] install failed: {type(exc).__name__}: {exc}", flush=True)
    return hint, groups


def _needs_value(answers: dict[str, str], qids: list[str], derived: set[str]) -> bool:
    """True when at least one visible id still lacks evidence of its own.

    A key that exists is not the same as a question that is answered: mirroring
    writes guesses, and a guess must keep the question open so later evidence
    can replace it.

    Args:
        answers: the answer map.
        qids: every visible question id.
        derived: ids whose value is a mirror rather than evidence.

    Returns:
        Whether any visible id is absent or only guessed.
    """
    return any(key not in answers or key in derived for key in qids)


def _record_answer(
    answers: dict[str, str],
    qids: list[str],
    value: str,
    primary: str,
    *,
    derived: set[str],
) -> list[str]:
    """Record a recovered value, and mirror it onto the ids still unanswered.

    ``answers`` is a map keyed by question id, and the platform submits each key
    it finds: an id that is absent scores zero even when the string is right.
    A challenge whose ``questions`` lists two visible ids therefore used to
    score one of them (ledger 4.9: a two-id run kept ``my_fully_solved=false``
    after a correct flag).  Gated ids are never here -- their prompt does not
    exist until an earlier one is answered.

    Two rules keep the mirror honest, and both were learned the hard way:

    * A mirrored value is a **guess**, tracked in ``derived``.  Without that,
      the guess itself looks like a known answer and the real answer for the
      second id -- found later in the same run -- is dropped as "already
      answered".  That is strictly worse than never mirroring.
    * A later finding is evidence for a *different* id when the primary is
      already evidence-backed.  Attributing everything to the primary would
      let the first hit mask the second.

    Args:
        answers: the out-parameter map.
        qids: every visible question id, in declaration order.
        value: the recovered answer.
        primary: the id this value was derived for; preferred when it is open.
        derived: ids whose current value is a mirror, not evidence.  Mutated.

    Returns:
        The ids written, attribution target first; empty when every visible id
        already holds evidence.
    """
    target = primary if primary not in answers or primary in derived else None
    if target is None:
        target = next((key for key in qids if key in derived), None)
    if target is None:
        return []

    answers[target] = value
    derived.discard(target)
    written = [target]
    for key in qids:
        if key == target:
            continue
        if key in answers and key not in derived:
            continue  # real answer for that question: never overwrite it
        answers[key] = value
        derived.add(key)
        written.append(key)
    return written


def _run_agent(
    task: dict[str, Any],
    answers: dict[str, str],
    qid: str = "flag",
    *,
    kind: str = "web",
    attachments: list[dict[str, str]] | None = None,
    publisher: Any = None,
    qids: list[str] | None = None,
    derived: set[str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """调用 strix 打这一道题。

    Args:
        task: 已解析的 task.json，用于取题目描述与 turn 预算。
        answers: 出参。拿到 flag 时写入 ``answers[qid]``。
        qid: 主 question id（日志与提示用）。
        qids: 本轮**全部可见**的 question id；缺省时退化为 ``[qid]``。
        derived: 记录哪些 ``answers`` 值是"镜像猜测"而不是实证；由 main 持有，
            使后到的真实答案仍能覆盖它。
        kind: 题型，由 :func:`_challenge_kind` 给出。
        attachments: 已读入的附件（``extra_files`` 形状）。附件题由 main 读好
            传进来，避免同一批文件被搬两遍。
        publisher: engagement 的报告投递器（由 main 建好）。其它题型传 None。

    Returns:
        ``(实际 turn 数, 诊断信息)``。turn 数优先取 SDK 的
        ``result.usage.requests``，取不到时退回 event sink 统计的 root 工具调用数。
    """
    import asyncio

    from ctf_strix.local_backend import install as install_backend

    # One process can host more than one run (tests / embedded callers).  A
    # trip from the previous run must not refuse this run's first paid call.
    begin_usage_run()
    install_backend()

    # Replace strix's short retry ladder with the CTF policy.  Installing here
    # (before the first attempt) means every later attempt in this process
    # uses it as well.  A failure to install is reported once and leaves
    # strix's stock behaviour intact, exactly as before.
    error_policy.install()
    llm_errors: list[dict[str, Any]] = []

    # 本函数末尾要返回的诊断字典（与 `main` 里的 `diag` 同名但不同作用域）。
    # 守卫接线失败就写进这里，随 `out.update(diag)` 进 result.json。
    diag: dict[str, Any] = {}
    # Structured proof that this run solved the challenge.  Everything that
    # may stop the run early reports through this ledger; nothing here reads
    # page text or model prose.
    success = SuccessLedger()

    # Every flag has to be seen in a tool output from *this* run before it is
    # submitted; a flag the model only wrote down is a guess.  078 produced one
    # (``3cada892...``) and it was one parameter away from being submitted via
    # ``finish_scan``.  See docs/11 section 4.15.  The ledger is created before
    # the finish guard so the guard can require that provenance instead of
    # trusting a regex match in the model's own summary.
    from ctf_strix.evidence import EvidenceLedger

    ledger = EvidenceLedger()

    # ⚠️ 挂载钩子必须最先装。三个守卫都是替换 factory._with_bounded_result 来
    # 挂 on_invoke_tool 的，但 exec_command / write_stdin 走 Shell capability 的
    # _configure_shell_tools，**绕过**那个函数。不装钩子，守卫只覆盖
    # view_agent_graph / think / create_agent 这类流程工具——永远不会发出载荷。
    #
    # 这个是正赛入口，代价比评测更大：评测跑废了还能重跑，正赛一道题只有一次
    # 机会。2026-10-28 的一次复跑就是被这个洞白烧了 1170 秒。
    from ctf_strix.guard_mount import install_mount_hook

    install_mount_hook()

    # Parallel hypothesis racing is opt-in.  The hook wraps create_agent /
    # agent_finish / finish_scan on the same mount seam as the other guards, so
    # it covers the shell and filesystem paths a child agent also uses.
    parallel_on = False
    try:
        from ctf_strix import parallel

        parallel_on = parallel.enabled() and parallel.install()
    except Exception as exc:  # noqa: BLE001 -- parallelism must not gate the run
        print(f"[ctfy] parallel guard failed: {type(exc).__name__}: {exc}", flush=True)

    # 两个守卫都装在正赛入口上。评测脚本装过、入口没装，等于只测了个空壳。
    from ctf_strix.enum_guard import install as install_enum_guard

    # Keep the instance: the sink reads its escalation state (a family the
    # model keeps retrying after the hard block) and the run summary needs
    # ``blocked_calls``; a discarded return value made both invisible.
    enum_guard = install_enum_guard()

    from ctf_strix.journey_guard import install as install_journey_guard

    install_journey_guard()

    # 单次调用内部的扫描守卫。``enum_guard`` 按**调用**去重，对"把几万个候选
    # 塞进一条 exec_command 的 Python 循环"完全无能为力——一次实测
    # 打了约 36,000 次路径变体，枚举守卫计数为 0，577 秒后失败。
    #
    # 2026-11-02 外部审查发现：这个守卫只在 scripts/run_strix_ctf.py 里装过，
    # **正赛入口 agent.py 从来没装**。也就是说评测里它有、交付镜像里它没有，
    # 和 v2 原语漏装（capabilities.py 模块文档记的同一类事故）是一个形态。
    from ctf_strix.sweep_guard import install as install_sweep_guard

    install_sweep_guard()

    # Path-independent "the target is not there" guard.  ``enum_guard`` counts
    # per path family, so a single run's 95 curls at 95 distinct paths never
    # moved any counter; this one counts one identical body across paths.
    from ctf_strix.target_absent import install as install_target_absent

    target_guard = install_target_absent()
    question_ids = [
        str(q.get("id") or "").strip()
        for q in (task.get("questions") or [])
        if isinstance(q, dict) and str(q.get("id") or "").strip()
    ]
    question_modes = {
        str(q.get("id") or "").strip(): str(q.get("mode") or "").strip().lower()
        for q in (task.get("questions") or [])
        if isinstance(q, dict) and str(q.get("id") or "").strip()
    }

    # ``finish_scan`` is usually the last call, so its wiring must be resolved
    # before the guard is installed: the guard needs the probe object, and the
    # probe needs the resolved platform/instance/token.  Building the submitter
    # first also removes the old ordering bug where the guard was installed
    # before the submitter existed and therefore never saw a checker.
    #
    # Wrapper order matters: the last installed wrapper runs first.  Submission
    # must run before the flag guard, otherwise a guard refusal on a non-flag
    # answer (a 32-hex slug) swallows the only submission.  So the guard is
    # installed here and the autosubmit wrapper right after it.
    submitted_to = _autosubmit_target(task)
    qa_target = (
        _qa_target(task)
        if submitted_to is None and kind != "engagement"
        else None
    )
    submitter: Any = None
    if kind != "engagement" and (submitted_to is not None or qa_target is not None):
        try:
            from ctf_strix.autosubmit import AutoSubmitter

            if qa_target is not None:
                qa_platform, qa_token, qa_challenge, qa_competition = qa_target
                submitter = AutoSubmitter(
                    qa_platform,
                    "",
                    qa_token,
                    success=success,
                    fallback_question_ids=question_ids,
                    fallback_question_modes=question_modes,
                    run_mode="qa",
                    challenge_id=qa_challenge,
                    competition_id=qa_competition,
                )
            else:
                submitter = AutoSubmitter(
                    *submitted_to,
                    success=success,
                    fallback_question_ids=question_ids,
                    fallback_question_modes=question_modes,
                )
        except Exception as exc:  # noqa: BLE001 -- probing is an optimisation
            print(f"[ctfy] autosubmit unavailable: {type(exc).__name__}: {exc}", flush=True)
            diag["autosubmit"] = "failed"

    # Proof-of-exploitation runs have an instance channel but no flag.  The
    # arming condition is ``_autosubmit_target`` itself (platform + instance +
    # token), never a bare instance id: without the other two the probe would
    # post to an empty URL and look like a platform outage.  ``mode`` is not
    # consulted -- measured tasks leave it empty and still grade /check.
    checker_probe = None
    if submitter is not None and submitted_to is not None:
        # QA 没有实例，``/instances//check`` 只会 404；只有实例通道能探。
        from ctf_strix.autosubmit import CheckerProbe

        checker_probe = CheckerProbe(
            submitter,
            question_ids=question_ids,
            known_question_ids=question_ids,
            question_modes=question_modes,
        )

    # Finish guard: an answerless finish_scan is refused.  engagement and
    # checker-only challenges have no flag, so those kinds let it through.
    from ctf_strix.finish_guard import install as install_finish_guard

    finish_guard = install_finish_guard(
        require_flag=kind not in {"engagement", "checker"},
        success=success,
        evidence=ledger,
        checker=(checker_probe.check if checker_probe is not None else None),
    )
    if kind != "engagement":
        diag["checker_probe"] = "armed" if checker_probe is not None else "off"

    if kind not in {"engagement", "checker"}:
        if submitted_to is None and qa_target is None:
            print("[ctfy] autosubmit off (no platform/instance/token)", flush=True)
            diag["autosubmit"] = "off"
        elif qa_target is not None and not question_ids:
            # 没有 qid 就不知道要交哪一项；装上也只是在收工时静默丢弃答案。
            print("[ctfy] autosubmit off (qa task has no questions[].id)", flush=True)
            diag["autosubmit"] = "off"
        elif submitter is None:
            diag.setdefault("autosubmit", "failed")
        else:
            try:
                from ctf_strix.autosubmit import install as install_autosubmit

                if qa_target is not None:
                    install_autosubmit(
                        qa_target[0],
                        "",
                        qa_target[1],
                        success=success,
                        fallback_question_ids=question_ids,
                        fallback_question_modes=question_modes,
                        submitter=submitter,
                        run_mode="qa",
                        challenge_id=qa_target[2],
                        competition_id=qa_target[3],
                    )
                    print(f"[ctfy] autosubmit on (qa {qa_target[2]})", flush=True)
                else:
                    install_autosubmit(
                        *submitted_to,
                        success=success,
                        fallback_question_ids=question_ids,
                        fallback_question_modes=question_modes,
                        submitter=submitter,
                    )
                    print(f"[ctfy] autosubmit on (instance {submitted_to[1][:8]}...)", flush=True)
                diag["autosubmit"] = "on"
            except Exception as exc:  # noqa: BLE001 -- submission failure must not stop the run
                print(
                    f"[ctfy] autosubmit registration failed: {type(exc).__name__}: {exc}",
                    flush=True,
                )
                diag["autosubmit"] = "failed"

    # finish_scan is a local strix tool with an SDK-level 60 s limit, so the
    # agent side can bound it.  Install this *after* the autosubmit wrapper:
    # the last installed wrapper runs first, which is what lets the timeout
    # counter see the slow platform submission instead of being outside the
    # SDK's wait_for.  engagement has no flags and its finish hook is separate.
    if kind != "engagement":
        try:
            install_finish_degradation(
                answers,
                _result_path(_work_dir(), task),
                diag=diag,
            )
            diag["finish_degradation"] = "armed"
        except Exception as exc:  # noqa: BLE001 -- degradation must not gate the run
            print(
                f"[ctfy] finish degradation failed: {type(exc).__name__}: {exc}",
                flush=True,
            )
            diag["finish_degradation"] = "failed"

    # The exec observer records a direct verdict printed by a shell call and
    # then raises the existing SolvedStop root stop.  It is a read-only
    # observer; a missing platform URL, instance, or question id leaves it
    # disarmed rather than trusting a local file.
    try:
        from ctf_strix.success_stop import install_exec_observer

        exec_observer = install_exec_observer(
            success,
            platform_url=_platform_url(task),
            instance=(submitted_to[1] if submitted_to is not None else ""),
            question_ids=tuple(question_ids),
        )
        diag["exec_observer"] = "armed" if exec_observer else "off"
    except Exception as exc:  # noqa: BLE001 -- observation must not gate the run
        print(f"[ctfy] exec observer failed: {type(exc).__name__}: {exc}", flush=True)
        diag["exec_observer"] = "failed"

    # The observer above raises SolvedStop for a validated shell verdict.  On
    # the root that unwinds the run correctly; on a child it would only kill
    # that detached task, leaving the root and the other children running.
    # Install the race bridge *outside* the observer so the same verdict wakes
    # the root and stops the siblings.  It is a pure forwarder: the observer
    # still owns the validation, and only success.source == "exec_verdict"
    # crosses this seam.  
    if parallel_on:
        try:
            bridged = parallel.install_exec_bridge()
            diag["parallel_exec_bridge"] = "on" if bridged else "off"
        except Exception as exc:  # noqa: BLE001 -- bridging must not gate the run
            print(
                f"[ctfy] parallel exec bridge failed: {type(exc).__name__}: {exc}",
                flush=True,
            )
            diag["parallel_exec_bridge"] = "failed"

    if parallel_on:
        # The configured state is per run; the guard itself is process-wide.
        parallel.reset_run()

    # The runner restarts an autonomous run that ends without a lifecycle call,
    # once per remaining turn.  Bound that at the runner's own interactive
    # limit, and use the first nudge to ask our checker whether the answer was
    # already scored.  A direct "yes" stops the run before any restart.
    from ctf_strix.success_stop import RECOVERY_LIMIT, install_recovery_guard

    try:
        install_recovery_guard(
            limit=RECOVERY_LIMIT,
            checker=(checker_probe.check if checker_probe is not None else None),
            ledger=success,
        )
        diag["recovery_guard"] = "on"
    except Exception as exc:  # noqa: BLE001 -- the wallclock still bounds the run
        print(f"[ctfy] recovery guard failed: {type(exc).__name__}: {exc}", flush=True)
        diag["recovery_guard"] = "failed"

    # 装完立刻验证接线。正赛里没有第二次机会，接线失败必须当场知道。
    from ctf_strix.guard_mount import verify_mount

    wired = verify_mount(
        (
            "_ctf_guarded",
            "_ctf_journey_guarded",
            "_ctf_sweep_guarded",
            "_ctf_target_guarded",
        )
    )
    print(f"[ctfy] guard mount verified={wired}", flush=True)
    if not wired:
        # 不抛异常：没挂上守卫仍然能把题跑完，只是少了三层纠偏。但这件事必须
        # 出现在 result.json 里，否则"守卫全废"和"今天没触发"在数据上同形。
        diag["guard_mount"] = "failed"

    from ctf_strix.tool_trim import install_ctf_toolset

    # Caido tools always go (no caido-cli in the image).  Bookkeeping tools
    # (notes / coverage / threat model / reports) stay only for engagement,
    # whose deliverable is the report.  For web/file/tcp they are 17 schemas
    # that cost tokens every turn and tempt the model to write prose instead
    # of reading the answer.  The eval harness already trimmed them; keeping
    # them here made the submitted tool surface differ from the measured one.
    install_ctf_toolset(drop_bookkeeping=kind != "engagement")
    # workdir 兼容：见 tool_trim.install_workdir_shim 的实测说明。
    from ctf_strix.tool_trim import install_workdir_shim

    install_workdir_shim()

    # Capability parity with scripts/run_strix_ctf.py.  The v2 primitives were
    # validated there but were never registered here, so the submitted image
    # silently ran the pre-v2 tool surface.  Both entrypoints now share one
    # installer; failures are printed instead of swallowed.
    # One place assembles the tool surface, so what is registered and what
    # the prompt describes cannot drift apart (docs/27 C3/C4).
    hint, groups = install_toolset(task, kind)

    # Every visible question id, resolved once per run.  ``qid`` stays the
    # primary (prompt + log line); ``all_qids`` is what answers are keyed by.
    all_qids = qids or [qid]
    mirrors: set[str] = derived if derived is not None else set()

    from strix.core.runner import run_strix_scan

    goal = _read_goal(kind)
    description = (task.get("challenge") or {}).get("description") or ""
    max_turns = _turn_budget(task)

    engagement = kind == "engagement"
    specs = _target_specs(task)
    attachment_files = list(attachments or [])
    if attachment_files:
        print(f"[ctfy] injecting {len(attachment_files)} attachment file(s)", flush=True)

    # engagement 报告投递：publisher 由 main 建好传进来（运行时起不来时也要
    # 能先交付一版）；这里只负责注册 agent 工具与收工钩子。
    if engagement and publisher is not None:
        try:
            from ctf_strix.engagement import install_finish_hook
            from ctf_strix.engagement import install_tool

            tool_names = install_tool(publisher)
            print(f"[ctfy] report tools={tool_names}", flush=True)
        except Exception as exc:  # noqa: BLE001 — 工具注册失败不能阻止跑题
            print(f"[ctfy] report tool registration failed: {type(exc).__name__}: {exc}", flush=True)

    captured: list[str] = []
    activity: list[str] = []
    tool_outputs = 0
    root_tool_calls = 0
    root_agent: str | None = None
    attempt_pairs: list[tuple[str, str]] = []
    attempt_outputs: list[str] = []
    pending_calls: dict[str, tuple[str, str]] = {}
    pending_seq: list[tuple[str, str]] = []
    # Flags the model wrote into a tool call's arguments.  Kept until a tool
    # output proves the same string was actually read -- a self-echo (same
    # literal in the producing call's arguments) does not count.
    arg_claims: list[str] = []
    own_host = _host_of(_targets_from(task)[0]) if _targets_from(task) else ""
    save_threads: list[threading.Thread] = []

    if parallel_on:
        # The per-attempt coordinator is bound inside the attempt loop.  At
        # this point only the ledgers exist; the coordinator that owns the
        # agent graph is created together with the scan.
        parallel.configure(success=success, evidence=ledger)
        diag["parallel"] = parallel.stats()

    def _report_text() -> str:
        """当前进展的报告正文：agent 自己写过就用它，否则由活动记录拼。"""
        assert publisher is not None
        if publisher.authored and publisher.last_text:
            return publisher.last_text
        if not activity:
            # 一条工具输出都还没有时，拼出来的只是「暂无发现」的骨架。发出去
            # 等于用空报告覆盖平台上一版已计分的正文——run 中途崩了就再也
            # 拿不回来。宁可不发，等第一条证据出现再存。
            return ""
        from ctf_strix.engagement import build_report
        from ctf_strix.engagement import compact_activity

        # 后台线程里拼正文：条目多时 compact 要跑几十毫秒，别卡住事件循环。
        return build_report(
            task,
            activity=compact_activity(activity),
            elapsed=max(0.0, time.time() - started_at),
        )

    def _publish(force: bool, background: bool) -> None:
        assert publisher is not None
        text = _report_text()
        if not text:
            print("[ctfy] report save skipped: nothing to report yet", flush=True)
            return
        # 后台线程永远标 auto：它手里的正文是**启动那一刻的快照**，模型随后
        # 可能又写新版本，拿旧快照以 agent 身份重发等于回退。前台（收工钩子 /
        # 最终保存）才按 authored 标 agent——publish() 靠这个来源挡住自动摘要。
        source = "auto" if background else ("agent" if publisher.authored else "auto")
        if background:
            # 回收已结束的线程：长 run 里每 8 条输出就起一个，不清理会越攒越多。
            save_threads[:] = [t for t in save_threads if t.is_alive()]
            thread = threading.Thread(
                target=publisher.publish,
                args=(text,),
                kwargs={"force": force, "source": source},
                daemon=True,
            )
            thread.start()
            save_threads.append(thread)
            return
        ok, note = publisher.publish(text, force=force, source=source)
        print(f"[ctfy] report save ok={ok}: {note}", flush=True)

    started_at = time.time()
    idle = IdleWatchdog(_idle_limit_seconds())

    def sink(agent_id: str, event: object) -> None:
        nonlocal tool_outputs, root_tool_calls, root_agent
        # The only main-thread checkpoint available during a run.  On POSIX
        # ``SIGALRM`` reaches the main thread by itself; where it does not
        # exist the daemon can only raise this flag, and this is where the
        # run notices it.
        _check_soft_timeout()
        # The item has to be read before any early return: a slow tool's
        # output event must refresh the clock before this function decides
        # anything about idleness, otherwise a 150s ``nmap`` is killed and
        # its output (possibly the flag) is thrown away.
        item = getattr(event, "item", None)
        item_type = getattr(item, "type", None)
        round_boundary = _is_round_boundary(event)
        now = time.time()
        if item_type in _MODEL_ITEM_TYPES or round_boundary:
            # First real model/tool event of this attempt arms the clock.
            # Sandbox boot and provider setup emit neither, so a slow cold
            # start can no longer be reported as ``agent_idle`` at turns=0.
            idle.arm(now)
        if item_type in _TOOL_ACTIVITY_TYPES:
            # A tool call *and* its output are progress.  Refresh first, then
            # judge: the output is never dropped because the tool was slow.
            idle.note_activity(now)
        if root_agent is None:
            # Prefer the coordinator graph: on a resumed run the runner
            # respawns children before the root emits its first event, so
            # "first id seen" would mislabel a child as the root.
            root_agent = (parallel.root_id() if parallel_on else None) or agent_id
        # A structured success seen on the previous event means there is
        # nothing left to learn from this run.  Raise here, before the runner
        # can treat the next prose-only turn as an unfinished one and restart
        # the session.
        # Compare against the root id resolved above.  ``is_root`` returns
        # True when the graph is unknown, which is correct for a single agent
        # but would let a child raise SolvedStop in its detached task.
        if success.solved and (not parallel_on or agent_id == root_agent):
            raise SolvedStop(f"solved via {success.source}: {success.detail}")
        # An answer recorded anywhere in this run disarms the target-absent
        # guard: there is something to submit, so stopping early would trade a
        # score for wall clock.
        if answers or success.solved:
            target_guard.note_answer()
            # An answer disarms the enumeration guard too: whatever was
            # blocked while the value was unknown must open again, and the
            # retry counter that would escalate to EnumExhausted resets.
            enum_guard.note_answer()
        if round_boundary and target_guard.tripped and not success.solved:
            # The crossing tool call already returned the hard error.  Raise
            # from the sink, at a round boundary; ``main`` maps TargetAbsent
            # to its own stop reason (mirrors IdleTimeout).
            #
            # This is *not* the boundary of the round that tripped: the
            # vendor queue order is ``tool_call_item -> response.completed(N)
            # -> [tools run] -> output batch`` (every event is queued as soon
            # as it is produced), so boundary N arrives *before* round N's
            # outputs.  Safety comes from the FIFO queue plus boundary N+1
            # landing after all of round N's outputs; the boundary event
            # itself carries no item.  The stop therefore fires on the *next*
            # round's boundary, after a sibling call's output (possibly the
            # flag) has reached this sink.
            #
            # Cost: one extra generation.  Round N+1's ``tool_call_item`` has
            # already been emitted and this raise cancels it before it runs.
            # If that extra generation breaches the output budget,
            # ``stop_reason`` lands on ``output_budget`` instead (rare).
            raise TargetAbsent(
                target_guard.stop_detail(),
                origin=target_guard.tripped_origin or "",
                paths=target_guard.threshold,
            )
        if round_boundary and enum_guard.exhausted and not success.solved:
            # Refused calls return instantly and still produce a tool call,
            # so retrying a blocked family is free for the model and burns
            # the turn budget with no new observation.  End the run instead.
            #
            # Same boundary gate as the target-absent raise above, on the
            # same physical basis: boundary N arrives *before* round N's
            # outputs, and the refusal is counted inside the wrapper *during*
            # that round.  The FIFO queue delivers every output of round N
            # before boundary N+1, so the stop lands there without dropping a
            # sibling call's output (the B1 invariant).  Cost: one extra
            # generation whose already-planned tool call this raise cancels.
            raise EnumExhausted(
                enum_guard.exhausted_detail(),
                family=enum_guard.exhausted_family or "",
                refusals=enum_guard.refusal_count(enum_guard.exhausted_family or ""),
            )
        if round_boundary and not success.solved and idle.expired(now):
            # A dead-target run: after deciding the target was dead the model
            # wrote "I'll wait for the hard stop" and idled ~20 minutes.
            # Checked only when a round ends (streaming deltas are not a
            # decision point) and only against tool activity, so a long
            # single generation is never killed mid-stream while a pure
            # prose loop still trips at the boundary.
            raise IdleTimeout(
                f"no tool call for {idle.limit:g}s (idle reasoning loop)"
            )

        if item_type == "tool_call_item":
            # Child agents may hand the root a finished answer through
            # ``agent_finish``.  The text is prose, so it cannot be trusted as
            # evidence by itself; the claim is recorded only when the same
            # string appears in a tool output (which the parallel wrapper did
            # when the child called that tool, or this output later does).
            if parallel_on:
                raw = getattr(item, "raw_item", None)
                name = str(getattr(raw, "name", "?") or "?")
                if name == "agent_finish":
                    args_full = str(getattr(raw, "arguments", "") or "")
                    for claim in _extract_args_flags(args_full):
                        if claim not in arg_claims:
                            arg_claims.append(claim)
            # Pair *every* agent's call with its output, not only the root's:
            # a child (or a tcp payload) can echo a guess too, and echo
            # detection needs the full argument text, not the display prefix.
            raw = getattr(item, "raw_item", None)
            name = str(getattr(raw, "name", "?") or "?")
            args_full = str(getattr(raw, "arguments", "") or "")
            args = args_full[:300]
            call_id = str(
                getattr(item, "call_id", "")
                or getattr(raw, "call_id", "")
                or ""
            )
            if call_id:
                pending_calls[call_id] = (name, args_full)
            else:
                pending_seq.append((name, args_full))
            if agent_id == root_agent:
                root_tool_calls += 1
                # finish_scan carries the agent's final answer in its
                # arguments, not in a tool output.  Scanning outputs only was
                # losing challenges where the agent read the flag correctly
                # but reported it through the lifecycle call (082: both A/B
                # arms had the flag in finish_scan and neither was submitted).
                if not engagement and qid not in answers:
                    found = _extract_flag(args_full, own_host)
                    if found:
                        # Record, do not submit yet: the same string must show
                        # up in a tool output before it counts as retrieved.
                        arg_claims.append(found)
            if engagement and agent_id == root_agent:
                activity.append(f"`{name}` {args}")
                if len(activity) > _CAPTURE_LIMIT:
                    del activity[:100]
            return

        if item_type != "tool_call_output_item":
            return

        text = str(getattr(item, "output", "") or "")
        captured.append(text)
        if len(captured) > _CAPTURE_LIMIT:
            del captured[:100]
        raw = getattr(item, "raw_item", None)
        call_id = str(
            getattr(item, "call_id", "")
            or (raw.get("call_id") if isinstance(raw, dict) else "")
            or ""
        )
        pair = pending_calls.pop(call_id, None) if call_id else None
        if pair is None and pending_seq:
            pair = pending_seq.pop(0)
        if pair is None and pending_calls:
            # Some providers omit call_id on the output item.  With a single
            # in-flight call, pair it directly; with several, take the oldest.
            oldest = next(iter(pending_calls))
            pair = pending_calls.pop(oldest)
        if pair is None and attempt_pairs and len(attempt_outputs) < len(attempt_pairs):
            # Fallback: the previous output was never paired.  Reuse its
            # call in order rather than dropping the output from the digest.
            pair = attempt_pairs[len(attempt_outputs)]
        # Only the root's calls feed the retry digest; child probes are a
        # different line of attack and would bury the root's own history.
        if pair is not None and agent_id == root_agent:
            attempt_pairs.append(pair)
            attempt_outputs.append(text)
        # ``None`` means this output could not be paired with a call, so the
        # arguments are unknown and the legacy "count everything" rule applies.
        call_arguments = pair[1] if pair is not None else None
        tool_outputs += 1

        if engagement:
            activity.append("```\n" + text.strip()[:500] + "\n```")
            if len(activity) > _CAPTURE_LIMIT:
                del activity[:100]
            # 边做边存：平台每次保存都抽证据计分，攒到最后再交等于零。
            # 模型自己调过 save_report 时不要再拿自动摘要覆盖它。
            if publisher is not None and tool_outputs % _REPORT_EVERY == 0:
                if not publisher.authored:
                    _publish(force=False, background=True)
            return

        # A flag in this output is *retrieved* evidence unless the same literal
        # was already in the call's own arguments: then the tool merely echoed
        # the model's guess back (Q6), and that observation must not support it.
        ledger.observe_output(text, arguments=call_arguments)
        if arg_claims:
            for claim in list(arg_claims):
                if ledger.supports(claim) and _record_answer(
                    answers, all_qids, claim, qid, derived=mirrors
                ):
                    print(
                        f"[ctfy] flag captured from tool args: {claim}",
                        flush=True,
                    )
                    success.observe_answer(claim, source="flag_extract")
                    break

        # ⚠️ 必须逐条输出单独判定，不能等最后拼起来一起判。拼接后
        # 本题靶机与别题 flag 的距离信息会被淹没，证据判定退化成瞎猜。
        flag = _extract_flag(text, own_host)
        if flag is not None and not ledger.supports(flag):
            # The extractor's pick is the literal this call echoed back.  If
            # the same output also carried another flag from a clean
            # observation, promote that one instead of dropping the output.
            from ctf_strix.flag_extract import FLAG_RE

            flag = next(
                (
                    candidate
                    for candidate in FLAG_RE.findall(text)
                    if ledger.supports(candidate)
                ),
                None,
            )
        if parallel_on and agent_id != root_agent:
            # A child's retrieved flag is a race win even when the root has not
            # seen this output yet.  Record the answer here as well: the root
            # may be interrupted before its own sink processes the output, and
            # ``result.json`` is written from this map.
            child_flag = flag or _parallel_flag(text, own_host)
            if child_flag and ledger.supports(child_flag):
                if _record_answer(answers, all_qids, child_flag, qid, derived=mirrors):
                    print(f"[ctfy] flag captured by sub-agent: {child_flag}", flush=True)
                parallel.note_success(agent_id, child_flag, root_id=root_agent)
        if flag and ledger.supports(flag) and _record_answer(
            answers, all_qids, flag, qid, derived=mirrors
        ):
            print(f"[ctfy] flag captured: {flag}", flush=True)
            success.observe_answer(flag, source="flag_extract")

    scope_note = _scope_note(task)
    parts = [goal, scope_note]
    if hint:
        parts.append(hint)

    # A later round leaves a README that names the round and scores the last
    # one.  Injecting it is the difference between continuing and restarting.
    round_note = _round_note(_work_dir())
    if round_note:
        parts.append(round_note)

    if len(all_qids) > 1:
        listing = "\n".join(f"- {item}" for item in all_qids)
        parts.append(
            "## Questions visible this round\n\n"
            f"The platform scores each id separately:\n\n{listing}\n\n"
            "Put the recovered value in `answers` under **every** id it could "
            "answer, not only the first. An id that is missing scores zero even "
            "when the string is right."
        )
    if attachment_files:
        # strix 只把 ``workspace_files`` 渲染进 task，``extra_files`` 是静默注入的。
        # 不说一声，agent 会不知道这些文件从哪来、甚至以为工作目录是空的。
        listing = "\n".join(f"- {entry['workspace_path']}" for entry in attachment_files)
        parts.append(
            "## Files already in your workspace\n\n"
            "The platform's attachments have been placed in your working directory:\n\n"
            f"{listing}\n\n"
            "Files ending in `.b64` are base64-encoded binaries — decode them first:\n"
            "`base64 -d FILE.b64 > FILE`."
        )
    parts.append(f"## Challenge description\n\n{description}")
    instruction = "\n\n".join(part.strip() for part in parts if part and part.strip())

    scan_config: dict[str, Any] = {
        "targets": specs,
        "user_instructions": instruction,
        # engagement 是广度问题，quick 模式会把侦察压得太窄；其余题型优先收敛。
        "scan_mode": "deep" if engagement else "quick",
    }

    if engagement and publisher is not None:
        # 收工那一刻必须保存：run 一结束实例就销毁，任何"等会儿再交"都来不及。
        # 这个钩子包在 finish_scan 外层（最后安装 = 最外层），先保存再交还控制权。
        def _save_at_finish() -> None:
            _publish(force=True, background=False)

        try:
            install_finish_hook(_save_at_finish)
        except Exception as exc:  # noqa: BLE001 — 钩子失败不能阻止跑题
            print(f"[ctfy] report finish hook failed: {type(exc).__name__}: {exc}", flush=True)

        # 开局探一次。此时还没有任何工具输出，_publish 会打印 "skipped" 并
        # 直接返回——不能用一份"暂无发现"的骨架覆盖平台上一版已计分的正文。
        # 它是本地自测里确认投递链路已接通的观测点。
        _publish(force=True, background=False)

    result: Any = None
    turns_total = 0
    # Attempt in flight, if any: the call count when it started.  A stop raised
    # mid-attempt bypasses the per-attempt accounting below, so the snapshot
    # settles that attempt's calls itself.  Without this, a second attempt's
    # work vanished whenever an earlier attempt had already counted turns.
    in_flight_calls_before: int | None = None
    usage_before = _usage_snapshot()
    # 有多少个 attempt 真的跑起来了（run_strix_scan 正常返回）。
    # 全部失败时上层必须把 stop_reason 从 "completed" 改成 "error"。
    runs_ok = 0
    turns_exhausted = 0
    attempts = 1 if engagement else _attempt_count()
    scan_id = f"ctfy-{int(time.time())}"
    try:
        split = float(os.environ.get("CTF_ATTEMPT_SPLIT", "0.6") or 0.6)
    except ValueError:
        split = 0.6
    budgets = _attempt_turns(max_turns, attempts, min(max(split, 0.2), 0.9))

    async def _go() -> None:
        nonlocal result, turns_total, root_agent, runs_ok, turns_exhausted
        nonlocal in_flight_calls_before
        for index, budget in enumerate(budgets):
            if not engagement and qid in answers:
                break
            # A prior attempt hit the single-call output cap.  Starting another
            # attempt would spend more wall clock on the same runaway path.
            if usage_trip_info() is not None:
                break
            # Each attempt gets a new strix agent id.  Without resetting this,
            # the sink keeps comparing against attempt 1 and undercounts every
            # later attempt as zero calls.
            root_agent = None
            # A call without an output at the end of an attempt must not pair
            # with the next attempt's first output.
            pending_calls.clear()
            pending_seq.clear()
            call_start = len(attempt_pairs)
            output_start = len(attempt_outputs)
            calls_before = root_tool_calls
            in_flight_calls_before = calls_before
            config = dict(scan_config)
            if index > 0:
                from ctf_strix.attempt_digest import build_digest

                digest = build_digest(
                    attempt_pairs[:call_start],
                    attempt_outputs[:output_start],
                )
                if not digest:
                    print("[ctfy] retry skipped: empty digest", flush=True)
                    break
                # Resume the same scan: strix restores the sandbox session and
                # the SDK history, then injects this as a new user message.
                # A fresh scan_id would lose /tmp scripts and login state.
                config["resume_instruction"] = (
                    "## Previous attempt (failed)\n\n"
                    + digest
                    + f"\n\nThis is attempt {index + 1} of {len(budgets)}. "
                    "Do not repeat the calls listed above. Change the mechanism, "
                    "not the parameter values. Start from an untried method or an "
                    "untried class of path, and read the real answer once you have "
                    "execution, file read, or DB read."
                )
                print(
                    f"[ctfy] retry with digest: {len(digest)} chars "
                    f"from {call_start} calls",
                    flush=True,
                )
                if os.environ.get("CTF_DIGEST_DEBUG", "").strip().lower() in ("1", "true", "yes"):
                    print(digest, flush=True)
            print(
                f"[ctfy] attempt {index + 1}/{len(budgets)} turns={budget}",
                flush=True,
            )
            attempt_coordinator = None
            if parallel_on:
                # `run_strix_scan` creates an AgentCoordinator when none is
                # supplied.  Supplying our own is what lets the race guard act
                # on the live graph: a coordinator left over from the previous
                # attempt is closed, and a race stop against it would silently
                # address nothing.  The two-child ceiling stays run-wide, so
                # only the graph binding is replaced here.
                attempt_coordinator = _new_coordinator()
                # Bind even when creation failed: ``None`` clears the previous
                # attempt's closed graph instead of leaving a stale root id.
                parallel.bind_attempt(attempt_coordinator)
            # A fresh attempt starts *unarmed*: its clock begins with its own
            # first model/tool event.  Seeding it with ``now`` counted sandbox
            # boot and the first LLM response against the limit, which is how
            # a healthy cold start got reported as ``agent_idle`` at turns=0.
            idle.reset()
            # The escalation state must not leak across attempts either.  A new
            # attempt *is* the instruction to change mechanism, so a refusal
            # count inherited from the previous attempt would end the retry on
            # its first (still exploratory) call.  The hard blocks stay: the
            # family produced no new information, so re-probing it is still
            # wasted work.
            enum_guard.soft_reset()
            try:
                result = await run_strix_scan(
                    scan_config=config,
                    scan_id=scan_id,
                    coordinator=attempt_coordinator,
                    image="unused-local",
                    local_sources=[],
                    extra_files=(attachment_files or None) if index == 0 else None,
                    max_turns=budget,
                    # Keep the sandbox alive between attempts; the final
                    # attempt is responsible for tearing it down.
                    cleanup_on_exit=index == len(budgets) - 1,
                    event_sink=sink,
                )
            except Exception as exc:  # noqa: BLE001 — turn 用尽属于正常终止
                print(f"[ctfy] scan ended: {type(exc).__name__}: {exc}", flush=True)
                turns_total += max(root_tool_calls - calls_before, 0)
                in_flight_calls_before = None
                if _is_turn_exhausted(exc):
                    # Counted apart from a crash: the attempt did run, it just
                    # never produced a lifecycle call.  ``main`` reports it as
                    # ``recovery_exhausted`` instead of ``error``.
                    turns_exhausted += 1
                    continue
                if error_policy.classify_error(exc) == "credential_failure":
                    # A rejected key cannot recover by starting another
                    # attempt: fail fast and let main report
                    # ``credential_failure`` instead of a generic error.
                    detail = error_policy.credential_failure(exc)
                    if detail is not None:
                        llm_errors.append(detail)
                        break
                continue
            runs_ok += 1
            # The root may have been stopped by a child agent's trip and return
            # normally.  Do not launch the next attempt in that case.
            if usage_trip_info() is not None:
                break
            used = _requests_of(result)
            turns_total += used if used > 0 else max(root_tool_calls - calls_before, 0)
            in_flight_calls_before = None

    def _snapshot_stats() -> tuple[int, dict[str, Any]]:
        """当前轮次与诊断的快照。

        正常收尾和五类止损终止（SolvedStop / RecoveryExhausted / IdleTimeout / 墙钟 /
        输出预算）共用这一份口径：两条路径写出的 result.json 必须能横向
        比较，否则每次异常终止都看起来像"一次都没跑"。
        """
        if llm_errors:
            diag["llm_errors"] = llm_errors
        snapshot_turns = turns_total
        if in_flight_calls_before is not None:
            snapshot_turns += max(root_tool_calls - in_flight_calls_before, 0)
        if snapshot_turns <= 0:
            snapshot_turns = root_tool_calls
        out_now: dict[str, Any] = {}
        if publisher is not None:
            out_now["report"] = publisher.snapshot()
        if ledger.observed or ledger.echoed or ledger.unsupported:
            out_now["evidence"] = ledger.summary()
        # A checker-only solve has no flag to add, but the verdict still belongs
        # in the diagnostics.
        out_now["success"] = success.snapshot()
        if enum_guard is not None:
            # The block counters used to be written but never read; the run
            # summary is the only place an operator can see that a family was
            # hard-blocked (and how many paid retries it swallowed).
            out_now["enum_guard"] = enum_guard.stats()
            print(
                "[ctfy] enum guard: "
                f"blocked_calls={enum_guard.blocked_calls} "
                f"blocked={len(enum_guard.blocked)} "
                f"exhausted={enum_guard.exhausted}",
                flush=True,
            )
        if finish_guard is not None and finish_guard.probe_note:
            out_now["checker_probe_note"] = finish_guard.probe_note
        out_now.update(diag)
        if parallel_on:
            # Tokens are process-wide already; turns are root-only in the vendor
            # result, so publish both halves explicitly instead of silently
            # under-counting a parallel run.
            usage = parallel.usage_summary(
                root_turns=snapshot_turns,
                before=usage_before,
                after=_usage_snapshot(),
            )
            out_now["parallel"] = {**parallel.stats(), "usage": usage}
            snapshot_turns = usage["turns"]
        return snapshot_turns, out_now

    try:
        asyncio.run(_go())
        # A tripped child agent ends only its own task.  The root can return
        # normally after ``request_stop``.  Re-raise here so the run still lands in
        # ``main``'s output_budget branch instead of looking like a clean finish.
        raise_if_tripped()

        # ``finish_scan`` is usually the last call, so no further tool output will
        # arrive to promote a claim recorded in its arguments.  Settle here as well,
        # otherwise a correct answer reported at the end would be dropped.
        #
        # "Still missing" means every visible id without evidence, not just the
        # primary one: mirroring fills the keys, so absence alone would say
        # "done" while the second question only holds a guess.
        if not engagement and _needs_value(answers, all_qids, mirrors):
            for claim in arg_claims:
                if ledger.supports(claim) and _record_answer(
                    answers, all_qids, claim, qid, derived=mirrors
                ):
                    print(
                        f"[ctfy] flag captured from tool args: {claim}",
                        flush=True,
                    )
                    success.observe_answer(claim, source="flag_extract")
                    break

        # 兜底：sink 里若因竞态没抓住，这里逐条重扫一遍。
        # ⚠️ 不要对 "\n".join(captured) 整体判定——拼接后本题靶机的出现位置被
        # 稀释到几千字符之外，证据判定会退化成"取最后一个"，正是踩过的坑。
        if not engagement and _needs_value(answers, all_qids, mirrors):
            for text in captured:
                flag = _extract_flag(text, own_host)
                # The sink already recorded every output in the ledger.  Re-check
                # support here as well, otherwise a self-echoed guess that the
                # sink correctly refused would be re-submitted by this rescan.
                if flag and ledger.supports(flag) and _record_answer(
                    answers, all_qids, flag, qid, derived=mirrors
                ):
                    print(f"[ctfy] flag captured on rescan: {flag}", flush=True)
                    success.observe_answer(flag, source="flag_extract")
                    break

        # A flag the model wrote but never read is a guess.  Keep it visible in the
        # diagnostics instead of submitting it.  Run this *after* the rescan: a
        # rescan hit is itself proof the string was printed by a tool.
        for claim in arg_claims:
            if not ledger.supports(claim) and answers.get(qid) != claim:
                ledger.reject(claim)
                if ledger.echoed_only(claim):
                    print(
                        f"[ctfy] flag rejected (self-echo in tool output): {claim}",
                        flush=True,
                    )
                else:
                    print(f"[ctfy] flag rejected (no tool output): {claim}", flush=True)

        # 最终保存必须在这里再走一次：agent 可能根本没调 finish_scan（被轮次上限
        # 或墙钟打断），那样上面的钩子从未触发，整轮发现会全部丢失。
        if engagement and publisher is not None:
            for thread in save_threads:
                thread.join(timeout=25)
            _publish(force=True, background=False)

        turns, out = _snapshot_stats()
        if attempts > 0 and runs_ok == 0 and not answers and turns_exhausted:
            # Ran to the turn cap without ever finishing.  This is the same verdict
            # as an exhausted recovery guard, so upper layers can use one spelling.
            out["turns_exhausted"] = turns_exhausted
        if attempts > 0 and runs_ok == 0 and not answers and not turns_exhausted:
            # 一次都没跑起来，而且也没拿到答案。上层据此把 stop_reason 写成
            # "error"，否则"运行时压根没启动"会以 turns=0 + stop_reason=completed
            # 混进失败率里。
            #
            # `and not answers` 是防御：将来若有人在进循环前就填好了 answers，
            # 那不是"没跑起来"，不该被标成 error。
            out["no_attempt_ran"] = True
        return turns, out
    except BaseException as exc:
        # A solve recorded by finish_guard/autosubmit can arrive before the
        # answer was copied into ``answers`` (the guard sees it in the tool
        # arguments).  Settle it here while the ledger is still in scope, so
        # the result file never says "solved" with an empty answer map.
        if isinstance(exc, SolvedStop) and not engagement and success.answer:
            if _record_answer(answers, all_qids, success.answer, qid, derived=mirrors):
                print(f"[ctfy] flag captured at stop: {success.answer}", flush=True)
        # 这五类异常直接穿过 ``main`` 的赋值语句，``turns_used, diag`` 永远
        # 停留在初值。统计在抛出点挂上去，收尾才能写出真实轮次与诊断。
        # 快照本身失败绝不能盖掉止损原文：那会把"已解出"降级成"崩溃"。
        if isinstance(exc, _STOP_TYPES):
            try:
                _attach_stop_state(exc, *_snapshot_stats())
            except Exception as snap_exc:  # noqa: BLE001
                print(
                    "[ctfy] stop-state snapshot failed: "
                    f"{type(snap_exc).__name__}: {snap_exc}",
                    flush=True,
                )
        raise
    finally:
        # The runner may leave the guard installed for the next attempt in this
        # process; leaving a checker bound to a dead submitter would keep
        # probing a torn-down instance.
        from ctf_strix.success_stop import uninstall_recovery_guard

        uninstall_recovery_guard()


def _requests_of(result: Any) -> int:
    """从 SDK 的 run result 里取 root agent 的 LLM 请求数（= turns）。"""
    usage = getattr(result, "usage", None)
    requests = getattr(usage, "requests", None)
    if isinstance(requests, int) and not isinstance(requests, bool):
        return requests
    return 0


if __name__ == "__main__":
    sys.exit(main())
