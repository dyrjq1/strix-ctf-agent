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
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any

#: 兜底 flag 形态（抽取器不可用时用）。与 ``flag_extract`` 的正则同源：
#: CTFY 的 flag 可能是 ``FLAG{...}`` / ``ctfy{...}`` / ``flag{...}``。
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


def _targets_from(task: dict[str, Any]) -> list[str]:
    """从 task.json 解析出可当 web 目标打的 URL。

    两种形态差别很大，不能混：

    - **instance**：``scope`` 里是起好的实例 URL（``https://xxx.node2.ctfy.run:443``）。
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
    if urls:
        return urls

    if run_mode == "engagement":
        # 只取单主机名：带 "/" 的是 CIDR，交给 agent 扫描而不是当 web 目标。
        hosts = [entry for entry in raw if "://" not in entry and "/" not in entry]
        return [f"https://{host}" for host in hosts]

    return []


def _target_specs(task: dict[str, Any]) -> list[dict[str, Any]]:
    """把 scope 翻译成 strix 的 ``scan_config["targets"]``。

    除了 web URL，还保留两类语义：

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


def _question_id(task: dict[str, Any]) -> str:
    """取本次要回答的 question id。

    ``answers`` 是个 map，key 必须**和题目声明的 id 对上**——写死 ``"flag"``
    只在题目恰好把 id 命名为 flag 时成立。平台按 id 逐条匹配，key 不对等于没交。

    Args:
        task: 已解析的 task.json。

    Returns:
        第一个 question 的 id；没有 questions（engagement / awd）时退回 ``"flag"``。
    """
    questions = task.get("questions") or []
    if questions and isinstance(questions[0], dict):
        declared = questions[0].get("id")
        if declared:
            return str(declared)
    return "flag"


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
        found = [f for f in FLAG_PATTERN.findall(blob) if set(f.split("{", 1)[1][:-1]) != {"."}]
        return found[-1] if found else None


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    """原子写 result.json。

    先写临时文件再 rename：中途被杀不会留下半截 JSON —— 半截 JSON 比没有文件更糟，
    因为平台会尝试解析它然后再报错，把"超时"变成"格式错误"。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


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


def _local_attachments(work: Path) -> list[dict[str, str]]:
    """把工作目录里的附件读成 strix 的 ``extra_files``。

    平台可能把附件直接放在 ``$CTFY_WORK_DIR``（或 ``attachments/`` /
    ``files/`` 子目录）。strix 的 sandbox 是私有临时目录，不注入的话 agent
    看不见这些文件。找不到任何文件时返回空列表，行为与改造前一致。

    **所有题型都要注入**，不只是附件题：web 题也常带附件（SAMPLE-001 的
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
    reserved = {"task.json", "result.json"}
    # 本地调试时 ``CTFY_WORK_DIR`` 常常没设，cwd 是仓库根。不排掉这些目录的话
    # 会把整个源码树当成附件打包（50 个文件配额一次就满），还会让 agent 读到
    # 评测脚本里的常量——SAMPLE-004 就是这么把套题 id 当 flag 交上去的。
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


#: 与 ctfy 0.7.0 的 ``core/agent_brief.BRIEF_SCHEMA_VERSION`` 对齐。
#: ⚠️ 必须写进 result.json：`inspect_probe` 会因为缺它而报 `no_schema_version`
#: （advisory，不 blocking，但白送的告警没有理由留着）。
BRIEF_SCHEMA_VERSION = 2


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
    answers: dict[str, str] = {}
    error: str | None = None
    stop_reason = "completed"
    turns_used = 0
    qid = _question_id(task)
    kind = _challenge_kind(task, work)
    diag: dict[str, Any] = {}
    # 附件只读一次：main 要用它判断"附件题是不是空的"，_run_agent 要把它注入
    # sandbox。读两遍等于把同一批文件从磁盘搬两遍。
    #
    # ⚠️ **所有题型**都要收集，不只是 file：web 题也常带附件（SAMPLE-001 的
    # admin slug 就写在 setup.txt 里），漏注入等于把题目的一半线索丢掉。
    attachments = _local_attachments(work)
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
            specs = _target_specs(task)
            scope = _raw_scope(task)
            if not specs and not (kind == "engagement" and scope) and kind != "file":
                # 写清楚是"模式不匹配"，不是"agent 傻了"。
                # instance 模式下 scope 为空意味着要自己 POST /instances 起靶机，
                # 本镜像还没做这一步——照实说，别伪装成扫过了。
                error = (
                    f"无可扫描目标：run_mode={task.get('run_mode')} "
                    f"scope={task.get('scope')} target_instance={task.get('target_instance')}"
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
                )

    except BaseException as exc:  # noqa: BLE001 — 任何异常都必须转成 result.json
        error = f"{type(exc).__name__}: {exc}"
        stop_reason = "error"
        traceback.print_exc()

    finally:
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
        try:
            _write_result(result_path, payload)
            print(f"[ctfy] result written to {result_path}")
        except OSError as exc:
            # 连文件都写不出去时，stdout 是最后的通道。虽然平台不读它，
            # 但在本地调试和 CTFY 的 stdout fallback 模式下仍然有意义。
            print(json.dumps(payload, ensure_ascii=False))
            print(f"[ctfy] FATAL: cannot write result file: {exc}", file=sys.stderr)

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


def _usage_snapshot() -> dict[str, int]:
    """读 token 计量；没装计量器时返回 0（不编数字）。"""
    try:
        from ctf_strix.usage_meter import snapshot

        snap = snapshot()
        return {
            "input_tokens": int(snap.get("input_tokens", 0)),
            "output_tokens": int(snap.get("output_tokens", 0)),
        }
    except Exception:  # noqa: BLE001 — 计量失败不能影响结果文件
        return {"input_tokens": 0, "output_tokens": 0}


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
    if error:
        lines.append(f"error: {error}")
    return "\n".join(lines)


def _run_agent(
    task: dict[str, Any],
    answers: dict[str, str],
    qid: str = "flag",
    *,
    kind: str = "web",
    attachments: list[dict[str, str]] | None = None,
    publisher: Any = None,
) -> tuple[int, dict[str, Any]]:
    """调用 strix 打这一道题。

    Args:
        task: 已解析的 task.json，用于取题目描述与 turn 预算。
        answers: 出参。拿到 flag 时写入 ``answers[qid]``。
        qid: 题目的 question id，决定 ``answers`` 的 key。
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

    install_backend()

    # ⚠️ 挂载钩子必须最先装。三个守卫都是替换 factory._with_bounded_result 来
    # 挂 on_invoke_tool 的，但 exec_command / write_stdin 走 Shell capability 的
    # _configure_shell_tools，**绕过**那个函数。不装钩子，守卫只覆盖
    # view_agent_graph / think / create_agent 这类流程工具——永远不会发出载荷。
    #
    # 这个是正赛入口，代价比评测更大：评测跑废了还能重跑，正赛一道题只有一次
    # 机会。2026-10-28 的 CTFARENA-012 复跑就是被这个洞白烧了 1170 秒。
    from ctf_strix.guard_mount import install_mount_hook

    install_mount_hook()

    # 两个守卫都装在正赛入口上。评测脚本装过、入口没装，等于只测了个空壳。
    from ctf_strix.enum_guard import install as install_enum_guard

    install_enum_guard()

    from ctf_strix.journey_guard import install as install_journey_guard

    install_journey_guard()

    # 收工守卫：没有 flag 的 finish_scan 会被拒绝。engagement 没有 flag，
    # checker 题也没有 flag——这两类必须让路，否则会误拦每一次正常收工。
    from ctf_strix.finish_guard import install as install_finish_guard

    install_finish_guard(require_flag=kind not in {"engagement", "checker"})

    # 装完立刻验证接线。正赛里没有第二次机会，接线失败必须当场知道。
    from ctf_strix.guard_mount import verify_mount

    wired = verify_mount(("_ctf_guarded", "_ctf_journey_guarded"))
    print(f"[ctfy] guard mount verified={wired}", flush=True)

    from ctf_strix.tool_trim import install_ctf_toolset

    # 只摘 Caido（本机没有 caido-cli，那 6 个工具调用必然报错），保留记账工具。
    # engagement 的交付物就是报告，记账/报告工具更不能裁。
    install_ctf_toolset(drop_bookkeeping=False)

    # 附件题（rev/pwn/misc/crypto）才装文件入口原语；web 题不为它付 schema token。
    if kind == "file":
        try:
            from ctf_strix import file_triage

            added = file_triage.register()
            print(f"[file] registered {len(added)} tools: {', '.join(added) or '(already present)'}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[file] registration failed: {type(exc).__name__}: {exc}", flush=True)

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
            hint = skillpack.prompt_hint(names)
            print(f"[ctfy] skills registered={len(names)} ref={skillpack.ref_root()}", flush=True)
        else:
            print("[ctfy] skills pack missing, routing hint not installed", flush=True)
    except Exception as exc:  # noqa: BLE001 — 技能装不上也要能把题跑完
        print(f"[ctfy] skills registration failed: {type(exc).__name__}: {exc}", flush=True)

    # AI 安全能力（指纹 + CVE 匹配）：走官方 register_agent_tools，不改 vendor。
    # 规则库缺失时不注册——挂一个必然报错的工具只会浪费轮次。
    try:
        from ctf_strix.aisec import aig_probe
        from ctf_strix.aisec import tools as aisec_tools

        if aig_probe.data_dir():
            registered = aisec_tools.register()
            print(f"[ctfy] aisec tools={len(registered)}", flush=True)
        else:
            print("[ctfy] aisec rules missing, tools not registered", flush=True)
    except Exception as exc:  # noqa: BLE001 — 增强能力失败不能让整题跑不动
        print(f"[ctfy] aisec registration failed: {type(exc).__name__}: {exc}", flush=True)

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
    own_host = _host_of(_targets_from(task)[0]) if _targets_from(task) else ""
    save_threads: list[threading.Thread] = []

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

    def sink(agent_id: str, event: object) -> None:
        nonlocal tool_outputs, root_tool_calls, root_agent
        if root_agent is None:
            root_agent = agent_id
        item = getattr(event, "item", None)
        item_type = getattr(item, "type", None)

        if item_type == "tool_call_item":
            if agent_id == root_agent:
                root_tool_calls += 1
            if engagement:
                raw = getattr(item, "raw_item", None)
                name = str(getattr(raw, "name", "?") or "?")
                args = str(getattr(raw, "arguments", "") or "")[:300]
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

        # ⚠️ 必须逐条输出单独判定，不能等最后拼起来一起判。拼接后
        # 本题靶机与别题 flag 的距离信息会被淹没，证据判定退化成瞎猜。
        flag = _extract_flag(text, own_host)
        if flag and qid not in answers:
            answers[qid] = flag
            print(f"[ctfy] flag captured: {flag}", flush=True)

    scope_note = _scope_note(task)
    parts = [goal, scope_note]
    if hint:
        parts.append(hint)
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

    async def _go() -> None:
        nonlocal result
        try:
            result = await run_strix_scan(
                scan_config=scan_config,
                scan_id=f"ctfy-{int(time.time())}",
                image="unused-local",
                local_sources=[],
                extra_files=attachment_files or None,
                max_turns=max_turns,
                cleanup_on_exit=True,
                event_sink=sink,
            )
        except Exception as exc:  # noqa: BLE001 — turn 用尽属于正常终止
            print(f"[ctfy] scan ended: {type(exc).__name__}: {exc}", flush=True)

    asyncio.run(_go())

    # 兜底：sink 里若因竞态没抓住，这里逐条重扫一遍。
    # ⚠️ 不要对 "\n".join(captured) 整体判定——拼接后本题靶机的出现位置被
    # 稀释到几千字符之外，证据判定会退化成"取最后一个"，正是踩过的坑。
    if not engagement and qid not in answers:
        for text in captured:
            flag = _extract_flag(text, own_host)
            if flag:
                answers[qid] = flag
                print(f"[ctfy] flag captured on rescan: {flag}", flush=True)
                break

    # 最终保存必须在这里再走一次：agent 可能根本没调 finish_scan（被轮次上限
    # 或墙钟打断），那样上面的钩子从未触发，整轮发现会全部丢失。
    if engagement and publisher is not None:
        for thread in save_threads:
            thread.join(timeout=25)
        _publish(force=True, background=False)

    turns = _requests_of(result)
    if turns <= 0:
        turns = root_tool_calls
    return turns, {"report": publisher.snapshot()} if publisher is not None else {}


def _requests_of(result: Any) -> int:
    """从 SDK 的 run result 里取 root agent 的 LLM 请求数（= turns）。"""
    usage = getattr(result, "usage", None)
    requests = getattr(usage, "requests", None)
    if isinstance(requests, int) and not isinstance(requests, bool):
        return requests
    return 0


if __name__ == "__main__":
    sys.exit(main())
