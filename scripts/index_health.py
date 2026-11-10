"""技能索引导航体检：纯读历史 jsonl + log，复算 D-5 的四个指标。

为什么是独立脚本而不是 ``ctf_strix`` 里的模块：这个解析器的全部价值在
「拿到任何机器上都能复算」——包括只拷走了 ``results.jsonl`` 和 ``*.log``
的机器。它因此只用 stdlib，一行都不 import ``ctf_strix``；与
``flag_extract.py`` 共享的 TOOL 行格式在这里复制一份（同一正则，两处
生命周期解耦是有意的：日志格式变了应该先红这里的测试）。

四个指标（对应 PLAN D-5）：

① ``load_rate``          有日志的 run 里，至少调用过一次 ``load_skill`` 的比例。
② ``ref_read_rate``      每次 ``load_skill`` 之后 3 个 TOOL 调用内，出现
                          读技能包引用路径（``jail/skills`` / ``skills_strix``）
                          的 ``exec_command``/``read_file`` 的比例。
③ ``inject_bytes``       单次注入字节：按 **load 调用**（不是按技能名）累加
                          该调用**实际命中**的索引文件尺寸（按命中文件计：
                          缺失的名字不计字节，只记 ``inject_missing``）。口径
                          是**源包**文件（``skills_root`` 下 ``<name>.md``），
                          比真实注入少 235B（20 字符 ref）的路径提示，故是
                          下界近似，不是精确值。
                          分母只数「至少命中一个文件」的调用；缺失的名字
                          不会把分母减成 0 或负数。
④ ``first_dir_rate``     首次 load 的方向与 run 的题型（``kind``）一致的比例；
                          ``ctf-triage`` 先行是批准的流程，恒视为一致。

用法::

    python3 scripts/index_health.py --results results.jsonl --logs-dir reports/
    python3 scripts/index_health.py --log run.log --kind web --id NAME
    # 两者都支持 --skills-root（默认 staged 的 skills_strix）与 --json OUT
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# 与 flag_extract.py 相同的 TOOL 行格式（复制而非 import：见模块 docstring）
_TOOL_LINE = re.compile(r"\[[0-9a-f]{8}\] TOOL (\S+)(.*)")

# 技能包引用根的两种形态：jail 内 /var/ctf/jail/skills，本地调试走仓库路径
# （skillpack.ref_root() 的约定）。log 里出现任一即算「读到了引用路径」。
_REF_MARKERS = ("jail/skills", "skills_strix")

# 只统计这两类工具的读路径：exec_command 是现行提示词规定的 L3 读取方式，
# read_file 是 vendor 基座时代的老日志里的同名行为。别的不算读。
_READ_TOOLS = ("exec_command", "read_file")

# load 之后多少个 TOOL 调用内算「命中后读取」
_READ_WINDOW = 3

# 题型 → 该题型下「方向一致」的首次 load 类别。triage 先行单列（恒一致）。
_KIND_DIRECTIONS: dict[str, frozenset[str]] = {
    "web": frozenset({"ctf-web"}),
    "tcp": frozenset({"ctf-pwn"}),
    "file": frozenset(
        {
            "ctf-reverse",
            "ctf-pwn",
            "ctf-crypto",
            "ctf-forensics",
            "ctf-misc",
            "ctf-malware",
            "ctf-osint",
        }
    ),
    "aisec": frozenset(
        {"ctf-agentic-ai", "ctf-ai-infra", "ctf-ai-ml", "ctf-supply-chain"}
    ),
}
_TRIAGE = "ctf-triage"

# 日志行被截断时 json.loads 会失败：退化为按技能名形状抓取（best-effort，
# PLAN 允许的降级路径）。
_SKILL_NAME = re.compile(r"\b(ctf-[a-z0-9-]+/[a-z0-9-]+)\b")


def parse_tool_calls(text: str) -> list[tuple[str, str]]:
    """按出现顺序返回 ``[(tool_name, raw_args), ...]``，raw 含原始 JSON 文本。"""
    return [(m.group(1), m.group(2)) for m in _TOOL_LINE.finditer(text)]


def _load_names(raw: str) -> list[str] | None:
    """解析 load_skill 参数里的技能名列表；参数不可读时返回 None。"""
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        found = _SKILL_NAME.findall(raw)
        return found or None
    skills = payload.get("skills") if isinstance(payload, dict) else None
    if isinstance(skills, list) and skills:
        return [str(s) for s in skills]
    return None


def _category(name: str) -> str:
    """``ctf-web/ctf-web`` -> ``ctf-web``（无斜杠时原样返回）。"""
    return name.split("/", 1)[0] if "/" in name else name


def analyze_log(text: str, skills_root: Path | None) -> dict:
    """一条 run 日志 -> 指标字段（全部可 json 序列化，只加不改）。

    返回字段是准备直接并入结果行的：``skill_loads``、``skill_first``、
    ``skill_ref_reads``、``skill_inject_bytes``、``skill_inject_missing``、
    ``skill_inject_calls``（③ 的分母：至少命中一个索引文件的 load 调用数）。
    """
    calls = parse_tool_calls(text)
    loads: list[int] = []  # 每个 load_skill 调用在 calls 里的下标
    names: list[str | None] = []  # 平行：解析出的技能名（None=参数不可读）
    for i, (tool, raw) in enumerate(calls):
        if tool == "load_skill":
            loads.append(i)
            names.append(_load_names(raw))

    ref_reads = 0
    for i in loads:
        window = calls[i + 1 : i + 1 + _READ_WINDOW]
        for tool, raw in window:
            if tool in _READ_TOOLS and any(m in raw for m in _REF_MARKERS):
                ref_reads += 1
                break

    inject_bytes = 0
    inject_missing = 0
    inject_calls = 0
    first: str | None = None
    for group in names:
        if not group:
            continue
        if first is None:
            first = _category(group[0])
        call_bytes = 0
        resolved = False
        for name in group:
            index_file = None if skills_root is None else skills_root / f"{name}.md"
            if index_file is not None and index_file.is_file():
                call_bytes += index_file.stat().st_size
                resolved = True
            else:
                inject_missing += 1
        inject_bytes += call_bytes
        if resolved:
            # 分母按「调用」计：一次 load_skill([a, b]) 缺 b 仍是一次注入。
            inject_calls += 1

    return {
        "skill_loads": len(loads),
        "skill_first": first,
        "skill_ref_reads": ref_reads,
        "skill_inject_bytes": inject_bytes,
        "skill_inject_missing": inject_missing,
        "skill_inject_calls": inject_calls,
    }


def first_load_consistent(kind: str | None, first: str | None) -> bool | None:
    """④ 的判定：True/False/None（题型未知或没有 load 时无法判定）。"""
    if not kind or not first:
        return None
    if first == _TRIAGE:
        return True
    return first in _KIND_DIRECTIONS.get(kind, frozenset())


def summarize_runs(runs: list[dict]) -> dict:
    """一批已分析的 run（含 ``kind`` 与 analyze_log 的字段）-> 四个汇总指标。"""
    with_log = [r for r in runs if r.get("has_log")]
    loads = sum(r.get("skill_loads", 0) for r in with_log)
    ref_reads = sum(r.get("skill_ref_reads", 0) for r in with_log)
    known_runs = [r for r in with_log if r.get("skill_inject_bytes") is not None]
    known_bytes = sum(r["skill_inject_bytes"] for r in known_runs)
    known_calls = sum(r.get("skill_inject_calls", 0) for r in known_runs)
    judged = [
        first_load_consistent(r.get("kind"), r.get("skill_first"))
        for r in with_log
    ]
    judged = [j for j in judged if j is not None]
    return {
        "runs": len(runs),
        "runs_with_log": len(with_log),
        "metric_1_load_rate": (
            sum(1 for r in with_log if r.get("skill_loads")) / len(with_log)
            if with_log
            else None
        ),
        "metric_2_ref_read_rate": (ref_reads / loads) if loads else None,
        "metric_3_inject_bytes_per_load": (
            known_bytes / known_calls if known_calls > 0 else None
        ),
        "metric_4_first_dir_rate": (
            sum(1 for j in judged if j) / len(judged) if judged else None
        ),
    }


def _fmt_rate(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.0%}"


def _fmt_bytes(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.0f} B" if value < 1024 else f"{value / 1024:.1f} KiB"


def _resolve_log(row: dict, logs_dir: Path | None) -> tuple[Path | None, bool]:
    """行里的日志路径 -> 可读文件。eval_sample 记 ``log_path``（可能是
    容器内绝对路径），拿不到时退化为按文件名在 ``--logs-dir`` 里找。"""
    raw = row.get("log_path") or row.get("log") or ""
    if not isinstance(raw, str) or not raw:
        return None, False
    direct = Path(raw)
    if direct.is_file():
        return direct, True
    if logs_dir is not None:
        by_name = logs_dir / Path(raw).name
        if by_name.is_file():
            return by_name, True
    return None, False


def run_report(
    rows: list[dict],
    skills_root: Path | None,
    logs_dir: Path | None = None,
) -> list[dict]:
    """rows: 结果 jsonl 的原始行。逐行 attach 指标字段后返回。"""
    out: list[dict] = []
    for row in rows:
        entry = dict(row)
        log, has_log = _resolve_log(row, logs_dir)
        if has_log and log is not None:
            text = log.read_text(encoding="utf-8", errors="ignore")
            entry.update(analyze_log(text, skills_root))
        else:
            entry.update(
                {
                    "skill_loads": 0,
                    "skill_first": None,
                    "skill_ref_reads": 0,
                    "skill_inject_bytes": None,
                    "skill_inject_missing": 0,
                    "skill_inject_calls": 0,
                }
            )
        entry["has_log"] = has_log
        out.append(entry)
    return out


_ARGS: argparse.Namespace | None = None  # main() 的参数缓存，供子模块复用


def _print_report(runs: list[dict], summary: dict) -> None:
    print(f"runs: {summary['runs']}  (有日志: {summary['runs_with_log']})\n")
    header = f"{'run':<24} {'kind':<6} {'load':>4} {'ref读':>4} {'注入B':>8}  首次方向"
    print(header)
    print("-" * len(header))
    for r in runs:
        first = r.get("skill_first") or "-"
        consistent = first_load_consistent(r.get("kind"), r.get("skill_first"))
        mark = "-" if consistent is None else ("✓" if consistent else "✗")
        inject = r.get("skill_inject_bytes")
        inject_s = "-" if inject is None else str(inject)
        print(
            f"{str(r.get('id') or r.get('challenge') or '?'):<24} "
            f"{str(r.get('kind') or '-'):<6} "
            f"{r.get('skill_loads', 0):>4} {r.get('skill_ref_reads', 0):>4} "
            f"{inject_s:>8}  {first}{mark}"
        )
    print()
    print(f"① load_skill 调用率        {_fmt_rate(summary['metric_1_load_rate'])}")
    print(f"② 命中→子文件读取率        {_fmt_rate(summary['metric_2_ref_read_rate'])}")
    print(
        f"③ 单次注入字节            "
        f"{_fmt_bytes(summary['metric_3_inject_bytes_per_load'])}"
    )
    print(f"④ 首次load方向与题型一致率 {_fmt_rate(summary['metric_4_first_dir_rate'])}")


def main(argv: list[str] | None = None) -> int:
    global _ARGS
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--results", help="结果 jsonl（行含 id/kind/log_path）")
    source.add_argument("--log", help="单条 run 日志（配合 --kind/--id）")
    parser.add_argument("--logs-dir", type=Path, help="按文件名找日志的目录")
    parser.add_argument("--kind", help="单日志模式的题型")
    parser.add_argument("--id", help="单日志模式的 run 名")
    parser.add_argument(
        "--skills-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent
        / "src"
        / "ctf_strix"
        / "skills_strix",
        help="技能包根（③ 的离线尺寸来源；默认随仓库布局）",
    )
    parser.add_argument("--json", type=Path, help="把逐行+汇总结果写成 JSON")
    _ARGS = parser.parse_args(argv)

    skills_root = _ARGS.skills_root if _ARGS.skills_root.is_dir() else None

    if _ARGS.results:
        rows = [
            json.loads(line)
            for line in Path(_ARGS.results)
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        runs = run_report(rows, skills_root, _ARGS.logs_dir)
    else:
        text = Path(_ARGS.log).read_text(encoding="utf-8", errors="ignore")
        row = {"id": _ARGS.id or Path(_ARGS.log).stem, "kind": _ARGS.kind}
        row.update(analyze_log(text, skills_root))
        row["has_log"] = True
        runs = [row]

    summary = summarize_runs(runs)
    _print_report(runs, summary)

    if _ARGS.json:
        payload = {"runs": runs, "summary": summary}
        _ARGS.json.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\n已写出 {_ARGS.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
