#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compete_report.py — 把 compete state 目录的实跑数据汇总成统计报告。

口径（与 11-13 run3 复盘一致）：

- **尝试次数** = ``runs/<qid>.jsonl`` 里 ``tool_calls > 0 or usage.llm_calls > 0``
  的记录数；其余是「实例未就绪/隧道超时」的空转重试，单独计 ``idle_records``。
- **时间** = 每次尝试的 ``total_s`` 求和；``span`` = 最早 started 到最晚
  finished 的墙钟，``overlap`` = 求和 / span（并发度代理，≈1 说明车道被平台
  串行化）。
- **工具调用** = ``tool_calls`` 求和；LLM 调用与 token 从 ``usage`` 取。
- 失败路径来自 ``state.json`` 的 ``failure_path``（compete 落盘）。

用法::

    python scripts/compete_report.py --state-dir ~/compete-state-run4
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter, defaultdict
from pathlib import Path


def _load_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            rows.append(rec)
    return rows


def _launched(rec: dict) -> bool:
    usage = rec.get("usage") or {}
    return int(rec.get("tool_calls") or 0) > 0 or int(usage.get("llm_calls") or 0) > 0


def collect(state_dir: Path) -> dict:
    state: dict = {}
    sp = state_dir / "state.json"
    if sp.exists():
        try:
            state = json.loads(sp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}

    per_q: dict[str, dict] = {}
    all_rows: list[dict] = []
    for path in sorted(glob.glob(str(state_dir / "runs" / "*.jsonl"))):
        qid = os.path.basename(path)[:-6]
        rows = _load_jsonl(path)
        all_rows.extend(rows)
        b = per_q.setdefault(qid, dict(
            records=0, attempts=0, idle_records=0, wall=0.0, tool_calls=0,
            llm_calls=0, input_tokens=0, output_tokens=0, solved=False,
            stop_reasons=Counter(), questions=set(), category="", difficulty="",
        ))
        for rec in rows:
            b["records"] += 1
            if _launched(rec):
                b["attempts"] += 1
                b["wall"] += float(rec.get("total_s") or 0)
                b["tool_calls"] += int(rec.get("tool_calls") or 0)
                usage = rec.get("usage") or {}
                b["llm_calls"] += int(usage.get("llm_calls") or 0)
                b["input_tokens"] += int(usage.get("input_tokens") or 0)
                b["output_tokens"] += int(usage.get("output_tokens") or 0)
            else:
                b["idle_records"] += 1
            reason = rec.get("stop_reason") or rec.get("error") or "unknown"
            b["stop_reasons"][str(reason)[:40]] += 1
            if rec.get("correct"):
                b["solved"] = True
            for qid_key in (rec.get("answers_ok") or {}):
                b["questions"].add(str(qid_key))

    solved = {qid for qid, b in per_q.items() if b["solved"]}
    for qid, rec in state.items():
        if rec.get("status") == "solved":
            solved.add(qid)
            per_q.setdefault(qid, dict(
                records=0, attempts=0, idle_records=0, wall=0.0, tool_calls=0,
                llm_calls=0, input_tokens=0, output_tokens=0, solved=True,
                stop_reasons=Counter(), questions=set(), category="",
                difficulty="",
            ))
        if qid in per_q:
            per_q[qid]["status"] = rec.get("status") or ""
            per_q[qid]["failure_path"] = rec.get("failure_path") or []
            per_q[qid]["runs"] = rec.get("runs") or 0
            per_q[qid]["fails"] = rec.get("fails") or 0
            per_q[qid]["skips"] = rec.get("skips") or 0
            per_q[qid]["last_run_at"] = rec.get("last_run_at") or ""
    for qid, b in per_q.items():
        b["solved"] = qid in solved
        b.setdefault("status", "solved" if b["solved"] else "")

    started = [float(r.get("started") or 0) for r in all_rows if r.get("started")]
    finished = [
        float(r.get("started") or 0) + float(r.get("total_s") or 0)
        for r in all_rows
        if r.get("started")
    ]
    span = (max(finished) - min(started)) if started else 0.0
    wall_sum = sum(b["wall"] for b in per_q.values())
    totals = dict(
        challenges=len(per_q),
        solved=len(solved),
        attempts=sum(b["attempts"] for b in per_q.values()),
        idle_records=sum(b["idle_records"] for b in per_q.values()),
        wall_s=round(wall_sum, 1),
        span_s=round(span, 1),
        overlap=round(wall_sum / span, 2) if span > 0 else 0.0,
        tool_calls=sum(b["tool_calls"] for b in per_q.values()),
        llm_calls=sum(b["llm_calls"] for b in per_q.values()),
        input_tokens=sum(b["input_tokens"] for b in per_q.values()),
        output_tokens=sum(b["output_tokens"] for b in per_q.values()),
    )
    return dict(per_q=per_q, totals=totals, solved=sorted(solved))


def render(data: dict) -> str:
    per_q = data["per_q"]
    t = data["totals"]
    lines = ["# compete 实跑统计", ""]
    lines.append(
        "| 题 | 状态 | 尝试 | 空转 | 墙钟(s) | 工具调用 | LLM 调用 | in_tok | out_tok | 失败路径 |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---|")
    order = sorted(
        per_q.items(),
        key=lambda kv: (not kv[1]["solved"], kv[0]),
    )
    for qid, b in order:
        fp = b.get("failure_path") or []
        fp_txt = (fp[-1] if fp else "").replace("|", "/")[:110]
        lines.append(
            f"| {qid} | {b.get('status') or ('solved' if b['solved'] else '')} | "
            f"{b['attempts']} | {b['idle_records']} | {b['wall']:.0f} | "
            f"{b['tool_calls']} | {b['llm_calls']} | {b['input_tokens']} | "
            f"{b['output_tokens']} | {fp_txt} |"
        )
    lines += [
        "",
        "## 合计",
        "",
        f"- 题数 {t['challenges']}，解出 {t['solved']}（{t['solved']/max(t['challenges'],1):.0%}）",
        f"- 真实尝试 {t['attempts']} 次，空转重试 {t['idle_records']} 条",
        f"- 墙钟求和 {t['wall_s']:.0f}s，跨度 {t['span_s']:.0f}s，"
        f"并发度 {t['overlap']}（≈1 = 车道被串行化）",
        f"- 工具调用 {t['tool_calls']} 次，LLM 调用 {t['llm_calls']} 次，"
        f"input {t['input_tokens']} / output {t['output_tokens']} tokens",
        "",
        "## 每题效率",
        "",
    ]
    for qid, b in order:
        if b["solved"] and b["attempts"]:
            lines.append(
                f"- {qid}: {b['wall']/b['attempts']:.0f}s/尝试，"
                f"{b['tool_calls']} 次工具调用"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--state-dir", required=True)
    p.add_argument("--out", default="", help="报告输出路径（默认 <state-dir>/report.md）")
    args = p.parse_args()
    state_dir = Path(args.state_dir).expanduser()
    data = collect(state_dir)
    text = render(data)
    out = Path(args.out).expanduser() if args.out else state_dir / "report.md"
    out.write_text(text, encoding="utf-8")
    (state_dir / "stats.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=1, default=str),
        encoding="utf-8",
    )
    print(text)
    print(f"[report] 已写 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())