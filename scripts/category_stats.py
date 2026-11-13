#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按题型（category）汇总一个 compete state 目录的解出率。

用途：整夜回归时判断「变强了没有」必须分题型看——历史上 40 个解几乎全来自
web，把 web 的分数混在一起会掩盖 crypto/rev/misc/pwn 的真实短板。

口径与 ``scripts/compete_report.py`` 一致：

- 「尝试」= ``runs/<qid>.jsonl`` 里 ``tool_calls > 0 or usage.llm_calls > 0``
  的记录（其余是实例未就绪/隧道超时的空转重试）；
- 「解出」= 该题任一记录 ``correct`` 为真，或 ``state.json`` 里 status=solved；
- 题型/难度取记录里带的 ``category`` / ``difficulty``，记录没有时回落到
  ``state.json`` 的 ``category``/``difficulty``（compete 派单时写入）。

用法::

    python scripts/category_stats.py --state-dir ~/night-state-cy
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import defaultdict
from pathlib import Path


def _rows(path: str) -> list[dict]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _launched(rec: dict) -> bool:
    usage = rec.get("usage") or {}
    return int(rec.get("tool_calls") or 0) > 0 or int(usage.get("llm_calls") or 0) > 0


def collect(state_dir: Path) -> dict[str, dict]:
    state: dict = {}
    sp = state_dir / "state.json"
    if sp.exists():
        try:
            state = json.loads(sp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            state = {}

    per: dict[str, dict] = defaultdict(
        lambda: dict(chals=0, solved=0, attempts=0, wall=0.0, cat="", diff=0)
    )
    for path in sorted(glob.glob(str(state_dir / "runs" / "*.jsonl"))):
        qid = os.path.basename(path)[:-6]
        rows = _rows(path)
        if not rows:
            continue
        rec0 = rows[0]
        st = state.get(qid) or {}
        cat = rec0.get("category") or st.get("category") or "?"
        bucket = per[cat]
        bucket["cat"] = cat
        bucket["chals"] += 1
        seen = False
        solved = (st.get("status") == "solved")
        for rec in rows:
            if _launched(rec):
                bucket["attempts"] += 1
                bucket["wall"] += float(rec.get("total_s") or 0)
                seen = True
            if rec.get("correct"):
                solved = True
        if solved:
            bucket["solved"] += 1
        if not seen:
            bucket["diff"] += 1
    return per


def render(per: dict[str, dict]) -> str:
    lines = [
        "| 题型 | 题数 | 解出 | 解出率 | 真实尝试 | 墙钟(s) | 只有空转 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    tot = dict(chals=0, solved=0, attempts=0, wall=0.0, diff=0)
    for cat in sorted(per, key=lambda c: (-per[c]["chals"], c)):
        b = per[cat]
        rate = 100.0 * b["solved"] / b["chals"] if b["chals"] else 0.0
        lines.append(
            f"| {cat} | {b['chals']} | {b['solved']} | {rate:.0f}% | "
            f"{b['attempts']} | {b['wall']:.0f} | {b['diff']} |"
        )
        for k in ("chals", "solved", "attempts", "diff"):
            tot[k] += b[k]
        tot["wall"] += b["wall"]
    rate = 100.0 * tot["solved"] / tot["chals"] if tot["chals"] else 0.0
    lines.append(
        f"| **合计** | {tot['chals']} | {tot['solved']} | {rate:.0f}% | "
        f"{tot['attempts']} | {tot['wall']:.0f} | {tot['diff']} |"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--state-dir", required=True)
    args = p.parse_args()
    print(render(collect(Path(args.state_dir))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())