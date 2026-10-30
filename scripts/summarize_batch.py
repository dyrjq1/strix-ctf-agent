"""把批量评测的 JSONL 汇总成可读的表格与失败归因。

用法：
    python3 scripts/summarize_batch.py /tmp/batch/results.jsonl
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load(path: str) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def classify_failure(log_path: Path) -> str:
    """给失败归类。这才是批量评测里最有价值的部分——知道为什么输。"""
    if not log_path.exists():
        return "无日志"
    text = log_path.read_text(encoding="utf-8", errors="ignore")

    if "WALLCLOCK TIMEOUT" in text:
        return "墙钟超时（占满预算）"
    if "MaxTurnsExceeded" in text:
        return "turn 用尽"
    if "login failed" in text.lower() or "401" in text:
        return "卡在登录/认证"
    tool_calls = text.count(" TOOL ")
    if tool_calls < 10:
        return f"过早放弃（仅 {tool_calls} 次调用）"
    return "跑满但没找到"


def main(path: str) -> None:
    rows = load(path)
    if not rows:
        print("没有数据")
        return

    print(f"共 {len(rows)} 题\n")

    # --- 主表 ---
    header = f"{'#':>2} {'题目':<15} {'难度':<7} {'结果':<7} {'调用':>4} {'agent':>7} {'平台':>7} {'rank':>4}"
    print(header)
    print("-" * len(header))
    for r in rows:
        ok = "✅" if r.get("correct") else "❌"
        solve = f"{r['solve_time_s']:.0f}s" if r.get("solve_time_s") else "-"
        rank = r.get("solve_rank") or "-"
        print(
            f"{r['idx']:>2} {r['challenge']:<15} {r['difficulty']:<7} {ok:<7} "
            f"{r.get('tool_calls', 0):>4} {r.get('agent_s', 0):>6.0f}s {solve:>7} {str(rank):>4}"
        )

    # --- 按难度聚合 ---
    print("\n=== 按难度 ===")
    by = defaultdict(list)
    for r in rows:
        by[r["difficulty"]].append(r)
    for diff in ("easy", "medium", "hard"):
        if diff not in by:
            continue
        group = by[diff]
        solved = sum(1 for r in group if r.get("correct"))
        tools = [r.get("tool_calls", 0) for r in group]
        times = [r["agent_s"] for r in group if r.get("agent_s")]
        print(
            f"  {diff:<7} {solved}/{len(group)} 解出   "
            f"平均调用 {sum(tools)/len(tools):.0f}   "
            f"平均耗时 {sum(times)/len(times):.0f}s"
        )

    total = sum(1 for r in rows if r.get("correct"))
    print(f"\n总计: {total}/{len(rows)} = {total/len(rows)*100:.0f}%")

    # --- 失败归因 ---
    fails = [r for r in rows if not r.get("correct")]
    if fails:
        print("\n=== 失败归因 ===")
        reasons = Counter()
        for r in fails:
            log = Path(f"/tmp/batch/batch-{r['idx']:02d}-{r['challenge']}.log")
            reason = classify_failure(log)
            reasons[reason] += 1
            print(f"  {r['challenge']:<15} {r['difficulty']:<7} {reason}")
        print("\n  汇总:", dict(reasons))

    # --- 调度效率 ---
    print("\n=== 调度开销 ===")
    launches = [r.get("launch_s", 0) for r in rows if r.get("launch_s")]
    totals = [r.get("total_s", 0) for r in rows]
    if launches:
        print(f"  实例启动: 平均 {sum(launches)/len(launches):.1f}s  最大 {max(launches):.1f}s")
    print(f"  单题总占用（含启动+拆除）: 平均 {sum(totals)/len(totals):.0f}s")
    print(f"  10h 场次理论吞吐: {36000/(sum(totals)/len(totals)):.0f} 题")


if __name__ == "__main__":
    main(sys.argv[1])
