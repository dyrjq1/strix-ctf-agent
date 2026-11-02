#!/usr/bin/env python3
"""诊断批的失败形态分类器。

## 只回答一个问题

诊断池（20 道）跑完，我们不需要"成功率"这个数字，只需要知道**失败里
哪种形态占主导**：

  · 过早收敛  —— 调用次数很少就放弃。解法是"别急着停"，成本低。
  · 燃尽      —— 撞轮次/墙钟上限。解法是改搜索策略，不是加预算。
  · 方向错    —— 跑满了但没进展。解法是换机制。
  · 环境      —— 隧道/连通性失败。解法是修接入。

## 为什么分类要写进脚本

"看日志凭感觉分"会不自觉地把难看的归到"环境"，把好看的归到"方向错"。
阈值写死在这里，结果可复现，别人能拿着同样的规则复核。

用法：
    python scripts/diagnose.py /home/rjq/diag.jsonl
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

#: 判"过早收敛"：调用次数低于这个值就放弃。实测成功题 p50 是 15 次，
#: 所以 10 次以下还没解出来，多半是没试够，而不是题太难。
EARLY_CALLS = 10
#: 判"燃尽"：调用次数达到轮次上限（诊断批统一 25 轮）。
CAP_CALLS = 25


def classify(rec: dict) -> str:
    """给一条结果打失败形态标签。

    Args:
        rec: ``batch_eval`` 写出的一行结果。

    Returns:
        形态名。成功返回 ``SOLVED``。
    """
    if rec.get("correct"):
        return "SOLVED"

    err = str(rec.get("error") or "")
    if "SKIPPED" in err or "隧道" in err:
        return "环境"
    if err.startswith(("TimeoutError", "TunnelRequiredError")):
        return "环境"

    calls = rec.get("tool_calls")
    if not isinstance(calls, int):
        return "未跑"

    if rec.get("turn_capped") or rec.get("wallclock_hit"):
        return "燃尽"
    if calls <= EARLY_CALLS:
        return "过早收敛"
    return "方向错"


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: diagnose.py <results.jsonl>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not rows:
        print("没有结果行", file=sys.stderr)
        return 1

    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(classify(r), []).append(r)

    order = ["SOLVED", "过早收敛", "燃尽", "方向错", "环境", "未跑"]
    print(f"诊断批：{len(rows)} 道\n")
    print(f"{'形态':<10}{'题数':>5}{'占比':>8}   说明")
    print("-" * 78)
    notes = {
        "SOLVED": "解出，作为基线",
        "过早收敛": f"调用 <= {EARLY_CALLS} 就放弃 —— 最便宜的可改进项",
        "燃尽": "撞轮次/墙钟上限 —— 要改搜索策略，不是加预算",
        "方向错": "跑够了但没进展 —— 要换机制",
        "环境": "接入/隧道失败 —— 修环境，不算能力",
        "未跑": "没有调用数据 —— 看 error 字段",
    }
    for k in order:
        v = groups.get(k) or []
        if not v:
            continue
        print(f"{k:<10}{len(v):>5}{100*len(v)/len(rows):>7.0f}%   {notes[k]}")

    print("\n逐题：")
    for r in sorted(rows, key=lambda x: str(x.get("challenge"))):
        calls = r.get("tool_calls")
        print("  %-14s %-7s %-8s calls=%-4s %ss" % (
            r.get("challenge"), r.get("difficulty"), classify(r),
            calls if calls is not None else "-", r.get("agent_s")))

    fails = [r for r in rows if not r.get("correct")]
    if fails:
        calls = [r["tool_calls"] for r in fails if isinstance(r.get("tool_calls"), int)]
        secs = [r["agent_s"] for r in fails if isinstance(r.get("agent_s"), (int, float))]
        if calls:
            print(f"\n失败题调用数: p50={statistics.median(calls):.0f} max={max(calls)}")
        if secs:
            print(f"失败题耗时:   p50={statistics.median(secs):.0f}s max={max(secs):.0f}s")

    dominant = max((k for k in groups if k not in ("SOLVED", "未跑")),
                   key=lambda k: len(groups[k]), default=None)
    if dominant:
        print(f"\n主导失败形态：{dominant}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
