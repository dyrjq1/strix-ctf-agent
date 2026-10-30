"""离线复核：拿已保存的运行日志重新判定，不重跑 agent。

## 为什么需要它

评测跑一轮要烧几十万 token，而"判定"这一步是纯后处理——flag 就在日志里
（或不在）。判定写错了、平台换了端点、只想补一次 checker 复核，都不该重跑
agent，更不该重跑靶机。

SAMPLE-002 就是这么一次教训：run.log 里明明白白有
``FLAG{1b89b7e8d76a29d75d9defa89c93b536}``，记录却是 ``ok=false / flag=null``，
连 ``submissions`` 字段都缺——看着像"平台判错"，其实是记录生成路径的问题。
有这份日志，就能原地复现；没有，就只能猜。

## 用法

复核单份日志（需要自己起实例、拿 instance_id）::

    PYTHONPATH=src:vendor/src .venv/bin/python scripts/rejudge.py \
        --token "$TOKEN" --challenge SAMPLE-002 --log /tmp/samplebox/sample-SAMPLE-002/run.log

批量补判 jsonl 里所有 ok=false 的题（会重新起实例）::

    ... scripts/rejudge.py --token "$TOKEN" --results /tmp/sample/r1.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import requests  # noqa: E402

from eval_sample import (  # noqa: E402
    Client,
    classify,
    extract_flag_candidates,
    parse_usage,
)

#: 无 flag 的题（checker 型）：判定走 /check，不看日志文本。
CHECKER_HINT = "=== THIS CHALLENGE HAS NO FLAG"


def judge(
    cli: Client, iid: str, log: str, detail: dict[str, Any], verbose: bool = True
) -> dict[str, Any]:
    """对一份日志 + 一个实例给出判定。

    Args:
        cli: 平台客户端。
        iid: 该题当前存活的实例 id。
        log: agent 运行日志全文。
        detail: 实例详情。
        verbose: 打印每次提交的中间结果——批量复核时要看清是哪一步失败。

    Returns:
        ``{"ok", "flag", "kind", "submissions", "checker"}``。
    """
    kind, info = classify(detail)
    out: dict[str, Any] = {
        "ok": False, "flag": None, "kind": kind,
        "submissions": [], "checker": [],
    }

    if info["has_flag_q"]:
        # 先把"可能带空格/换行的 flag"归一化：日志里 flag 出现在 shell 命令、
        # JSON 字符串、markdown 反引号里，正则能把它们都抓住，代价是偶尔会
        # 抓到被截断的片段——那些交给平台判错即可，反正 attempts_cap 是 null。
        cands = extract_flag_candidates(log)
        out["candidates"] = cands[:10]
        if verbose:
            print(f"  kind={kind} 候选 {len(cands)} 个: {cands[:5]}")
        for flag in cands[:8]:
            for qid, mode in info["modes"].items():
                if mode not in ("dynamic", "static"):
                    continue
                res = cli.submit_flag(iid, qid, flag)
                row = {
                    "flag": flag, "qid": qid,
                    **{k: res.get(k) for k in
                       ("correct", "solve_rank", "detail", "error", "question_id")},
                }
                out["submissions"].append(row)
                if verbose:
                    print(f"    submit {qid} {flag[:44]} -> correct={res.get('correct')} "
                          f"rank={res.get('solve_rank')} err={res.get('error')}")
                if res.get("correct"):
                    out["flag"] = flag
                    out["ok"] = True
                    break
            if out["ok"]:
                break

    # checker：门控题必须重新拉详情——flag 没提交前 checker question 不出现。
    if info["has_checker"] or not info["has_flag_q"]:
        try:
            fresh = cli.detail(iid)
            todo = [
                q["id"] for q in (fresh.get("questions") or [])
                if q.get("mode") == "checker"
            ]
        except requests.RequestException:
            todo = [q for q, m in info["modes"].items() if m == "checker"]
        for qid in todo:
            res = cli.run_checker(iid, qid)
            row = {"qid": qid, **{k: res.get(k) for k in
                                  ("passed", "exit_code", "timed_out", "error")}}
            out["checker"].append(row)
            if verbose:
                print(f"    check {qid} -> passed={res.get('passed')} "
                      f"exit={res.get('exit_code')} err={res.get('error')}")
            if res.get("passed"):
                out["ok"] = True
    return out


def rejudge_log(cli: Client, challenge: str, log: str, tag: str) -> dict[str, Any]:
    """起一个实例，用这份日志做判定，然后销毁实例。"""
    iid = cli.launch(challenge)
    try:
        detail = cli.detail(iid)
        res = judge(cli, iid, log, detail)
        res["challenge"] = challenge
        res["usage"] = parse_usage(log)
        res["tag"] = tag
        return res
    finally:
        cli.teardown(iid)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--token", required=True)
    ap.add_argument("--log", help="单份日志路径")
    ap.add_argument("--challenge", help="配 --log 用，题号如 SAMPLE-002")
    ap.add_argument("--results", help="jsonl 结果文件，逐条补判 ok=false 的题")
    ap.add_argument("--out", help="把复核结果追加写到这里（jsonl）")
    ap.add_argument("--all", action="store_true", help="配 --results 时连 ok=true 也复核")
    args = ap.parse_args()

    cli = Client(args.token)
    report: list[dict[str, Any]] = []

    if args.log and args.challenge:
        log = Path(args.log).read_text(encoding="utf-8", errors="replace")
        print(f"复核 {args.challenge} <- {args.log}")
        report.append(rejudge_log(cli, args.challenge, log, args.log))
    elif args.results:
        rows = [json.loads(x) for x in Path(args.results).read_text(
            encoding="utf-8").splitlines() if x.strip()]
        for rec in rows:
            if rec.get("ok") and not args.all:
                print(f"跳过 {rec['id']}（已 ok）")
                continue
            # 日志优先读落档的副本，退回 /tmp/samplebox 的现场。
            cand = [
                rec.get("log_path"),
                f"/tmp/samplebox/sample-{rec['id']}/run.log",
            ]
            path = next((p for p in cand if p and Path(p).exists()), None)
            if not path:
                print(f"跳过 {rec['id']}：找不到日志")
                continue
            print("=" * 60)
            print(f"复核 {rec['id']} <- {path}")
            log = Path(path).read_text(encoding="utf-8", errors="replace")
            r = rejudge_log(cli, rec["id"], log, path)
            print(f"  => {'OK' if r['ok'] else 'FAIL'} flag={r['flag']}")
            report.append(r)
    else:
        ap.error("要么给 --log/--challenge，要么给 --results")

    if args.out and report:
        with Path(args.out).open("a", encoding="utf-8") as fh:
            for r in report:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\n已追加 {len(report)} 条到 {args.out}")

    print("\n" + "=" * 60)
    for r in report:
        print(f"{r['challenge']:<12} {'OK  ' if r['ok'] else 'FAIL'} {r['flag'] or ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
