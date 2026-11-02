#!/usr/bin/env python3
"""校验评测池没有被偷偷重切。

## 为什么需要这个脚本

`experiments/pools.json` 是**尺子**。尺子被改一次，之前所有"提升 X%"都失去意义，
而这种改动在 git diff 里只是几个题号变了，人眼看不出来。

所以池子旁边放一个 `pools.json.sha256`。这个脚本做两件事：

1. 文件哈希与 `.sha256` 不一致 → 有人改过池子（`--resign` 才允许重签）
2. 结构断言：诊断池 / 储备池 / 官方封存集 / 已跑集合四者互不重叠

第 2 条比第 1 条重要。哈希只能证明"没改过"，但如果有人在**生成池子时**
就把封存题切进诊断池（本仓库真发生过一次：CTFARENA-024 / 097 同时进了
诊断池和封存集），哈希是自洽的，错的是切法。

## 用法

    python scripts/check_pools.py            # 校验，失败退出码 1
    python scripts/check_pools.py --resign   # 明确承认"我改了尺子"，重签并打印 diff

## 什么时候允许 --resign

只在**补抽**时：封存集某道被跑过 → 按守则 §7.1 补抽 → 重签 → 台账记
`HELDOUT-RESEAL`。其余任何理由（"这题太难了换个简单的"）都是尺子作弊。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POOLS = ROOT / "experiments" / "pools.json"
SEAL = ROOT / "experiments" / "pools.json.sha256"


def digest() -> str:
    """池子文件的 sha256。"""
    return hashlib.sha256(POOLS.read_bytes()).hexdigest()


def structural_errors(data: dict) -> list[str]:
    """四条集合互斥检查。

    Args:
        data: ``pools.json`` 解析结果。

    Returns:
        人类可读的错误列表；空表示通过。
    """
    def ids(key: str) -> set[str]:
        return {x["id"] for x in data.get(key, []) if isinstance(x, dict)}

    diag = ids("diagnostic")
    reserve = ids("reserve")
    sealed = set(data.get("sealed_excluded") or [])
    burned = set(data.get("burned") or [])

    errs: list[str] = []
    for label_a, a, label_b, b in (
        ("diagnostic", diag, "reserve", reserve),
        ("diagnostic", diag, "sealed", sealed),
        ("reserve", reserve, "sealed", sealed),
        ("diagnostic", diag, "burned", burned),
        ("reserve", reserve, "burned", burned),
    ):
        both = sorted(a & b)
        if both:
            errs.append(f"{label_a} 与 {label_b} 重叠: {both}")
    # 诊断池允许为空：一批烧完之后到下一轮补抽之间，这个状态是正常的。
    # 为空时必须留一句 diagnostic_note 说明下一批从哪抽，否则等于"池子被删了"
    # 而没人知道，下一次就可能直接拿 reserve 开跑。
    if not diag and not str(data.get("diagnostic_note") or "").strip():
        errs.append("diagnostic 为空且没有 diagnostic_note 说明")
    # 注意：上面 diag 已经是 id 集合，这里必须回到原始列表才能查字段。
    raw_diag = data.get("diagnostic") or []
    missing = sorted(
        str(x.get("id")) if isinstance(x, dict) else repr(x)
        for x in raw_diag
        if not isinstance(x, dict) or not x.get("bucket")
    )
    if missing:
        errs.append(f"diagnostic 有条目缺 bucket: {missing}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resign", action="store_true",
                    help="承认修改了尺子，重写 .sha256")
    args = ap.parse_args()

    if not POOLS.exists():
        print(f"缺少 {POOLS}", file=sys.stderr)
        return 1
    data = json.loads(POOLS.read_text(encoding="utf-8"))

    errs = structural_errors(data)
    if errs:
        print("池子结构有问题：", file=sys.stderr)
        for e in errs:
            print("  - " + e, file=sys.stderr)
        print("\n这是尺子坏了，不是数据坏了。先修结构再谈跑题。", file=sys.stderr)
        return 1

    cur = digest()
    sealed_hash = SEAL.read_text(encoding="utf-8").split()[0] if SEAL.exists() else ""

    if args.resign:
        SEAL.write_text(f"{cur}  pools.json\n", encoding="utf-8", newline="\n")
        print(f"已重签: {cur}")
        print(f"诊断池 {len(data['diagnostic'])} 道 / 储备池 {len(data['reserve'])} 道")
        print("⚠️ 记得在 docs/11 台账记一行 HELDOUT-RESEAL 并写原因。")
        return 0

    if cur != sealed_hash:
        print("池子被改过！", file=sys.stderr)
        print(f"  当前:   {cur}", file=sys.stderr)
        print(f"  已记录: {sealed_hash or '(无)'}", file=sys.stderr)
        print("\n如果是有意补抽，用 --resign 并记台账；否则恢复文件。", file=sys.stderr)
        return 1

    print(f"OK  {cur}")
    print(f"  诊断池 {len(data['diagnostic'])} 道（可烧）")
    print(f"  储备池 {len(data['reserve'])} 道（未烧，可补进封存）")
    print(f"  封存集 {len(data.get('sealed_excluded') or [])} 道（定稿前只跑一次）")
    print(f"  已烧   {len(data.get('burned') or [])} 道（永久退出验证）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
