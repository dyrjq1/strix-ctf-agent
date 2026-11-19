"""卡↔工具对齐盘点：卡/playbook 里点名的工具 vs 工具目录 vs 各 kind 的注册集。

跑法（仓库根）：PYTHONPATH=src:vendor/src .venv/bin/python scripts/card_tool_audit.py
纯只读，不写任何状态；退出码 1 = 有卡点名了目录外的工具，或有卡会在某个
kind 下被 `_usable` 整张剔掉（静默消失）。

它跟 `tests/test_method_cards.py` 是同一套判据的两种用法：测试防回归，这个
脚本给临场复核看一眼全表。
"""
from __future__ import annotations

import collections
import re
import sys

from ctf_strix import catalogue, method_cards


def all_cards():
    seen = {}
    for card in (
        list(method_cards.CARDS)
        + list(method_cards.DOMAIN_CARDS)
        + list(method_cards.CATEGORY_FALLBACK.values())
        + list(method_cards.FILE_CATEGORY_FALLBACK.values())
    ):
        seen[id(card)] = card
    return list(seen.values())


def main() -> int:
    registered = {info.name for info in catalogue.CATALOGUE}
    print(f"catalogue tools ({len(registered)}): {' '.join(sorted(registered))}")

    blobs = [("card:" + c.cid, c.text) for c in all_cards()]
    blobs += [
        ("playbook:web", method_cards.PLAYBOOK),
        ("playbook:file", method_cards.FILE_PLAYBOOK),
        ("playbook:tcp", method_cards.TCP_PLAYBOOK),
    ]

    ghost: dict[str, list[str]] = collections.defaultdict(list)
    use: collections.Counter[str] = collections.Counter()
    for name, text in blobs:
        for span in re.findall(r"`([^`]+)`", text):
            use[span] += 1
            if span not in registered:
                ghost[span].append(name)

    print(f"\nbackticked spans that are NOT a catalogue tool: {len(ghost)}")
    for span, where in sorted(ghost.items()):
        print(f"  GHOST {span!r} in {where[:3]}")

    print("\ntool usage across cards/playbooks:")
    for name, n in sorted(use.items()):
        if name in registered:
            print(f"  {n:3d}  {name}")

    # 每张卡点了哪些工具
    print("\nper-card tool names:")
    for card in sorted(all_cards(), key=lambda c: c.cid):
        named = sorted({n for n in re.findall(r"`([a-z0-9_]+)`", card.text) if n in registered})
        print(f"  {card.cid:28s} {', '.join(named) or '(none)'}")

    # 每张卡会被发到哪些 kind，以及那些 kind 下工具是否真的注册
    kinds_of = {info.name: info.kinds for info in catalogue.CATALOGUE}

    def where(card):
        if card.kinds:
            return tuple(sorted(card.kinds))
        if card in method_cards.CARDS:
            return ("web", "checker", "engagement")
        if card in method_cards.DOMAIN_CARDS:
            return ("file", "tcp")
        if card.cid in {c.cid for c in method_cards.FILE_CATEGORY_FALLBACK.values()}:
            return ("file",)
        return ("file", "tcp")

    print("\nkind × card: tools that would be filtered out (card still ships if >=1 survives)")
    bad_total = 0
    for card in sorted(all_cards(), key=lambda c: c.cid):
        named = sorted({n for n in re.findall(r"`([a-z0-9_]+)`", card.text) if n in registered})
        for kind in where(card):
            missing = [n for n in named if "*" not in kinds_of[n] and kind not in kinds_of[n]]
            if missing:
                bad_total += 1
                print(f"  {card.cid:28s} kind={kind:9s} MISSING {missing}")
    if not bad_total:
        print("  (none: every card's tools are registered under every kind it can be served to)")

    return 0 if not ghost and not bad_total else 1


if __name__ == "__main__":
    sys.exit(main())