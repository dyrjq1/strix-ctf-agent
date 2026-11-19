"""第五轮自选：把"这题该看哪几张打法卡"交回给模型自己定。

## 为什么

2026-11-19 用户定的机制：起手只给 playbook + 至多 3 张卡；跑到第 5 次工具
调用时，把**本题候选卡的菜单**（id + 一行标题，不含正文）摆出来，让模型按
"它已经看到的东西"点 3 张，再把这 3 张的正文注入。

下一次尝试**可以换也可以续**：用户口径是"如果模型在总结里认为那张卡有用，
下一轮还可以继续选"。菜单只用 ``*`` 标出选过的，不做任何强制轮换——这一步
的判据是模型对自己上一轮的判断，不是我们的计数器。

动机是今天（11-19 测试赛）的实测：全部 5 道题 0 张卡命中——平台 tag 是题型词
（`web,linux` / `pwn,heap`），卡表键是技术词，交集恒空。而"看到什么再决定
看哪张"这件事只能由模型做，确定性规则做不到。

## 约束

* 提示面为零：菜单里的 id 与标题来自本仓库固定文案，平台 tag/题面不进提示；
  模型给回未知 id 只是被忽略。
* 有上限：一次最多 :data:`MAX_PICK` 张、正文总长不超过 :data:`MAX_PICK_CHARS`；
  超出的截断并显式说明。
* 没有卡池时工具不注册（`:func:`install` 返回空列表），模型无从调用。
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from ctf_strix.method_cards import Card

logger = logging.getLogger(__name__)

#: 一次可选的最大卡数（用户口径：3 张）。
MAX_PICK = 3

#: 选中卡正文的总字符上限；超出的卡整张丢弃并提示。
MAX_PICK_CHARS = 1600

#: 模块级卡池与已选项。进程内单例，attempt 之间由 :func:`set_pool` 复位。
_POOL: list["Card"] = []
_CHOSEN: list[str] = []
_CHALLENGE = ""


def set_pool(cards: list["Card"], challenge_id: str = "") -> None:
    """给本 run 设定候选卡池（agent 启动时调用）。"""
    global _POOL, _CHOSEN, _CHALLENGE
    _POOL = list(cards)
    _CHOSEN = []
    _CHALLENGE = str(challenge_id or "")
    if _POOL:
        used = _load_used()
        if used:
            logger.info("card pick: previously used %s", used)


def reset_attempt() -> None:
    """新 attempt：清空"本次已选"，卡池与跨 attempt 的已用记录都不动。

    ``agent.py`` 的 attempt 循环里与 ``card_menu.reset_current`` 一起调用：
    不复位的话第二次 attempt 的菜单永远不会出现（"已经选过卡"的判据挂住）。
    """
    global _CHOSEN
    _CHOSEN = []


def chosen() -> list[str]:
    """本次 attempt 已选中的卡 id（没选过为空）。"""
    return list(_CHOSEN)


def pool_size() -> int:
    return len(_POOL)


def used() -> list[str]:
    """本 attempt 与之前各 attempt 累计点过的卡 id（菜单 ``*`` 标记同源）。

    收场记账要回答「上一轮选了什么方法卡」，而 ``chosen()`` 在每次 attempt
    开头就被清空——只读它，收场时永远看到空列表。跨 attempt 的累计记录本来
    就为菜单的 ``*`` 存在（``CTF_CARDS_STATE``），这里把它暴露成只读视图。
    """
    out = list(_CHOSEN)
    for cid in _load_used():
        if cid not in out:
            out.append(cid)
    return out


def _state_path() -> Path | None:
    """跨 attempt 的已用卡记录路径；``CTF_CARDS_STATE`` 未设则不落盘。"""
    raw = os.environ.get("CTF_CARDS_STATE", "").strip()
    if not raw or not _CHALLENGE:
        return None
    return Path(raw) / f"{_CHALLENGE.replace('/', '_')}.json"


def _load_used() -> list[str]:
    path = _state_path()
    if path is None or not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    used = data.get("used") if isinstance(data, dict) else None
    return [str(x) for x in used] if isinstance(used, list) else []


def _save_used(ids: list[str]) -> None:
    path = _state_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        merged = sorted(set(_load_used()) | {str(i) for i in ids})
        path.write_text(json.dumps({"used": merged}, ensure_ascii=False), encoding="utf-8")
    except OSError:  # 记不上账不能拖垮挑战本身
        logger.warning("card pick: cannot persist %s", path, exc_info=True)


def menu() -> str:
    """菜单文本：每条 ``id — 标题``，末尾写清怎么点。没卡池时为空串。"""
    if not _POOL:
        return ""
    used = set(_load_used())
    lines = ["[Method cards] 这一步你已经有观测了。下面是本题可选的打法卡，"
             f"按你看到的证据挑至多 {MAX_PICK} 张（* = 之前选过：总结里说它有用就"
             "继续选，没推进就换）："]
    for card in _POOL:
        mark = " *" if card.cid in used else ""
        lines.append(f"- {card.cid}{mark}：{card.title}")
    lines.append(
        '选完调用 `method_cards_pick`，参数 ids 传卡 id 列表，例如 '
        '{"ids": ["%s"]}；只想沿用起手那几张就传空列表。' % _POOL[0].cid
    )
    return "\n".join(lines)


def _pick(ids: list[str]) -> str:
    """按 id 取卡正文（工具实现）。未知 id 忽略，超预算整张丢弃。"""
    if not _POOL:
        return "本题没有可选打法卡。"
    wanted = [str(i).strip() for i in (ids or []) if str(i).strip()]
    if not wanted:
        return "未选卡；继续按起手 playbook 走。"
    by_id = {card.cid: card for card in _POOL}
    picked: list["Card"] = []
    missing: list[str] = []
    for cid in wanted:
        card = by_id.get(cid)
        if card is None:
            missing.append(cid)
        elif card not in picked:
            picked.append(card)
    picked = picked[:MAX_PICK]
    out: list[str] = []
    used = 0
    dropped: list[str] = []
    for card in picked:
        if used + len(card.text) > MAX_PICK_CHARS:
            dropped.append(card.cid)
            continue
        out.append("- " + card.text)
        used += len(card.text)
        if card.cid not in _CHOSEN:
            _CHOSEN.append(card.cid)
    _save_used(_CHOSEN)
    parts = ["[Method cards] 已注入你选的 %d 张：" % len(out), *out]
    if dropped:
        parts.append("[截断] 超预算丢弃：" + ", ".join(dropped))
    if missing:
        parts.append("[忽略] 不存在的 id：" + ", ".join(missing))
    parts.append("按这几张的先后顺序做；卡只是先看哪里，不是结论。")
    return "\n".join(parts)


def _as_async(func: Any) -> Any:
    """Async thin wrapper; ``functools.wraps`` keeps the schema's parameters.

    The SDK derives the JSON schema from ``inspect.signature``, which follows
    ``__wrapped__``.  Without the wrap the tool exposes no parameters and the
    model cannot pass ``ids`` at all.
    """

    import functools

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    return wrapper


def method_cards_pick(ids: list[str]) -> str:
    """Pick up to three method cards for this challenge, by id.

    Call it once, a few tool calls in, after you have seen the surface: the
    menu is injected for you. Unknown ids are ignored; it returns the card
    bodies.

    Args:
        ids: Card ids from the menu, at most three.

    Returns:
        The selected cards' text, or a note that nothing was selected.
    """
    return _pick(ids)


def install(register_fn: Any = None) -> list[str]:
    """注册 ``method_cards_pick``；卡池为空时不注册（返回空列表）。"""
    if not _POOL:
        return []
    if register_fn is None:
        from strix.agents import factory

        register_fn = factory.register_agent_tools
        try:
            existing = {getattr(t, "name", "") for t in factory.registered_agent_tools()}
        except Exception:  # noqa: BLE001
            existing = set()
    else:
        existing = set()

    from agents import function_tool

    wrapped = [function_tool(timeout=30)(_as_async(method_cards_pick))]
    fresh = [t for t in wrapped if getattr(t, "name", "") not in existing]
    if fresh:
        register_fn(*fresh)
    return [t.name for t in fresh]