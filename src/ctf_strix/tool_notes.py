"""工具结果注脚：追加文字时保住生命周期工具的 JSON 形状。

## 为什么

vendor 的 ``finish_scan`` / ``agent_finish`` 把生命周期结果序列化成一条
JSON 字符串；``factory._lifecycle_tool_completed`` 对它做 ``json.loads``，
只有解析成功且 ``success && scan_completed``（或 ``agent_completed``）时
SDK 才 ``is_final_output=True``，run 才会结束。

而本项目的 8 个守卫都按 ``f"{result}{hint}"`` 往结果末尾追加文本
（turn budget、soft deadline、enum、journey、progress、sweep、negative、
restart），autosubmit 还会追加 ``--- platform submission ---``。只要其中
任何一个在 ``finish_scan`` 上触发，JSON 后面就多出一段裸文本，
``json.loads`` 抛 ``Extra data`` → 生命周期检测失明 → 外层循环不停 →
恢复提示让模型"再交一次" → 模型再调 ``finish_scan`` → 直到
``MaxTurnsExceeded``。

实测（SAMPLE-007，2026-11-13 run3）：一次 run 里 8 次 ``finish_scan`` 全部
执行成功、``agent.status=completed`` 写了 8 次，但循环一直没停，25 轮预算
烧完后以 ``MaxTurnsExceeded`` 收场，``stop_reason=error``。

## 做法

``append_note`` 只在结果**确实是生命周期 JSON**（顶层对象且含
``scan_completed`` 或 ``agent_completed``）时改成结构化写法：注脚进
``_ctf_notes`` 数组，顶层键原样保留，再重新序列化。其他结果（普通文本、
非生命周期 JSON、非字符串）仍按原样追加——改动面只落在会被运行时解析的
那两个工具上。
"""

from __future__ import annotations

import json
from typing import Any


#: 生命周期工具在结果里带的完成标记。``finish_scan`` 用前者，
#: 子 agent 的 ``agent_finish`` 用后者。
LIFECYCLE_KEYS: tuple[str, ...] = ("scan_completed", "agent_completed")


def append_note(result: Any, note: str) -> Any:
    """把 ``note`` 附到工具结果上，且不破坏生命周期 JSON。

    Args:
        result: 工具原始返回值。通常是字符串；非字符串原样返回。
        note: 要追加的提示文本（可以带前导换行）。

    Returns:
        生命周期 JSON → 同键 JSON 字符串，注脚在 ``_ctf_notes``；
        其他字符串 → 原样拼接；其他类型 → 原对象。
    """
    if not note:
        return result
    if not isinstance(result, str):
        return result
    try:
        obj = json.loads(result)
    except (TypeError, ValueError):
        return result + note
    if not isinstance(obj, dict) or not any(k in obj for k in LIFECYCLE_KEYS):
        return result + note
    notes = obj.get("_ctf_notes")
    if not isinstance(notes, list):
        notes = []
    notes.append(note.strip())
    obj["_ctf_notes"] = notes
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return result + note
