"""从 strix 的运行状态重建每次 LLM 调用的 token 用量。

为什么需要这个：strix 的 ``provider_data`` 只留了 ``model`` 和 ``response_id``，
把 API 返回的 ``usage`` 丢掉了（见 agents.db 里的消息记录）。而 token 是评测
成本的硬指标——不测就只能猜。

好消息是 agents.db 存了**全部消息正文**，而 chat completions 的 prompt 就是将
历史消息重新序列化后发过去。所以按「每轮把已有消息序列化一次」累计，就能得到
与 API 口径接近的 prompt token 数；completion 用返回文本估算。

口径说明（写在这里避免误读）：
  · prompt 用字符数 / 5.0 估算（两个实测样本分别为 5.23 与 4.89）；
  · ⚠️ DeepSeek-V4.1-Flash 默认开思维链，reasoning_tokens 计入
    completion_tokens。thought 内容不在 message.content 里，所以本脚本的
    completion 只是**可见输出**的下界，真实值更高；
  · 每次工具调用都会触发一轮新的 completion，历史全量重发，所以 prompt
    随轮次线性增长——这正是"轮次越多、单价越贵"的来源。
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

# 实测校准（2026-10-28，DeepSeek-V4.1-Flash）：
#   · 纯英文输出  230 字符 / 44 completion_tokens  = 5.23
#   · 中文思维链  3910 字符 / 800 reasoning_tokens = 4.89
# 取 5.0。早先用的 3.2 来自"字节数 ÷ token"，遇上多字节中文会严重低估。
CHARS_PER_TOKEN = 5.0


def _text_len(msg: dict) -> int:
    """一条消息序列化后的字符数，作为 prompt 占用的代理指标。"""
    parts: list[str] = []
    role = msg.get("role") or ""
    parts.append(str(role))
    content = msg.get("content")
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for c in content:
            if isinstance(c, dict):
                parts.append(str(c.get("text") or ""))
    if msg.get("arguments"):
        parts.append(str(msg["arguments"]))
    if msg.get("output"):
        parts.append(str(msg["output"]))
    if msg.get("summary"):
        parts.append(json.dumps(msg["summary"], ensure_ascii=False))
    return len(" ".join(parts))


def measure(db: Path) -> dict[str, int]:
    """统计一个 run 的 token 用量。

    Args:
        db: ``<run>/.state/agents.db``。

    Returns:
        ``{"calls", "prompt_tokens", "completion_tokens", "total_tokens"}``。
    """
    if not db.is_file():
        return {}

    conn = sqlite3.connect(db)
    rows = [json.loads(md) for (md,) in conn.execute("select message_data from agent_messages")]
    conn.close()

    # 一次「LLM 调用」= 一条 assistant 消息。它的 prompt 是此前所有消息之和。
    calls = 0
    prompt_chars = 0
    completion_chars = 0
    running = 0
    for msg in rows:
        running += _text_len(msg)
        if msg.get("role") == "assistant":
            calls += 1
            prompt_chars += running
            completion_chars += _text_len(msg)

    prompt_tokens = int(prompt_chars / CHARS_PER_TOKEN)
    completion_tokens = int(completion_chars / CHARS_PER_TOKEN)
    return {
        "calls": calls,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }


def main() -> None:
    base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("strix_runs")
    print(f"{'run':<32} {'calls':>6} {'prompt':>9} {'completion':>11} {'total':>9}")
    print("-" * 72)
    # 用 rglob 而不是 glob：run 目录可能嵌套多层。沙箱模式下每题是
    # /tmp/ctfbox/<题名>/strix_runs/<run>/.state/agents.db，深度不固定。
    ordered = sorted(base.rglob(".state/agents.db"), key=lambda p: p.parent.parent.name)
    grand = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for db in ordered:
        m = measure(db)
        if not m:
            continue
        for k in grand:
            grand[k] += m[k]
        print(
            f"{db.parent.parent.name:<32} {m['calls']:>6} {m['prompt_tokens']:>9,} "
            f"{m['completion_tokens']:>11,} {m['total_tokens']:>9,}"
        )
    print("-" * 72)
    print(
        f"{'合计':<32} {grand['calls']:>6} {grand['prompt_tokens']:>9,} "
        f"{grand['completion_tokens']:>11,} {grand['total_tokens']:>9,}"
    )


if __name__ == "__main__":
    main()
