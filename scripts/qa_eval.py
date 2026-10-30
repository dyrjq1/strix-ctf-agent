"""选择题（QA 题库）通道：问一次、投三票、只在高置信时提交。

## 为什么不能"多试几次"

平台源码 ``core/config.py:2023`` 的 ``question_attempt_caps``：
``single_select`` 只给 **3 次**错误机会，锁死后只有管理员能重置。
四选一随机猜的期望是 0.75 次错误/题 —— 猜三题就锁两题。
所以这条通道的核心不是"答得多"，而是"**答不准就别交**"。

## 判分契约（源码级，不是猜的）

``ctfy/challenge/runtime.py:184`` 的 ``grade_one``：

```python
if mode is QuestionMode.SINGLE_SELECT:
    sub = submission.strip()
    return sub in choices and sub == answer
```

- **大小写敏感**：选项是 ``["A","B","C","D"]``，交 ``"a"`` 会在 ``sub in choices`` 就失败；
- 首尾空白会被 strip，其余一律原样比较；
- ``static`` 模式同理：``submission.strip() == answer.strip()``。

## 为什么要三票 + 打乱选项

``Zheng et al. 2023 (arXiv 2309.03882)``：LLM 当多选题选择器时有系统性
**位置偏置**（偏好某个位置），把选项顺序换掉再投票能显著降低这种偏差。
``Wang et al. 2022 (arXiv 2203.11171)`` 的自一致性：同一题多次采样取多数，
比单次贪心稳。两者叠起来就是本脚本的做法：**k 次独立采样，每次打乱选项，
投票映射回原始字母**。

## 用法

    python scripts/qa_eval.py --list
    python scripts/qa_eval.py --suite MMLU-CS --limit 20            # 只算不交
    python scripts/qa_eval.py --suite MMLU-CS --limit 20 --submit --register

产物：``~/qa-results.jsonl``，每题一行，可断点续跑（已解/已锁跳过）。
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from pathlib import Path

import requests

PLATFORM = "https://ctfy.tsinghua.edu.cn"
SUITES = {
    "MMLU-CS": "73e5785947414421bde36806ffe512dd",
    "CTI-MCQ": "821a8beda4114ec5885cf57082bf808a",
    "SECQA": "ba65f88cbe674c0eb7795391bc6faec7",
}
_LETTER = re.compile(r"\b([A-D])\b")
_OPT = re.compile(r"(?:^|\s)([A-D])\)\s*")


def parse_options(desc: str) -> tuple[str, list[tuple[str, str]]]:
    """把 ``description`` 拆成（题干, [(字母, 选项文本)]）。

    题库约定：题干和选项都在 ``description`` 里，形如
    ``... question?  A) foo B) bar C) baz D) qux``。``questions[].choices``
    只有字母，没有文本。

    Args:
        desc: 题目描述原文。

    Returns:
        ``(stem, options)``；解析不出四个选项时 options 为空。
    """
    marks = list(_OPT.finditer(desc or ""))
    if len(marks) < 2:
        return (desc or "").strip(), []
    stem = desc[: marks[0].start()].strip()
    opts: list[tuple[str, str]] = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(desc)
        opts.append((m.group(1), desc[m.end() : end].strip()))
    return stem, opts


def build_prompt(stem: str, opts: list[tuple[str, str]], order: list[int]) -> tuple[str, dict[str, str]]:
    """按给定顺序渲染选项，返回（提示, 展示字母 → 原始字母）。

    Args:
        stem: 题干。
        opts: 原始 (字母, 文本)。
        order: 展示顺序（opts 的下标列表）。

    Returns:
        ``(prompt, mapping)``；mapping 把"模型看到的字母"映射回原始字母。
    """
    shown = "ABCD"
    lines = []
    mapping: dict[str, str] = {}
    for slot, idx in enumerate(order):
        letter = shown[slot]
        orig, text = opts[idx]
        mapping[letter] = orig
        lines.append(f"{letter}) {text}")
    prompt = (
        "Answer this multiple-choice security question. Reply with ONLY the letter "
        "(A, B, C or D) of the correct option — no explanation, no punctuation.\n\n"
        f"Question: {stem}\n\n" + "\n".join(lines)
    )
    return prompt, mapping


def ask_llm(prompt: str, temperature: float) -> tuple[str, str]:
    """问一次模型，返回 ``(content, reasoning)``。

    ⚠️ 本机用的是 reasoning 模型（deepseek-v4.1-flash）：``max_tokens`` 给
    8 时 8 个 token 全花在 ``reasoning_content`` 上，``content`` 返回空串。
    实测确认过一次（finish_reason=length, reasoning_tokens=8）。所以：
    token 预算给足 600，并且把 reasoning 一并返回，让解析层能兜住。

    Args:
        prompt: 完整提示。
        temperature: 采样温度。

    Returns:
        ``(content, reasoning_content)``；请求失败时都是空串。
    """
    base = os.environ.get("LLM_API_BASE", "").rstrip("/")
    key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("STRIX_LLM", "openai/deepseek-v4.1-flash-1017").split("/", 1)[-1]
    if not base or not key:
        raise SystemExit("需要 LLM_API_BASE / LLM_API_KEY")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": 600,
    }
    r = requests.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json=body,
        timeout=60,
    )
    if r.status_code >= 400:
        return "", ""
    msg = ((r.json().get("choices") or [{}])[0].get("message") or {})
    return (msg.get("content") or ""), (msg.get("reasoning_content") or "")


def pick_letter(content: str, reasoning: str = "") -> str | None:
    """取答案字母：优先 content 的第一个，其次 reasoning 的**最后**一个。

    reasoning 里会复述选项（"A is wrong, B is wrong..."），结论在结尾，
    所以回退时取最后一个匹配，而不是第一个。

    Args:
        content: 模型正文。
        reasoning: 思考内容（content 为空时用）。

    Returns:
        大写字母；解析不到返回 None。
    """
    m = _LETTER.search((content or "").upper())
    if m:
        return m.group(1)
    hits = _LETTER.findall((reasoning or "").upper())
    return hits[-1] if hits else None


def vote(stem: str, opts: list[tuple[str, str]], k: int, temperature: float, seed: int) -> tuple[str | None, list[str]]:
    """k 次采样，每次打乱选项，按原始字母投票。

    Args:
        stem: 题干。
        opts: 原始选项。
        k: 采样次数。
        temperature: 采样温度。
        seed: 随机种子（同一题可复现）。

    Returns:
        ``(胜出字母, 全部原始字母票)``；无有效票时字母为 None。
    """
    rng = random.Random(seed)
    votes: list[str] = []
    base_order = list(range(len(opts)))
    for i in range(k):
        order = base_order[:]
        if i > 0:
            rng.shuffle(order)
        prompt, mapping = build_prompt(stem, opts, order)
        content, reasoning = ask_llm(prompt, temperature)
        letter = pick_letter(content, reasoning)
        if letter and letter in mapping:
            votes.append(mapping[letter])
    if not votes:
        return None, []
    counts: dict[str, int] = {}
    for v in votes:
        counts[v] = counts.get(v, 0) + 1
    best = max(counts.items(), key=lambda kv: kv[1])[0]
    return best, votes


def api(token: str) -> requests.Session:
    """建一个带 token 的会话。"""
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    return s


def register_solo(s: requests.Session, competition_id: str) -> int:
    """加入一个 suite（``POST /competitions/{id}/teams {"mode":"solo"}``）。"""
    r = s.post(f"{PLATFORM}/api/v1/competitions/{competition_id}/teams", json={"mode": "solo"}, timeout=60)
    return r.status_code


def load_done(path: Path) -> set[str]:
    """读已有结果，返回"不必再碰"的题目集合（已解或已锁）。"""
    done: set[str] = set()
    if not path.exists():
        return done
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("correct") or rec.get("locked"):
            done.add(rec["challenge"])
    return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="QA 题库通道（默认只算不交）")
    ap.add_argument("--token", default=os.environ.get("CTF_PLATFORM_TOKEN", ""))
    ap.add_argument("--suite", default="MMLU-CS", choices=sorted(SUITES))
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--k", type=int, default=3, help="每题采样次数")
    ap.add_argument("--temperature", type=float, default=0.7)
    ap.add_argument("--min-agree", type=int, default=3, help="至少几张同票才提交")
    ap.add_argument("--submit", action="store_true", help="真的提交（默认只算）")
    ap.add_argument("--register", action="store_true", help="先加入该 suite")
    ap.add_argument("--out", default="~/qa-results.jsonl")
    ap.add_argument("--list", action="store_true", help="只列各 suite 规模")
    args = ap.parse_args(argv)

    if not args.token:
        raise SystemExit("需要 --token 或 CTF_PLATFORM_TOKEN")
    s = api(args.token)
    comp = SUITES[args.suite]

    if args.list:
        for name, cid in SUITES.items():
            r = s.get(f"{PLATFORM}/api/v1/qa/challenges", params={"competition_id": cid}, timeout=60)
            print(f"{name:8} {cid[:8]} -> {r.status_code} {len(r.json()) if r.ok else 0} 题")
        return 0

    if args.register:
        code = register_solo(s, comp)
        print(f"[register] {args.suite} -> HTTP {code}")

    r = s.get(f"{PLATFORM}/api/v1/qa/challenges", params={"competition_id": comp}, timeout=60)
    r.raise_for_status()
    items = r.json()
    out = Path(args.out).expanduser()
    done = load_done(out)
    todo = [c for c in items if c["id"] not in done]
    print(f"[qa] {args.suite}: {len(items)} 题，待做 {len(todo)}，已有结果 {len(done)}")

    for c in todo[: args.limit]:
        stem, opts = parse_options(c.get("description", ""))
        if len(opts) < 2:
            print(f"  ! {c['id']} 选项解析失败，跳过")
            continue
        choice, votes = vote(stem, opts, args.k, args.temperature, seed=hash(c["id"]) & 0xFFFF)
        agree = max((votes.count(v) for v in set(votes)), default=0)
        rec = {
            "challenge": c["id"],
            "bucket": c.get("bucket"),
            "choice": choice,
            "votes": votes,
            "agree": agree,
            "k": args.k,
            "ts": time.time(),
        }
        if not args.submit:
            print(f"  {c['id']} -> {choice}  votes={votes}")
        elif choice and agree >= args.min_agree:
            resp = s.post(
                f"{PLATFORM}/api/v1/qa/submissions",
                json={"challenge_id": c["id"], "competition_id": comp, "question_id": "answer", "answer": choice},
                timeout=60,
            )
            body = resp.json() if resp.content else {}
            rec.update(
                submitted=True,
                status=resp.status_code,
                correct=bool(body.get("correct")),
                attempts_remaining=body.get("attempts_remaining"),
                locked=resp.status_code == 429,
            )
            print(f"  {c['id']} -> {choice}  votes={votes}  "
                  f"{'✓' if rec['correct'] else '✗'} left={rec.get('attempts_remaining')}")
        else:
            rec["skipped"] = "low_agreement"
            print(f"  {c['id']} -> 弃权  votes={votes}")
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
