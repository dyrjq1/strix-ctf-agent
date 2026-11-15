"""Verify no real flag survives in solve_notes.jsonl, then render a markdown catalog.

1. Collect every flag-shaped string found in the result rows / autosubmit verdicts.
2. Assert none of them appears in the notes file.
3. Write /home/rjq/solve-catalog.md, grouped by challenge.
"""
import collections
import glob
import json
import os
import re

FLAG_RE = re.compile(r"[A-Za-z0-9_.-]{2,40}\{[^{}\s]{4,}\}")
HOST_RE = re.compile(r"https?://[A-Za-z0-9.-]*(?:ctfy\.run|node\d+\.ctfy\.run)[A-Za-z0-9/._-]*")


def scrub(text):
    """Replace live-target URLs: they die with the instance and do not belong in a doc."""
    return HOST_RE.sub("<TARGET>", FLAG_RE.sub("<FLAG>", text or ""))

# ---- 1. harvest every flag string we have ever captured ------------------
known = set()
rows = []
for path in glob.glob("/home/rjq/*.jsonl"):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                rows.append(row)
                for key in ("flag", "answer", "autosubmit_verdict", "verdict"):
                    val = row.get(key)
                    if isinstance(val, str):
                        known.update(FLAG_RE.findall(val))
    except OSError:
        pass

notes_text = open("/home/rjq/solve_notes.jsonl", encoding="utf-8").read()
catalog_text = open("/home/rjq/solve_catalog.jsonl", encoding="utf-8").read()

leaks = sorted(f for f in known if f in notes_text or f in catalog_text)
leftover = sorted(set(FLAG_RE.findall(notes_text)) - {"<FLAG>"})
print("known flag strings harvested:", len(known))
print("leaks into notes/catalog   :", len(leaks))
for f in leaks[:5]:
    print("   LEAK:", f[:40] + "...")
print("unredacted flag-shaped text:", len(leftover))
for f in leftover[:5]:
    print("   RESIDUE:", f[:60])
if leaks or leftover:
    raise SystemExit("refusing to render: flag text still present")

# ---- 2. render ----------------------------------------------------------
recs = [json.loads(l) for l in open("/home/rjq/solve_notes.jsonl", encoding="utf-8")]
by_ch = collections.defaultdict(list)
for rec in recs:
    by_ch[rec["challenge"]].append(rec)

lines = [
    "# 解出题解法台账（从 agents.db item 流离线重建，零 token）",
    "",
    f"生成于 2026-11-15。来源：VM `/home/rjq/runs/*/strix_runs/*/.state/agents.db`，"
    f"共 {len(recs)} 条解出 run、{len(by_ch)} 道不同题。"
    "解法取自每次解题收尾 `finish_scan` 的 `executive_summary` / `methodology`（agent 自述），"
    "flag 一律替换为 `<FLAG>`。",
    "",
    "## 摘要分布",
    "",
]
tech = collections.Counter()
for rec in recs:
    blob = (rec["summary"] + " " + rec["methodology"]).lower()
    for name, words in {
        "命令注入/RCE": ["command injection", "rce", "os command"],
        "鉴权绕过": ["auth bypass", "missing authentication", "no authentication"],
        "IDOR/越权": ["idor", "broken access control"],
        "SSRF": ["ssrf"],
        "文件上传/插件": ["upload", "plugin"],
        "SQL 注入": ["sqli", "sql injection"],
        "信息泄漏": ["disclosure", "leak", "debug"],
        "业务逻辑": ["business logic", "sku", "approval"],
        "JWT": ["jwt"],
        "路径遍历": ["traversal"],
        "XXE": ["xxe"],
        "逆向/解压": ["reverse-engineering", "decompress", "reversed"],
        "弱加密": ["weak crypto", "predictable"],
    }.items():
        if any(w in blob for w in words):
            tech[name] += 1
lines += [f"- {name}：{n} 次" for name, n in tech.most_common()]
lines += ["", "## 逐题", ""]

for ch in sorted(by_ch):
    lines.append(f"### {ch}")
    for rec in sorted(by_ch[ch], key=lambda r: -(r["wall_s"] or 0)):
        head = f"- run `{rec['run_id']}`：墙钟 {rec['wall_s']}s / {rec['n_calls']} 次调用"
        lines.append(head)
        summary = scrub(rec["summary"]).replace("\n", " ").strip()
        summary = re.sub(r"ANSWER\[flag\]=<FLAG>\s*", "", summary)
        if summary:
            lines.append(f"  - 结论：{summary[:400]}")
        meth = scrub(rec["methodology"]).replace("\n", " ").strip()
        if meth:
            lines.append(f"  - 方法：{meth[:300]}")
        lines.append(f"  - 工具链：{' > '.join(rec['tools'])}")
    lines.append("")

out = "/home/rjq/solve-catalog.md"
tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(lines))
os.replace(tmp, out)
print("\nwrote", out, os.path.getsize(out), "bytes,", len(lines), "lines")
left_hosts = re.findall(r"[A-Za-z0-9.-]*ctfy\.run", open(out, encoding="utf-8").read())
print("remaining target hostnames:", len(left_hosts))