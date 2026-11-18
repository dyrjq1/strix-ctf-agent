#!/usr/bin/env python3
"""ctfdesk -- 人机协同赛的本地解题流水线（不接触比赛平台）.

设计前提（见 docs/52）：比赛规则要求「读题 / 开实例 / 提交 flag」必须由人完成，
智能体不得与比赛平台直接交互。因此本工具只消费人放进 inbox 的题目材料：

    <root>/inbox/<challenge_id>/
        meta.json          # 人填：name/category/target/target_kind/flag_format/files
        statement.md       # 人粘贴的题面
        files/             # 人下载的附件

流水线负责：注册题目 -> 按题型派发给一个或多个 agent -> 隔离工作区并发解题 ->
收集 RESULT.json / result.json -> 提取并排序 flag -> 生成给人看的提交单与 WP 草稿。

用法：
    python scripts/ctfdesk.py init  --root ~/ctf-desk
    python scripts/ctfdesk.py watch --root ~/ctf-desk --workers 3 --once
    python scripts/ctfdesk.py status --root ~/ctf-desk

agent 由 <root>/agents.json 定义，命令模板支持占位符：
    {python} {repo} {root} {workdir} {files_dir} {target} {target_kind}
    {category} {challenge_id} {name} {turns} {budget} {soft_deadline}
    {result_out} {statement} {prompt}
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TZ = timezone(timedelta(hours=8))
REPO = Path(__file__).resolve().parents[1]

DEFAULT_TURNS = 25
DEFAULT_BUDGET = 900
DEFAULT_AGENTS = ["strix"]

PROMPT = """你在一场 CTF 比赛中独立解一道题。只允许使用本工作区里的材料，不要访问任何比赛平台或提交接口。

题号：{challenge_id}
题名：{name}
题型：{category}
目标：{target}
附件目录：{files_dir}

题目原文：
---
{statement}
---

要求：
1. 在 ./ 下工作，把过程写进 ./transcript.md（关键命令、输出、推理）。
2. 找到 flag 后写 ./RESULT.json：
   {{"flag": "...", "confidence": 0.0, "notes": "怎么得到的"}}
   confidence 用 0-1 表示你对 flag 正确的把握。
3. 找不到就写 {{"flag": null, "confidence": 0.0, "notes": "卡在哪里"}}，不要编造。
"""


# ---------------------------------------------------------------- utilities

def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    name TEXT, category TEXT, target TEXT, target_kind TEXT,
    flag_format TEXT, notes TEXT, agents TEXT,
    inbox_dir TEXT, status TEXT DEFAULT 'pending',
    created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    challenge_id TEXT, agent TEXT, status TEXT,
    started_at TEXT, finished_at TEXT,
    exit_code INTEGER, result_path TEXT, log_path TEXT
);
CREATE TABLE IF NOT EXISTS flags (
    challenge_id TEXT, flag TEXT, confidence REAL, agent TEXT,
    run_id TEXT, created_at TEXT
);
"""


def connect(root: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(root / "state.db", check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def load_agents(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "agents.json"
    if path.exists():
        return read_json(path)
    write_json(path, DEFAULT_AGENTS_SPEC)
    return DEFAULT_AGENTS_SPEC


DEFAULT_AGENTS_SPEC: dict[str, dict[str, Any]] = {
    "strix": {
        "cmd": [
            "{python}", "{repo}/scripts/run_strix_ctf.py",
            "--target", "{target}",
            "--target-kind", "{target_kind}",
            "--files-dir", "{files_dir}",
            "--turns", "{turns}",
            "--result-out", "{result_out}",
            "--soft-deadline", "{soft_deadline}",
            "--wall-deadline", "{budget}",
            "--name", "{challenge_id}-strix",
        ],
        "result": "{result_out}",
        "env": {
            "PYTHONPATH": "{repo}/src{pathsep}{repo}/vendor/src",
            "STRIX_RUNTIME_BACKEND": "local",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
            "STRIX_TELEMETRY": "false",
        },
    },
    "codex": {
        "cmd": ["codex", "exec", "--cd", "{workdir}", "--skip-git-repo-check", "{prompt}"],
        "result": "{workdir}/RESULT.json",
    },
    "claude": {
        "cmd": [
            "claude", "-p", "--permission-mode", "acceptEdits",
            "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep",
            "{prompt}",
        ],
        "result": "{workdir}/RESULT.json",
    },
}


# ---------------------------------------------------------------- inbox

REQUIRED = ("id", "name", "category")


def scan_inbox(conn: sqlite3.Connection, root: Path) -> list[str]:
    """把 inbox 里新出现的题目登记进 state.db，返回本次新登记 id。"""
    added: list[str] = []
    inbox = root / "inbox"
    if not inbox.is_dir():
        return added
    for meta_path in sorted(inbox.glob("*/meta.json")):
        try:
            meta = read_json(meta_path)
        except (OSError, json.JSONDecodeError):
            continue
        if not all(meta.get(k) for k in REQUIRED):
            continue
        cid = str(meta["id"])
        row = conn.execute("SELECT id,status FROM challenges WHERE id = ?", (cid,)).fetchone()
        if row:
            if row["status"] == "pending":  # 人可能补填 target / agents
                conn.execute(
                    "UPDATE challenges SET name=?,category=?,target=?,target_kind=?,"
                    "flag_format=?,notes=?,agents=?,updated_at=? WHERE id=?",
                    (meta.get("name", ""), meta.get("category", ""),
                     meta.get("target", ""), meta.get("target_kind", "file"),
                     meta.get("flag_format", ""), meta.get("notes", ""),
                     json.dumps(meta.get("agents") or DEFAULT_AGENTS),
                     now_iso(), cid),
                )
                conn.commit()
            continue
        conn.execute(
            "INSERT INTO challenges (id,name,category,target,target_kind,flag_format,"
            "notes,agents,inbox_dir,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)",
            (
                cid, meta.get("name", ""), meta.get("category", ""),
                meta.get("target", ""), meta.get("target_kind", "file"),
                meta.get("flag_format", ""), meta.get("notes", ""),
                json.dumps(meta.get("agents") or DEFAULT_AGENTS),
                str(meta_path.parent), now_iso(), now_iso(),
            ),
        )
        conn.commit()
        added.append(cid)
    return added


def agents_for(row: sqlite3.Row, available: dict[str, dict[str, Any]]) -> list[str]:
    try:
        wanted = json.loads(row["agents"] or "[]")
    except json.JSONDecodeError:
        wanted = []
    return [a for a in wanted if a in available]


# ---------------------------------------------------------------- flags

GENERIC_FLAG = re.compile(r"(?i)\b(?:flag|ctf|thuctf|tpctf)\{[^}\r\n]{1,200}\}")
BRACED = re.compile(r"\b[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")


def find_flags(text: str, flag_format: str = "") -> list[str]:
    if not text:
        return []
    pattern = re.compile(flag_format) if flag_format else GENERIC_FLAG
    hits = [m.group(0) for m in pattern.finditer(text)]
    if not hits and not flag_format:
        hits = [m.group(0) for m in BRACED.finditer(text)]
    seen: list[str] = []
    for h in hits:
        h = h.strip()
        if h and h not in seen:
            seen.append(h)
    return seen


def extract_result(result_path: Path, stdout: str) -> tuple[list[str], float, str]:
    """从 agent 的 RESULT.json / strix result.json 里取全部 flag（多 flag 题）。"""
    flags: list[str] = []
    confidence, notes = 0.0, ""
    if result_path.exists():
        try:
            data = read_json(result_path)
        except (OSError, json.JSONDecodeError):
            data = {}
        if isinstance(data, dict):
            raw = data.get("flag")
            if isinstance(raw, str) and raw.strip():
                flags.append(raw.strip())
            if isinstance(data.get("answers"), dict):
                for value in data["answers"].values():
                    if isinstance(value, str) and value.strip():
                        flags.append(value.strip())
                if flags:
                    confidence = max(confidence, 0.8)
            try:
                confidence = float(data.get("confidence", confidence))
            except (TypeError, ValueError):
                pass
            notes = str(data.get("notes") or data.get("writeup") or "")
    if not flags:
        hits = find_flags(stdout)
        if hits:
            flags, confidence = hits, max(confidence, 0.5)
    seen: list[str] = []
    for f in flags:
        if f not in seen:
            seen.append(f)
    return seen, max(0.0, min(1.0, confidence)), notes


# ---------------------------------------------------------------- run

class Runner:
    def __init__(self, root: Path, conn: sqlite3.Connection,
                 agents: dict[str, dict[str, Any]], budget: int,
                 turns: int, verbose: bool = True):
        self.root = root
        self.conn = conn
        self.agents = agents
        self.budget = budget
        self.turns = turns
        self.verbose = verbose
        self._lock = threading.Lock()

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def _values(self, row: sqlite3.Row, agent: str, workdir: Path,
                result_out: Path, files_dir: Path, statement: str) -> dict[str, str]:
        return {
            "python": sys.executable,
            "repo": str(REPO),
            "root": str(self.root),
            "workdir": str(workdir),
            "files_dir": str(files_dir),
            "target": row["target"] or "",
            "target_kind": row["target_kind"] or "file",
            "category": row["category"] or "",
            "challenge_id": row["id"],
            "name": row["name"] or row["id"],
            "turns": str(self.turns),
            "budget": str(self.budget),
            "soft_deadline": str(int(self.budget * 0.8)),
            "result_out": str(result_out),
            "statement": statement,
            "prompt": PROMPT.format(
                challenge_id=row["id"], name=row["name"] or row["id"],
                category=row["category"] or "unknown", target=row["target"] or "(无)",
                files_dir=str(files_dir), statement=statement,
            ),
            "pathsep": os.pathsep,
            "agent": agent,
        }

    def run_one(self, row: sqlite3.Row, agent: str) -> dict[str, Any]:
        cid = row["id"]
        spec = self.agents[agent]
        inbox = Path(row["inbox_dir"])
        files_dir = inbox / "files"
        statement_path = inbox / "statement.md"
        statement = statement_path.read_text(encoding="utf-8", errors="replace") \
            if statement_path.exists() else ""
        workdir = self.root / "work" / cid / agent
        workdir.mkdir(parents=True, exist_ok=True)
        result_out = workdir / "RESULT.json"
        run_id = f"{cid}-{agent}-{datetime.now(TZ).strftime('%H%M%S')}"

        vals = self._values(row, agent, workdir, result_out, files_dir, statement)
        try:
            cmd = [str(part).format(**vals) for part in spec["cmd"]]
        except KeyError as exc:
            return {"run_id": run_id, "status": "config_error", "error": str(exc)}
        env = os.environ.copy()
        for k, v in (spec.get("env") or {}).items():
            env[str(k)] = str(v).format(**vals)

        started = now_iso()
        with self._lock:
            self.conn.execute(
                "INSERT INTO runs (run_id,challenge_id,agent,status,started_at,result_path) "
                "VALUES (?,?,?,?,?,?)",
                (run_id, cid, agent, "running", started, str(result_out)),
            )
            self.conn.execute(
                "UPDATE challenges SET status='running', updated_at=? WHERE id=?",
                (started, cid),
            )
            self.conn.commit()
        self.log(f"[ctfdesk] start {cid} agent={agent}")

        status, code, out = "error", None, ""
        try:
            proc = subprocess.run(
                cmd, cwd=str(workdir), env=env, capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=self.budget + 180,
            )
            code, out = proc.returncode, (proc.stdout or "") + "\n" + (proc.stderr or "")
            status = "ok" if code == 0 else "error"
        except subprocess.TimeoutExpired as exc:
            status = "timeout"
            out = (exc.stdout or "") + "\n" + (exc.stderr or "") if isinstance(exc.stdout, str) else ""
        except OSError as exc:
            status, out = "error", str(exc)

        result_path = Path(str(spec.get("result") or result_out).format(**vals))
        if not result_path.exists() and result_out.exists():
            result_path = result_out
        flags, confidence, notes = extract_result(result_path, out)

        log_dir = self.root / "outbox" / "evidence" / cid / agent
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "stdout.log").write_text(out, encoding="utf-8", errors="replace")
        if result_path.exists():
            shutil.copy2(result_path, log_dir / result_path.name)
        transcript = workdir / "transcript.md"
        if transcript.exists():
            shutil.copy2(transcript, log_dir / "transcript.md")

        finished = now_iso()
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET status=?,finished_at=?,exit_code=?,log_path=? WHERE run_id=?",
                (status, finished, code, str(log_dir), run_id),
            )
            for flag in flags:
                self.conn.execute(
                    "INSERT INTO flags (challenge_id,flag,confidence,agent,run_id,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (cid, flag, confidence, agent, run_id, finished),
                )
            if flags and confidence >= 0.9:
                self.conn.execute(
                    "UPDATE challenges SET status='done', updated_at=? WHERE id=?",
                    (finished, cid),
                )
            self.conn.commit()

        if flags:
            outbox = self.root / "outbox"
            outbox.mkdir(parents=True, exist_ok=True)
            with (outbox / "flags.jsonl").open("a", encoding="utf-8") as fh:
                for flag in flags:
                    fh.write(json.dumps({"id": cid, "flag": flag, "confidence": confidence,
                                         "agent": agent, "run_id": run_id,
                                         "at": finished}, ensure_ascii=False) + "\n")
        self.write_outbox(cid, notes)
        self.log(f"[ctfdesk] done  {cid} agent={agent} status={status} "
                 f"flags={len(flags)} conf={confidence:.2f}")
        return {"run_id": run_id, "status": status, "flags": flags,
                "confidence": confidence, "notes": notes}

    def write_outbox(self, cid: str, notes: str = "") -> None:
        outbox = self.root / "outbox"
        rows = self.conn.execute(
            "SELECT flag,confidence,agent,run_id,created_at FROM flags "
            "WHERE challenge_id=? ORDER BY confidence DESC, created_at ASC", (cid,)
        ).fetchall()
        if rows:
            wp = outbox / "wp" / f"{cid}.md"
            if not wp.exists():
                atomic_write(wp, wp_skeleton(self.conn, cid, rows[0], notes))
        self.regenerate_sheet()

    def regenerate_sheet(self) -> None:
        rows = self.conn.execute(
            "SELECT c.id, c.name, c.status, f.flag, f.confidence, f.agent, f.created_at "
            "FROM challenges c LEFT JOIN flags f ON f.rowid = ("
            "  SELECT rowid FROM flags WHERE challenge_id=c.id "
            "  ORDER BY confidence DESC, created_at ASC LIMIT 1) "
            "ORDER BY c.created_at ASC"
        ).fetchall()
        lines = ["# 提交单", "", "| 题号 | 题名 | Flag | 置信度 | 来源 | 状态 |", "|---|---|---|---|---|---|"]
        for r in rows:
            if not r["flag"]:
                lines.append(f"| {r['id']} | {r['name']} | — | — | — | {r['status']} |")
                continue
            mark = "可直接提交" if r["confidence"] >= 0.9 else \
                   ("建议核对" if r["confidence"] >= 0.6 else "低置信")
            lines.append(f"| {r['id']} | {r['name']} | `{r['flag']}` | "
                         f"{r['confidence']:.2f} | {r['agent']} | {mark} |")
        lines += ["", "> 平台提交仍由人完成（规则要求）。提交后把结果记回 state.db 或在表中标注。", ""]
        atomic_write(self.root / "outbox" / "submit-sheet.md", "\n".join(lines))


def wp_skeleton(conn: sqlite3.Connection, cid: str, flag_row: sqlite3.Row,
                notes: str) -> str:
    ch = conn.execute("SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
    runs = conn.execute(
        "SELECT agent,status,started_at,finished_at,log_path FROM runs WHERE challenge_id=? "
        "ORDER BY started_at", (cid,)
    ).fetchall()
    lines = [
        f"# {cid} · {ch['name']}", "",
        f"- 题型：{ch['category']}",
        f"- 目标：{ch['target'] or '（无，附件题）'}",
        f"- Flag：`{flag_row['flag']}`（来源 {flag_row['agent']}，置信度 {flag_row['confidence']:.2f}）",
        "", "## 关键分析", "", notes or "（待补）", "",
        "## 复现步骤", "", "（按 evidence 里的 transcript / stdout 整理）", "",
        "## AI 使用说明", "",
        "> 规则要求写明 AI 的作用与人工验证过程。",
        "", "- 使用的 agent / 模型：",
        "- 人工验证了什么：",
        "", "## 运行记录", "",
    ]
    for r in runs:
        lines.append(f"- {r['agent']} · {r['status']} · {r['started_at']} → {r['finished_at']} · 证据 `{r['log_path']}`")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- commands

def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser()
    for sub in ("inbox", "work", "outbox/wp", "outbox/evidence"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    connect(root).close()
    load_agents(root)
    print(f"initialized {root}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser()
    root.mkdir(parents=True, exist_ok=True)
    conn = connect(root)
    agents = load_agents(root)
    runner = Runner(root, conn, agents, args.budget, args.turns)
    rounds = 0
    while True:
        rounds += 1
        added = scan_inbox(conn, root)
        for cid in added:
            print(f"[ctfdesk] registered {cid}")
        pending = conn.execute(
            "SELECT * FROM challenges WHERE status IN ('pending','running') "
            "ORDER BY created_at"
        ).fetchall()
        jobs: list[tuple[sqlite3.Row, str]] = []
        for row in pending:
            if row["status"] == "running":
                continue
            for agent in agents_for(row, agents):
                jobs.append((row, agent))
        if not jobs:
            if args.once or args.interval <= 0:
                break
            time.sleep(args.interval)
            continue
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futs = [pool.submit(runner.run_one, row, agent) for row, agent in jobs]
            for fut in as_completed(futs):
                fut.result()
        runner.regenerate_sheet()
        if args.once:
            break
        if args.interval <= 0:
            break
        time.sleep(args.interval)
    conn.close()
    print(f"watch finished after {rounds} round(s)")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser()
    conn = connect(root)
    rows = conn.execute(
        "SELECT c.id,c.name,c.category,c.status,"
        " (SELECT COUNT(*) FROM runs r WHERE r.challenge_id=c.id) AS runs,"
        " (SELECT MAX(confidence) FROM flags f WHERE f.challenge_id=c.id) AS conf"
        " FROM challenges c ORDER BY c.created_at"
    ).fetchall()
    if not rows:
        print("(empty)")
        return 0
    print(f"{'ID':<14}{'CAT':<10}{'STATUS':<10}{'RUNS':<6}{'CONF':<6}NAME")
    for r in rows:
        conf = f"{r['conf']:.2f}" if r["conf"] is not None else "-"
        print(f"{r['id']:<14}{r['category']:<10}{r['status']:<10}{r['runs']:<6}{conf:<6}{r['name']}")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser()
    cid = args.id
    dest = root / "inbox" / cid
    (dest / "files").mkdir(parents=True, exist_ok=True)
    meta = {
        "id": cid, "name": args.name or cid, "category": args.category,
        "target": args.target or "", "target_kind": args.target_kind,
        "flag_format": args.flag_format or "", "notes": args.notes or "",
        "agents": args.agents.split(",") if args.agents else DEFAULT_AGENTS,
    }
    write_json(dest / "meta.json", meta)
    statement = dest / "statement.md"
    if not statement.exists():
        statement.write_text("", encoding="utf-8")
    if args.files:
        src = Path(args.files)
        for item in src.iterdir():
            target = dest / "files" / item.name
            if item.is_dir():
                shutil.copytree(item, target, dirs_exist_ok=True)
            else:
                shutil.copy2(item, target)
    print(f"added {cid} -> {dest}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="local CTF solving desk (platform-free)")
    sub = p.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="create root layout and default agents.json")
    init.add_argument("--root", default="~/ctf-desk")
    init.set_defaults(func=cmd_init)

    watch = sub.add_parser("watch", help="scan inbox and dispatch agents")
    watch.add_argument("--root", default="~/ctf-desk")
    watch.add_argument("--workers", type=int, default=3)
    watch.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    watch.add_argument("--turns", type=int, default=DEFAULT_TURNS)
    watch.add_argument("--interval", type=float, default=30.0,
                       help="idle seconds between scans; 0 exits after one round")
    watch.add_argument("--once", action="store_true")
    watch.set_defaults(func=cmd_watch)

    status = sub.add_parser("status", help="show challenge table")
    status.add_argument("--root", default="~/ctf-desk")
    status.set_defaults(func=cmd_status)

    add = sub.add_parser("add", help="register one challenge by hand")
    add.add_argument("--root", default="~/ctf-desk")
    add.add_argument("--id", required=True)
    add.add_argument("--name", default="")
    add.add_argument("--category", default="misc")
    add.add_argument("--target", default="")
    add.add_argument("--target-kind", default="file", choices=("file", "web", "tcp"))
    add.add_argument("--flag-format", default="")
    add.add_argument("--notes", default="")
    add.add_argument("--agents", default="")
    add.add_argument("--files", default="")
    add.set_defaults(func=cmd_add)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())