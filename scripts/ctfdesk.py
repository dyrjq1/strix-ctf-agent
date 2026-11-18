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
import signal
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

# 并发闸门：每个 agent 进程按 ~700 MB 估，低于保留下限就不再开新的一路。
MIN_FREE_MB = 1500
PER_WORKER_MB = 700


def free_mem_mb() -> int | None:
    """当前可用物理内存（MB）。拿不到时返回 None，交由调用方按原并发放行。"""
    if sys.platform == "win32":
        import ctypes

        class _MemStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = _MemStatus()
        st.dwLength = ctypes.sizeof(_MemStatus)
        try:
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return None
        except (AttributeError, OSError):
            return None
        return int(st.ullAvailPhys // (1024 * 1024))
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError):
        pass
    return None


def plan_workers(requested: int, free_mb: int | None,
                 min_free_mb: int = MIN_FREE_MB,
                 per_worker_mb: int = PER_WORKER_MB) -> int:
    """按可用内存收窄并发：保住 min_free_mb，其余每 per_worker_mb 放一路。"""
    requested = max(1, requested)
    if free_mb is None:
        return requested
    if free_mb < min_free_mb:
        return 1
    return max(1, min(requested, (free_mb - min_free_mb) // max(1, per_worker_mb)))

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
4. 写 ./VERIFY.md，让人（不需要安全背景）能验证这个 flag 确实来自本题：
   - `## 复现命令`：一条可直接执行的命令（附件题给本地命令；靶机题给最小 curl/脚本）
   - `## 期望输出`：执行后应看到的关键片段（含 flag 或可判定字符串）
   - `## 来源核对`：怎么确认这是本题/本实例的 flag，而不是别处的
   - `## 人工核对要点`：人只需要看哪一行、比对什么
"""


# ---------------------------------------------------------------- utilities

def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def read_json(path: Path) -> Any:
    # utf-8-sig：agent 在 Windows 上写出的 JSON 常带 BOM（codex 实测），
    # 用 utf-8 读会 JSONDecodeError，风控退化成 stdout 正则、置信度丢失。
    return json.loads(path.read_text(encoding="utf-8-sig"))


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


def CLAUDE_SETTINGS(base_url: str, token_ref: str, model: str,
                    fast_model: str | None = None) -> dict[str, str]:
    """claude CLI 的 --settings env 块。token_ref 保持 @secret: 引用，运行时解析。"""
    return {
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_AUTH_TOKEN": token_ref,
        "ANTHROPIC_API_KEY": token_ref,
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": fast_model or model,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_AUTO_MODE_SERVER": "0",
    }


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
        # `codex exec -` 从 stdin 读 prompt（实测可用），避免 .cmd 壳吞多行。
        # CODEX_HOME 指向 desk 自己的配置：全局那份挂着 ctfy 平台 MCP，不能用。
        "cmd": ["codex", "exec", "--cd", "{workdir}", "--skip-git-repo-check", "-"],
        "stdin": "{prompt}",
        "env": {"CODEX_HOME": "{root}/codex-home",
                "OPENAI_API_KEY": "@secret:QWEN_KEY"},
        "result": "{workdir}/RESULT.json",
    },
    # 三条 claude 车道，各自钉死一个网关。
    # 必须用 --settings：claude CLI 会用 ~/.claude/settings.json 的 env 覆盖
    # 进程环境变量（实测把 ANTHROPIC_BASE_URL 指向死端口仍能正常应答），
    # 只靠 adapter.env 会静默走到用户全局配置的那个网关上去。
    # prompt 走 stdin（适配器 "stdin" 键）：长文本经 npm 的 .cmd 壳会被拆坏。
    "claude": {
        "cmd": [
            "claude", "--settings", "{settings}", "-p",
            # 空 MCP 配置 + strict：不继承用户全局 MCP（ctfy 平台工具绝不能进
            # agent 的工具面——人机协同赛道禁止 agent 接触平台）。
            "--strict-mcp-config", "--mcp-config", '{{"mcpServers":{{}}}}',
            "--permission-mode", "acceptEdits",
            "--model", "deepseek-v4.1-flash",
            "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep",
            "-",
        ],
        "stdin": "{prompt}",
        "settings": CLAUDE_SETTINGS(
            "https://maas.qianwenaiapi.com/apps/anthropic",
            "@secret:QWEN_KEY", "deepseek-v4.1-flash", "deepseek-v4.1-flash"),
        "result": "{workdir}/RESULT.json",
    },
    # 异构第二模型：智谱 GLM 的 Anthropic 兼容口。
    # 密钥放 <root>/secrets.json 的 ZHIPU_KEY，agents.json 里只写 @secret: 引用。
    "claude-glm": {
        "cmd": [
            "claude", "--settings", "{settings}", "-p",
            # 空 MCP 配置 + strict：不继承用户全局 MCP（ctfy 平台工具绝不能进
            # agent 的工具面——人机协同赛道禁止 agent 接触平台）。
            "--strict-mcp-config", "--mcp-config", '{{"mcpServers":{{}}}}',
            "--permission-mode", "acceptEdits",
            "--model", "glm-5",
            "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep",
            "-",
        ],
        "stdin": "{prompt}",
        "settings": CLAUDE_SETTINGS(
            "https://open.bigmodel.cn/api/anthropic",
            "@secret:ZHIPU_KEY", "glm-5", "glm-5"),
        "result": "{workdir}/RESULT.json",
    },
    # 异构第三模型：小米 MiMo 的 Anthropic 兼容口（OpenAI 口也通）。
    "claude-mimo": {
        "cmd": [
            "claude", "--settings", "{settings}", "-p",
            # 空 MCP 配置 + strict：不继承用户全局 MCP（ctfy 平台工具绝不能进
            # agent 的工具面——人机协同赛道禁止 agent 接触平台）。
            "--strict-mcp-config", "--mcp-config", '{{"mcpServers":{{}}}}',
            "--permission-mode", "acceptEdits",
            "--model", "mimo-v2.6-pro",
            "--allowedTools", "Bash,Read,Write,Edit,Glob,Grep",
            "-",
        ],
        "stdin": "{prompt}",
        "settings": CLAUDE_SETTINGS(
            "https://api.xiaomimimo.com/anthropic",
            "@secret:XIAOMI_KEY", "mimo-v2.6-pro", "mimo-v2.6-flash"),
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

def load_secrets(root: Path) -> dict[str, str]:
    """<root>/secrets.json 里的密钥。文件在仓库外，不进 git。"""
    path = root / "secrets.json"
    if not path.exists():
        return {}
    try:
        data = read_json(path)
    except (OSError, json.JSONDecodeError):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, (str, int))}


def resolve_secret(value: str, secrets: dict[str, str]) -> str:
    """`@secret:NAME` 从 secrets.json 取值，`@env:NAME` 从环境变量取，其余原样。"""
    if value.startswith("@secret:"):
        return secrets.get(value.split(":", 1)[1], "")
    if value.startswith("@env:"):
        return os.environ.get(value.split(":", 1)[1], "")
    return value


def kill_tree(proc: "subprocess.Popen[str]") -> None:
    """超时后连同子进程一起杀。npm 的 .cmd 壳会留下 node 孙进程攥住管道。"""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            proc.kill()


def write_settings_file(path: Path, env: dict[str, Any],
                        secrets: dict[str, str]) -> Path:
    """把适配器的 settings 块落成 claude CLI 的 --settings 文件。

    为什么要文件而不是环境变量：claude CLI 启动时会用 ~/.claude/settings.json
    的 env 覆盖进程环境变量（实测把 ANTHROPIC_BASE_URL 指向死端口仍能正常应答），
    只有 --settings 的优先级够高。文件放 <root>/runtime/，不进 workdir，
    避免明文密钥落进证据目录。写完用 os.replace，避免 Windows 截断写。
    """
    resolved = {str(k): resolve_secret(str(v), secrets) for k, v in env.items()}
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"env": resolved}, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    os.replace(tmp, path)
    return path


class Runner:
    def __init__(self, root: Path, conn: sqlite3.Connection,
                 agents: dict[str, dict[str, Any]], budget: int,
                 turns: int, verbose: bool = True):
        self.root = root
        self.conn = conn
        self.agents = agents
        self.secrets = load_secrets(root)
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
            "settings": "",
        }

    def _config_error(self, run_id: str, cid: str, agent: str,
                      msg: str) -> dict[str, Any]:
        """配置错误必须在日志里留痕：静默 config_error 会表现为「点了不动」。"""
        self.log(f"[ctfdesk] config_error {cid} agent={agent}: {msg}")
        return {"run_id": run_id, "status": "config_error", "error": msg}

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
        if spec.get("settings"):
            vals["settings"] = str(write_settings_file(
                self.root / "runtime" / f"settings-{agent}.json",
                spec["settings"], self.secrets))
        try:
            cmd = [str(part).format(**vals) for part in spec["cmd"]]
        except KeyError as exc:
            return self._config_error(run_id, cid, agent,
                                      f"unresolved placeholder {exc}")
        # npm 装的 CLI 在 Windows 是 claude.cmd / codex.cmd，CreateProcess 不认
        # 无扩展名的 "claude"（WinError 2）。PATHEXT 解析交给 shutil.which。
        resolved_exe = shutil.which(cmd[0])
        if not resolved_exe:
            return self._config_error(run_id, cid, agent,
                                      f"executable not found: {cmd[0]}")
        cmd[0] = resolved_exe
        env = os.environ.copy()
        for k, v in (spec.get("env") or {}).items():
            env[str(k)] = resolve_secret(str(v).format(**vals), self.secrets)

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
        # 长 prompt 走命令行会被 Windows 的 .cmd 壳拆坏（多行直接丢），
        # 适配器用 "stdin" 声明改用标准输入喂。
        stdin_text = str(spec["stdin"]).format(**vals) if spec.get("stdin") else None
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(workdir), env=env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                creationflags=(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
                               if os.name == "nt" else 0),
                start_new_session=(os.name != "nt"),
            )
        except OSError as exc:
            proc, status, out = None, "error", str(exc)
        if proc is not None:
            try:
                out, _ = proc.communicate(
                    stdin_text, timeout=float(spec.get("timeout") or (self.budget + 180)))
                code = proc.returncode
                status = "ok" if code == 0 else "error"
            except subprocess.TimeoutExpired:
                # .cmd 壳被杀只死 cmd.exe，node 子进程还攥着管道 → 必须杀整棵树，
                # 否则 communicate() 永远等不到 EOF（实测卡死 8 分钟以上）。
                status = "timeout"
                kill_tree(proc)
                try:
                    out, _ = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out = ""
            out = out or ""

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
        verify_doc = workdir / "VERIFY.md"
        if verify_doc.exists():
            shutil.copy2(verify_doc, log_dir / "VERIFY.md")

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
                atomic_write(wp, wp_skeleton(self.conn, self.root, cid, rows[0], notes))
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


def wp_skeleton(conn: sqlite3.Connection, root: Path, cid: str,
                flag_row: sqlite3.Row, notes: str) -> str:
    ch = conn.execute("SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
    runs = conn.execute(
        "SELECT agent,status,started_at,finished_at,log_path FROM runs WHERE challenge_id=? "
        "ORDER BY started_at", (cid,)
    ).fetchall()
    verify_path = root / "outbox" / "evidence" / cid / flag_row["agent"] / "VERIFY.md"
    verify = verify_path.read_text(encoding="utf-8", errors="replace") \
        if verify_path.exists() else "（agent 未产出 VERIFY.md，按 transcript 手工整理）"
    lines = [
        f"# {cid} · {ch['name']}", "",
        f"- 题型：{ch['category']}",
        f"- 目标：{ch['target'] or '（无，附件题）'}",
        f"- Flag：`{flag_row['flag']}`（来源 {flag_row['agent']}，置信度 {flag_row['confidence']:.2f}）",
        "", "## 关键分析", "", notes or "（待补）", "",
        "## 复现步骤", "", "（按 evidence 里的 transcript / stdout 整理）", "",
        "## 验证材料（agent 产出）", "", verify, "",
        "## AI 使用说明", "",
        "> 规则要求写明 AI 的作用与人工验证过程。按实际写，不要替人声称未做过的验证。",
        "", "- 使用的 agent / 模型：",
        "- AI 完成了哪些步骤：",
        "", "## 人工验证记录", "",
        "> 由本人执行后填写；`ctfdesk record` 会把同样的记录写进 outbox/verify/。",
        "", "- 验证时间：",
        "- 执行的命令：",
        "- 观察到的输出（须含 flag 或可判定片段）：",
        "- 来源核对（本题 / 本实例）：",
        "- 结论：",
        "", "## 运行记录", "",
    ]
    for r in runs:
        lines.append(f"- {r['agent']} · {r['status']} · {r['started_at']} → {r['finished_at']} · 证据 `{r['log_path']}`")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------- commands

CODEX_CONFIG = """# ctfdesk 专用 CODEX_HOME：故意不声明任何 mcp_servers。
# 用户全局 ~/.codex/config.toml 里挂着 ctfy 平台 MCP，绝不能带进解题进程。
model = "deepseek-v4.1-flash-1017"
model_provider = "qianwen-maas"
approval_policy = "never"
sandbox_mode = "danger-full-access"

[model_providers.qianwen-maas]
name = "Qianwen MaaS"
base_url = "https://maas.qianwenaiapi.com/compatible-mode/v1"
wire_api = "responses"
env_key = "OPENAI_API_KEY"
"""


def ensure_codex_home(root: Path) -> Path:
    """写一份不含 MCP 的 codex 配置。密钥走 OPENAI_API_KEY 环境变量，不落盘。"""
    home = root / "codex-home"
    home.mkdir(parents=True, exist_ok=True)
    cfg = home / "config.toml"
    if not cfg.exists():
        tmp = cfg.with_name(cfg.name + ".tmp")
        tmp.write_text(CODEX_CONFIG, encoding="utf-8", newline="\n")
        os.replace(tmp, cfg)
    return home


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.root).expanduser()
    for sub in ("inbox", "work", "outbox/wp", "outbox/evidence"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    connect(root).close()
    load_agents(root)
    ensure_codex_home(root)
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
        free_mb = free_mem_mb()
        workers = plan_workers(args.workers, free_mb, args.min_free_mb,
                               args.per_worker_mb)
        mem_note = "unknown" if free_mb is None else f"{free_mb} MB"
        suffix = "" if workers == args.workers else f" (requested {args.workers})"
        print(f"[ctfdesk] free mem={mem_note} -> workers={workers}{suffix}; "
              f"jobs={len(jobs)}", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as pool:
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


def cmd_record(args: argparse.Namespace) -> int:
    """人执行验证后落一条带时间戳的存证（WP 的人工验证记录由此汇总）。"""
    root = Path(args.root).expanduser()
    out = root / "outbox" / "verify" / f"{args.id}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    block = "\n".join([
        f"## {args.id} · {now_iso()}",
        f"- 执行的命令：`{args.command}`",
        f"- 观察到的输出：{args.observed}",
        f"- 来源核对：{args.source or '（未填）'}",
        f"- 结论：{args.result}",
        f"- 备注：{args.note or '（无）'}",
        "",
    ])
    with out.open("a", encoding="utf-8") as fh:
        fh.write(block)
    print(f"recorded -> {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="local CTF solving desk (platform-free)")
    sub = p.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="create root layout and default agents.json")
    init.add_argument("--root", default="~/ctf-desk")
    init.set_defaults(func=cmd_init)

    watch = sub.add_parser("watch", help="scan inbox and dispatch agents")
    watch.add_argument("--root", default="~/ctf-desk")
    watch.add_argument("--workers", type=int, default=3,
                       help="并发上限；实际值还会按可用内存收窄")
    watch.add_argument("--min-free-mb", type=int, default=MIN_FREE_MB,
                       help="保底空闲内存（MB），低于它只跑 1 路")
    watch.add_argument("--per-worker-mb", type=int, default=PER_WORKER_MB,
                       help="每个 agent 大约吃多少内存，用来换算并发")
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

    rec = sub.add_parser("record", help="log a human verification run (timestamped)")
    rec.add_argument("--root", default="~/ctf-desk")
    rec.add_argument("--id", required=True)
    rec.add_argument("--command", required=True)
    rec.add_argument("--observed", required=True)
    rec.add_argument("--source", default="")
    rec.add_argument("--result", default="pass", choices=("pass", "fail", "partial"))
    rec.add_argument("--note", default="")
    rec.set_defaults(func=cmd_record)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())