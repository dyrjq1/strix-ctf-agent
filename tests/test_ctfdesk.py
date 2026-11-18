"""ctfdesk 端到端测试：用假 agent 验证 inbox -> 派发 -> 提交单链路，不联网。"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ctfdesk.py"


def _module():
    spec = importlib.util.spec_from_file_location("ctfdesk_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

FAKE_AGENT = '''
import json
import sys
from pathlib import Path

work = Path(sys.argv[1])
(work / "transcript.md").write_text("fake solver ran\\n", encoding="utf-8")
(work / "VERIFY.md").write_text(
    "## 复现命令\\n`cat files/a.txt`\\n## 期望输出\\nflag{test_123}\\n",
    encoding="utf-8",
)
(work / "RESULT.json").write_text(
    json.dumps({"flag": "flag{test_123}", "confidence": 0.95, "notes": "fake"}),
    encoding="utf-8",
)
'''


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def test_pipeline_end_to_end(tmp_path: Path) -> None:
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "fake_agent.py"
    fake.write_text(FAKE_AGENT, encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {"cmd": [sys.executable, str(fake), "{workdir}"],
                             "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )

    ch = root / "inbox" / "CH1"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH1", "name": "demo", "category": "misc",
                    "agents": ["fake"], "target_kind": "file"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("find the flag", encoding="utf-8")

    proc = _run("watch", "--root", str(root), "--once", "--workers", "1")
    assert proc.returncode == 0, proc.stderr
    assert "free mem=" in proc.stdout  # 内存闸门在派发时留痕

    flags = (root / "outbox" / "flags.jsonl").read_text(encoding="utf-8")
    assert "flag{test_123}" in flags
    sheet = (root / "outbox" / "submit-sheet.md").read_text(encoding="utf-8")
    assert "CH1" in sheet
    assert "flag{test_123}" in sheet
    assert (root / "outbox" / "wp" / "CH1.md").exists()
    assert (root / "outbox" / "evidence" / "CH1" / "fake" / "RESULT.json").exists()
    assert (root / "outbox" / "evidence" / "CH1" / "fake" / "VERIFY.md").exists()
    wp = (root / "outbox" / "wp" / "CH1.md").read_text(encoding="utf-8")
    assert "人工验证记录" in wp
    assert "复现命令" in wp  # agent 产出的验证材料已并入 WP

    rec = _run("record", "--root", str(root), "--id", "CH1",
               "--command", "cat files/a.txt", "--observed", "flag{test_123}",
               "--source", "本队实例", "--result", "pass")
    assert rec.returncode == 0, rec.stderr
    verify_log = (root / "outbox" / "verify" / "CH1.md").read_text(encoding="utf-8")
    assert "cat files/a.txt" in verify_log and "pass" in verify_log


def test_resolve_secret_forms() -> None:
    mod = _module()
    secrets = {"K": "v1"}
    assert mod.resolve_secret("@secret:K", secrets) == "v1"
    assert mod.resolve_secret("@secret:MISSING", secrets) == ""
    assert mod.resolve_secret("plain", secrets) == "plain"
    os.environ["CTFDESK_TEST_ENV"] = "e1"
    assert mod.resolve_secret("@env:CTFDESK_TEST_ENV", secrets) == "e1"


SECRET_AGENT = '''
import json, os, sys
from pathlib import Path
work = Path(sys.argv[1])
(work / "seen.txt").write_text(os.environ.get("FAKE_KEY", "MISSING"), encoding="utf-8")
(work / "RESULT.json").write_text(json.dumps({"flag": "flag{sec}", "confidence": 0.9}),
                                 encoding="utf-8")
'''


def test_secret_reaches_agent_env(tmp_path: Path) -> None:
    """secrets.json 里的密钥要通过 @secret: 注入到子进程，且不写进 agents.json。"""
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "sec_agent.py"
    fake.write_text(SECRET_AGENT, encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {"cmd": [sys.executable, str(fake), "{workdir}"],
                             "env": {"FAKE_KEY": "@secret:FAKE"},
                             "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )
    (root / "secrets.json").write_text(json.dumps({"FAKE": "s3cr3t"}), encoding="utf-8")

    ch = root / "inbox" / "CH3"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH3", "name": "sec", "category": "misc",
                    "agents": ["fake"], "target_kind": "file"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("x", encoding="utf-8")

    assert _run("watch", "--root", str(root), "--once", "--workers", "1").returncode == 0
    seen = (root / "work" / "CH3" / "fake" / "seen.txt").read_text(encoding="utf-8")
    assert seen == "s3cr3t"


SETTINGS_AGENT = '''
import json, sys
from pathlib import Path

args = sys.argv[1:]
settings = json.loads(Path(args[args.index("--settings") + 1]).read_text(encoding="utf-8"))
env = settings["env"]
(Path.cwd() / "seen.json").write_text(json.dumps(env), encoding="utf-8")
(Path("RESULT.json")).write_text(
    json.dumps({"flag": "flag{" + env["ANTHROPIC_API_KEY"] + "}", "confidence": 0.9}),
    encoding="utf-8")
'''


def test_settings_file_carries_secret_and_stays_out_of_workdir(tmp_path: Path) -> None:
    """claude 车道靠 --settings 钉网关：密钥要解析进去，且不落在 workdir/证据里。"""
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "settings_agent.py"
    fake.write_text(SETTINGS_AGENT, encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {
            "cmd": [sys.executable, str(fake), "--settings", "{settings}"],
            "settings": {"ANTHROPIC_API_KEY": "@secret:FAKE",
                         "ANTHROPIC_BASE_URL": "https://example.invalid/anthropic"},
            "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )
    (root / "secrets.json").write_text(json.dumps({"FAKE": "s3cr3t"}), encoding="utf-8")

    ch = root / "inbox" / "CH4"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH4", "name": "cfg", "category": "web",
                    "agents": ["fake"], "target_kind": "url"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("x", encoding="utf-8")

    proc = _run("watch", "--root", str(root), "--once", "--workers", "1")
    assert proc.returncode == 0, proc.stderr
    assert "flag{s3cr3t}" in (root / "outbox" / "flags.jsonl").read_text(encoding="utf-8")

    written = root / "runtime" / "settings-fake.json"
    assert written.exists()
    payload = json.loads(written.read_text(encoding="utf-8"))
    assert payload["env"]["ANTHROPIC_API_KEY"] == "s3cr3t"  # @secret: 已解析
    assert payload["env"]["ANTHROPIC_BASE_URL"] == "https://example.invalid/anthropic"
    workdir = root / "work" / "CH4" / "fake"
    assert not list(workdir.glob("settings-*.json"))  # 密钥不落 workdir


STDIN_AGENT = '''
import json, sys
from pathlib import Path

prompt = sys.stdin.read()
(Path("seen_prompt.txt")).write_text(prompt, encoding="utf-8")
(Path("RESULT.json")).write_text(
    json.dumps({"flag": "flag{stdin_ok}" if "MULTILINE" in prompt else "flag{bad}",
                "confidence": 0.9}), encoding="utf-8")
'''

SLEEPY_AGENT = '''
import subprocess, sys, time
subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
print("started", flush=True)
time.sleep(120)
'''


def test_prompt_goes_through_stdin(tmp_path: Path) -> None:
    """多行 prompt 必须走 stdin：Windows 的 .cmd 壳会把它拆坏。"""
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "stdin_agent.py"
    fake.write_text(STDIN_AGENT, encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {
            "cmd": [sys.executable, str(fake), "-"],
            "stdin": "{prompt}",
            "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )

    ch = root / "inbox" / "CH5"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH5", "name": "stdin multi\nline", "category": "misc",
                    "agents": ["fake"], "target_kind": "file"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("MULTILINE\nsecond line\n", encoding="utf-8")

    assert _run("watch", "--root", str(root), "--once", "--workers", "1").returncode == 0
    assert "flag{stdin_ok}" in (root / "outbox" / "flags.jsonl").read_text(encoding="utf-8")


def test_timeout_kills_whole_process_tree(tmp_path: Path) -> None:
    """超时要连孙进程一起杀，否则 communicate() 等不到 EOF，worker 永久挂死。"""
    import time

    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "sleepy_agent.py"
    fake.write_text(SLEEPY_AGENT, encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {
            "cmd": [sys.executable, str(fake)],
            "timeout": 3,
            "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )

    ch = root / "inbox" / "CH6"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH6", "name": "sleepy", "category": "misc",
                    "agents": ["fake"], "target_kind": "file"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("x", encoding="utf-8")

    started = time.monotonic()
    proc = _run("watch", "--root", str(root), "--once", "--workers", "1")
    elapsed = time.monotonic() - started
    assert proc.returncode == 0, proc.stderr
    assert elapsed < 60, f"watch 没有及时返回（{elapsed:.1f}s），进程树可能没杀干净"
    assert "status=timeout" in proc.stdout


def test_claude_lanes_have_no_platform_mcp() -> None:
    """人机协同赛道禁止 agent 接触平台：claude 车道必须屏蔽全局 MCP。"""
    mod = _module()
    for name, spec in mod.DEFAULT_AGENTS_SPEC.items():
        if not name.startswith("claude"):
            continue
        cmd = spec["cmd"]
        assert "--strict-mcp-config" in cmd, name
        mcp_arg = cmd[cmd.index("--mcp-config") + 1]
        assert mcp_arg.format(settings="x") == '{"mcpServers":{}}', name  # 模板转义正确
        assert spec["settings"]["ANTHROPIC_BASE_URL"].startswith("https://"), name
        assert spec["stdin"] == "{prompt}", name


def test_init_writes_mcp_free_codex_home(tmp_path: Path) -> None:
    """codex 车道用 desk 自己的 CODEX_HOME，不能继承全局的 ctfy 平台 MCP。"""
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0
    cfg = (root / "codex-home" / "config.toml").read_text(encoding="utf-8")
    assert "[mcp_servers" not in cfg
    assert 'env_key = "OPENAI_API_KEY"' in cfg

    mod = _module()
    env = mod.DEFAULT_AGENTS_SPEC["codex"]["env"]
    assert env["CODEX_HOME"] == "{root}/codex-home"
    assert env["OPENAI_API_KEY"] == "@secret:QWEN_KEY"


def test_result_json_with_bom_is_parsed(tmp_path: Path) -> None:
    """codex 在 Windows 上写出的 RESULT.json 带 BOM：不能退化成 stdout 正则。"""
    mod = _module()
    p = tmp_path / "RESULT.json"
    p.write_bytes(b'\xef\xbb\xbf{"flag": "flag{bom}", "confidence": 0.97}\r\n')
    flags, confidence, _ = mod.extract_result(p, "no flag in stdout")
    assert flags == ["flag{bom}"]
    assert confidence == 0.97


def test_plan_workers_narrows_on_memory() -> None:
    mod = _module()
    # 拿不到内存信息：按请求放行
    assert mod.plan_workers(3, None) == 3
    # 内存充足：不超过请求上限
    assert mod.plan_workers(3, 6400) == 3
    assert mod.plan_workers(6, 10000) == 6
    # 内存偏紧：按每路 700 MB 收窄，但至少留 1 路
    assert mod.plan_workers(4, 3600) == 3
    assert mod.plan_workers(3, 2300) == 1
    # 低于保底线：只跑 1 路
    assert mod.plan_workers(3, 800) == 1
    # 请求为 0 或负数也要有 1 路
    assert mod.plan_workers(0, 6400) == 1
    # 真实读数可用（拿不到也算通过，只要不抛异常）
    got = mod.free_mem_mb()
    assert got is None or got > 0


def test_pipeline_records_failure_without_fabricating_flag(tmp_path: Path) -> None:
    root = tmp_path / "desk"
    assert _run("init", "--root", str(root)).returncode == 0

    fake = tmp_path / "no_flag_agent.py"
    fake.write_text("import sys\n", encoding="utf-8")
    (root / "agents.json").write_text(
        json.dumps({"fake": {"cmd": [sys.executable, str(fake), "{workdir}"],
                             "result": "{workdir}/RESULT.json"}}),
        encoding="utf-8",
    )

    ch = root / "inbox" / "CH2"
    (ch / "files").mkdir(parents=True)
    (ch / "meta.json").write_text(
        json.dumps({"id": "CH2", "name": "noflag", "category": "rev",
                    "agents": ["fake"], "target_kind": "file"}),
        encoding="utf-8",
    )
    (ch / "statement.md").write_text("nothing here", encoding="utf-8")

    proc = _run("watch", "--root", str(root), "--once", "--workers", "1")
    assert proc.returncode == 0, proc.stderr

    flags_path = root / "outbox" / "flags.jsonl"
    assert not flags_path.exists() or "CH2" not in flags_path.read_text(encoding="utf-8")
    sheet = (root / "outbox" / "submit-sheet.md").read_text(encoding="utf-8")
    assert "CH2" in sheet
    assert "—" in sheet