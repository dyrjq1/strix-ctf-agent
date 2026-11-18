"""ctfdesk 端到端测试：用假 agent 验证 inbox -> 派发 -> 提交单链路，不联网。"""

from __future__ import annotations

import importlib.util
import json
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