"""``scripts/index_health.py``——历史日志的技能索引导航体检（D-5）。

守的东西，按回归代价排序：

1. **纯解析器。** 不 import ``ctf_strix``：拿到任何机器上（只有 jsonl+log）
   都必须能复算。这里的测试同样只构造日志文本，不启动任何 agent。
2. **② 的窗口语义。** load 后 3 个 TOOL 调用内读到引用路径才算命中；
   第 4 个不算，非引用路径不算，别的工具名不算。
3. **③ 是离线确定性。** 注入字节按 load 的技能名取 staged 索引文件尺寸
   （D-1 的 8KB 闸使然）；文件缺失如实记 missing，不猜。
4. **④ 的判定规则。** triage 先行恒一致；方向集合按题型；题型未知不判。
5. **降级路径。** 参数被日志截断时按形状抓取，抓不到就 None——但 load
   本身仍然计数（① 不因参数丢失而漏报）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from index_health import (  # noqa: E402
    analyze_log,
    first_load_consistent,
    parse_tool_calls,
    run_report,
    summarize_runs,
)


def _log(*entries: tuple[str, str]) -> str:
    """构造与 run.log 相同行格式的日志文本。"""
    lines = []
    for tool, args in entries:
        lines.append(f"  [0011aa22] TOOL {tool} {args}")
        lines.append("  [0011aa22] OUT  ok")
    return "\n".join(lines) + "\n"


def _load(skill: str) -> tuple[str, str]:
    return ("load_skill", json.dumps({"skills": [skill]}))


def _exec(cmd: str) -> tuple[str, str]:
    return ("exec_command", json.dumps({"cmd": cmd, "workdir": "/tmp/sandbox-1"}))


def test_parse_tool_calls_reads_name_and_raw_args() -> None:
    text = _log(_load("ctf-web/ctf-web"), _exec("curl -sk https://example.test/"))
    calls = parse_tool_calls(text)
    assert [name for name, _ in calls] == ["load_skill", "exec_command"]
    assert "ctf-web/ctf-web" in calls[0][1]
    # OUT 行不算 TOOL 调用
    assert len([1 for line in text.splitlines() if "OUT" in line]) >= 1


def test_ref_read_within_window_counts() -> None:
    text = _log(
        _load("ctf-web/ctf-web"),
        _exec("ls /tmp"),
        _exec("cat /var/ctf/jail/skills/ctf-web/web-sqli.md | head"),
    )
    result = analyze_log(text, None)
    assert result["skill_loads"] == 1
    assert result["skill_ref_reads"] == 1


def test_ref_read_after_the_window_does_not_count() -> None:
    """第 4 个 TOOL 调用才读引用路径：超出「3 轮内」的契约，不算命中。"""
    text = _log(
        _load("ctf-web/ctf-web"),
        _exec("ls"),
        _exec("pwd"),
        _exec("echo hi"),
        _exec("cat /var/ctf/jail/skills/ctf-web/web-sqli.md"),
    )
    assert analyze_log(text, None)["skill_ref_reads"] == 0


def test_jail_ref_root_via_read_file_counts() -> None:
    """老日志用 vendor 基座的 read_file 读子文件，同样算命中。"""
    text = _log(
        _load("ctf-crypto/ctf-crypto"),
        ("read_file", json.dumps({"path": "/src/ctf_strix/skills_strix/ctf-crypto/rsa.md"})),
    )
    assert analyze_log(text, None)["skill_ref_reads"] == 1


def test_non_ref_commands_do_not_count() -> None:
    """load 之后全是目标侧命令（curl/objdump/strings）：如实计 0。"""
    text = _log(
        _load("ctf-triage/ctf-triage"),
        _exec("curl -sk https://example.test/ | head -c 3000"),
        _exec("objdump -d ./chall | head"),
    )
    assert analyze_log(text, None)["skill_ref_reads"] == 0


def test_inject_bytes_are_offline_staged_sizes(tmp_path: Path) -> None:
    """③ 按 load 的技能名取 staged 索引尺寸；缺失如实记 missing。"""
    web = tmp_path / "ctf-web"
    web.mkdir()
    (web / "ctf-web.md").write_bytes(b"x" * 1000)
    triage = tmp_path / "ctf-triage"
    triage.mkdir()
    (triage / "ctf-triage.md").write_bytes(b"x" * 2000)

    text = _log(_load("ctf-triage/ctf-triage"), _load("ctf-web/ctf-web"), _load("ctf-ai-ml/ctf-ai-ml"))
    result = analyze_log(text, tmp_path)
    assert result["skill_inject_bytes"] == 3000
    assert result["skill_inject_missing"] == 1
    assert result["skill_first"] == "ctf-triage"


def test_missing_skills_root_degrades_to_unknown() -> None:
    """没有 staged 技能包时 ③ 无法计算：只报 missing，不报负数不抛错。"""
    result = analyze_log(_log(_load("ctf-web/ctf-web")), None)
    assert result["skill_inject_bytes"] == 0
    assert result["skill_inject_missing"] == 1


def test_first_load_consistency_rules() -> None:
    """triage 先行恒一致；题型方向集合内一致；跨题型不一致；未知题型不判。"""
    assert first_load_consistent("web", "ctf-triage") is True
    assert first_load_consistent("tcp", "ctf-triage") is True
    assert first_load_consistent("web", "ctf-web") is True
    assert first_load_consistent("file", "ctf-reverse") is True
    assert first_load_consistent("web", "ctf-reverse") is False
    assert first_load_consistent("tcp", "ctf-web") is False
    assert first_load_consistent(None, "ctf-web") is None
    assert first_load_consistent("web", None) is None


def test_unparseable_args_degrade_but_still_count_the_load() -> None:
    """日志行截断导致 JSON 不完整：按形状抓技能名；完全抓不到时 load 仍计数。"""
    text = (
        "  [0011aa22] TOOL load_skill {\"skills\":[\"ctf-web/ctf-w\n"
        "  [0011aa22] TOOL exec_command {\"cmd\":\"ls\"}\n"
    )
    result = analyze_log(text, None)
    assert result["skill_loads"] == 1
    assert result["skill_first"] == "ctf-web"
    assert result["skill_inject_missing"] == 1

    garbage = "  [0011aa22] TOOL load_skill ???truncated???\n"
    result = analyze_log(garbage, None)
    assert result["skill_loads"] == 1
    assert result["skill_first"] is None


def test_summarize_runs_computes_all_four_metrics() -> None:
    runs = [
        {  # 有日志、有 load、读到子文件、triage 先行
            "id": "A", "kind": "web", "has_log": True,
            "skill_loads": 1, "skill_first": "ctf-triage",
            "skill_ref_reads": 1, "skill_inject_bytes": 5000,
            "skill_inject_missing": 0,
        },
        {  # 有日志、有 load、没读子文件、方向错
            "id": "B", "kind": "tcp", "has_log": True,
            "skill_loads": 2, "skill_first": "ctf-osint",
            "skill_ref_reads": 0, "skill_inject_bytes": 6000,
            "skill_inject_missing": 0,
        },
        {  # 没有日志：只进分母不进分子（has_log=False 整行排除）
            "id": "C", "kind": "web", "has_log": False,
            "skill_loads": 0, "skill_first": None,
            "skill_ref_reads": 0, "skill_inject_bytes": None,
            "skill_inject_missing": 0,
        },
        {  # 有日志、没 load
            "id": "D", "kind": "web", "has_log": True,
            "skill_loads": 0, "skill_first": None,
            "skill_ref_reads": 0, "skill_inject_bytes": 0,
            "skill_inject_missing": 0,
        },
    ]
    s = summarize_runs(runs)
    assert s["runs"] == 4
    assert s["runs_with_log"] == 3
    assert s["metric_1_load_rate"] == 2 / 3  # A、B
    assert s["metric_2_ref_read_rate"] == 1 / 3  # 3 次 load 里 1 次读到
    assert s["metric_3_inject_bytes_per_load"] == 11000 / 3
    assert s["metric_4_first_dir_rate"] == 1 / 2  # A 一致、B 不一致；D 无 load 不判


def test_run_report_resolves_logs_by_basename(tmp_path: Path) -> None:
    """log_path 是容器内路径时，按文件名在 --logs-dir 里找到对应日志。"""
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "run-a.log").write_text(_log(_load("ctf-web/ctf-web")), encoding="utf-8")

    rows = [{"id": "A", "kind": "web", "log_path": "/workspace/reports/run-a.log"}]
    runs = run_report(rows, None, logs_dir=logs)
    assert runs[0]["has_log"] is True
    assert runs[0]["skill_loads"] == 1


def test_run_report_without_log_reports_zero_fields(tmp_path: Path) -> None:
    rows = [{"id": "A", "kind": "web", "log_path": "/gone/run-a.log"}]
    runs = run_report(rows, None, logs_dir=tmp_path)
    assert runs[0]["has_log"] is False
    assert runs[0]["skill_loads"] == 0
    assert runs[0]["skill_inject_bytes"] is None


def test_main_single_log_mode_reproduces_all_four(tmp_path, capsys) -> None:
    """单日志模式：一条 log 直接复现四指标（PLAN 的验收原句）。"""
    import index_health as ih

    skills = tmp_path / "skills"
    (skills / "ctf-triage").mkdir(parents=True)
    (skills / "ctf-triage" / "ctf-triage.md").write_bytes(b"x" * 5097)
    log = tmp_path / "run.log"
    log.write_text(_log(_load("ctf-triage/ctf-triage"), _exec("curl -sk https://example.test/")), encoding="utf-8")
    out = tmp_path / "health.json"

    rc = ih.main(
        [
            "--log", str(log), "--kind", "web", "--id", "demo",
            "--skills-root", str(skills), "--json", str(out),
        ]
    )
    assert rc == 0
    printed = capsys.readouterr().out
    for marker in ("①", "②", "③", "④"):
        assert marker in printed, f"指标 {marker} 没有出现在输出里"

    payload = json.loads(out.read_text(encoding="utf-8"))
    run = payload["runs"][0]
    assert run["skill_inject_bytes"] == 5097
    assert payload["summary"]["metric_1_load_rate"] == 1.0
    assert payload["summary"]["metric_2_ref_read_rate"] == 0.0
    assert payload["summary"]["metric_4_first_dir_rate"] == 1.0
