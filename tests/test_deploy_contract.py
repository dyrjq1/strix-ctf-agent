"""部署契约的防漂移单测（docs/47 §1.5）。

比赛日最贵的失败不是解不出题，是 10:00 到点进程起不来。这一层没有 Python 代码
可测，所以把"会漂移的三处"用文本钉住：

  1. 启动器传给 compete.py 的参数名 —— compete.py 改过参数名而启动器没跟上，
     结果是开机就 argument error，而且只有比赛当天才会发现；
  2. 启动器读的环境变量 —— 脚本加了必填项而模板没加，部署时缺一个就是 30 分钟；
  3. 模板里不许有真凭据 —— 这个文件是要进仓库的。
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import compete  # noqa: E402

DEPLOY = ROOT / "scripts" / "deploy"
RUNNER = DEPLOY / "agent_run.sh"
INSTALLER = DEPLOY / "install.sh"
ENV_TEMPLATE = DEPLOY / "agent.env.example"
RUNBOOK = DEPLOY / "RUNBOOK.md"

# agent_run.sh 自己用、不该出现在环境模板里的变量：CTFY_ENV 是"去哪读这份文件"，
# 写进文件里就成了先有鸡还是先有蛋。
_NOT_IN_TEMPLATE = {"CTFY_ENV"}


def _read(path: Path) -> str:
    assert path.is_file(), f"缺少部署文件：{path}"
    return path.read_text(encoding="utf-8")


def _flags_passed_by_runner() -> set[str]:
    """启动器在 args=(...) 里传出去的 --flag。"""
    text = _read(RUNNER)
    block = re.search(r"args=\((.*?)\n  \)", text, re.S)
    assert block, "agent_run.sh 里找不到 args=(...) 块"
    return set(re.findall(r"(--[a-z][a-z-]+)", block.group(1)))


def _flags_compete_defines() -> set[str]:
    return {
        opt
        for action in compete.build_parser()._actions
        for opt in action.option_strings
        if opt.startswith("--")
    }


def test_every_flag_the_runner_passes_is_a_real_compete_flag() -> None:
    passed = _flags_passed_by_runner()
    assert passed, "args 块里一个参数都没解析出来"
    unknown = passed - _flags_compete_defines()
    assert not unknown, f"启动器传了 compete.py 不认识的参数：{sorted(unknown)}"


def test_runner_passes_the_two_required_compete_flags() -> None:
    passed = _flags_passed_by_runner()
    assert {"--token", "--competition"} <= passed


def test_env_template_defines_every_variable_the_runner_reads() -> None:
    """脚本读的变量模板里都要有，否则部署时才发现缺项。"""
    runner = _read(RUNNER)
    wanted = set(re.findall(r"\$\{?((?:CTFY|LLM|STRIX)_[A-Z0-9_]+)", runner))
    wanted -= _NOT_IN_TEMPLATE
    template = _read(ENV_TEMPLATE)
    missing = sorted(name for name in wanted if name not in template)
    assert not missing, f"环境模板缺这些变量：{missing}"


def test_env_template_has_no_credential_shaped_value() -> None:
    """模板进仓库：凭据必须还是 <...> 占位符（URL/布尔/整数这类默认值允许写实）。"""
    text = _read(ENV_TEMPLATE)
    for line in text.splitlines():
        if line.lstrip().startswith("#") or "=" not in line:
            continue
        key, _, raw = line.partition("=")
        value = raw.split("#", 1)[0].strip()
        assert not re.search(r"\b(pf_|pk_|sk-)[A-Za-z0-9_\-]{8,}", value), (
            f"{key.strip()} 里像是有真凭据"
        )
        assert not re.fullmatch(r"[0-9a-fA-F]{32,}", value), (
            f"{key.strip()} 里像是有真 key/competition id"
        )


def test_env_template_asks_for_max_tokens() -> None:
    """网关缺 max_tokens 一律 400（11-14 实测），模板必须带上且是个数。"""
    assert re.search(r"^LLM_MAX_TOKENS=\d+", _read(ENV_TEMPLATE), re.M)


def test_deploy_scripts_are_lf_and_have_shebangs() -> None:
    for path in (RUNNER, INSTALLER):
        raw = path.read_bytes()
        assert b"\r\n" not in raw, f"{path.name} 有 CRLF，到 Linux 上 bash 会报错"
        assert raw.startswith(b"#!/usr/bin/env bash"), f"{path.name} 缺 shebang"


def test_runbook_covers_the_gates_that_have_bitten_us() -> None:
    """四道闸门每一项都有实测出处，少一项就等于没写。"""
    text = _read(RUNBOOK)
    for token in ("WireGuard", "max_tokens", "重启", "19:45"):
        assert token in text, f"runbook 缺：{token}"