"""本地校验 agent 入口是否符合 CTFY 的 result 契约。

## 为什么需要这个

平台上真正的检查是 `ctfy agent check`，它要 Docker 才能跑 `docker run`，
而开发机没有 Docker。于是"容器内是否符合契约"一直是最大的未知项。

这个脚本用**平台自己的判据**（`ctfy.core.harness_conformance.inspect_probe`）
在**本机直接执行入口脚本**，跳过 Docker 但保留全部判定逻辑。这样能消掉的
是契约层面（起得来吗、写得出文件吗、字段对吗），消不掉的是镜像层面
（entrypoint、架构、拉取）——后者本地无法测，属于已知残余风险。

判据来自 `harness_conformance.py:280-344`，只有两条 blocking：

    did_not_start   —— 容器起不来
    no_result_file  —— 没写出可读的 result 文件

其余（`no_schema_version` / `dry_run_ignored` / `nonzero_exit`）都是 advisory。
**注意**：advisory 不阻断，但每次 dispatch 都会显示，属于白送的扣分。

## 用法

    cd /workspace && PYTHONPATH=src:vendor/src .venv/bin/python scripts/check_contract.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "src" / "ctf_strix" / "agent.py"

try:
    from ctfy.core.harness_conformance import ProbeResult, inspect_probe
except ImportError:  # pragma: no cover
    sys.exit("找不到 ctfy 包，先在项目 venv 里安装 ctfy==0.7.0")

#: dry run 的期望上限。平台给 180s，但一个不解题的 dry run 应该是秒级——
#: 若接近 180s，说明入口忽略了 dry_run 真去打了靶机。
DRY_RUN_EXPECT_S = 10.0


def _make_task(work: Path, payload: dict[str, Any]) -> None:
    """把 task.json 写进工作目录。"""
    (work / "task.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _read_rollup(result_path: Path) -> dict[str, Any] | None:
    """模拟平台节点的读取：文件不存在或解析失败都记为 None（=no_result_file）。"""
    if not result_path.exists():
        return None
    try:
        data = json.loads(result_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return data if isinstance(data, dict) else None


def _run_scenario(
    name: str,
    task: dict[str, Any],
    *,
    env_patch: dict[str, str] | None = None,
    timeout_s: float = 120.0,
) -> tuple[ProbeResult, dict[str, Any] | None, float]:
    """在独立临时目录里跑一次入口，返回探针结果。

    Args:
        name: 场景名，仅用于目录命名。
        task: 写进 task.json 的内容。
        env_patch: 追加/覆盖的环境变量，用来注入故障。
        timeout_s: 子进程墙钟上限。

    Returns:
        (探针结果, 解析出的 rollup, 实际耗时秒)
    """
    work = Path(tempfile.mkdtemp(prefix=f"contract-{name}-"))
    _make_task(work, task)

    env = {
        "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / 'vendor/src'}",
        "PYTHONUNBUFFERED": "1",
        "CTFY_WORK_DIR": str(work),
        # 断掉模型与平台：契约校验不该产生任何外部副作用。
        "LLM_API_KEY": "sk-contract-check-not-a-real-key",
        "LLM_API_BASE": "http://127.0.0.1:1/v1",
        "STRIX_LLM": "openai/contract-check-stub",
        "STRIX_TELEMETRY": "false",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    if env_patch:
        env.update(env_patch)

    started = time.time()
    timed_out = False
    try:
        proc = subprocess.run(
            [str(ROOT / ".venv/bin/python"), "-u", str(ENTRY)],
            env=env,
            cwd=str(work),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        exit_code = proc.returncode
        tail = (proc.stdout or "")[-600:] + (proc.stderr or "")[-400:]
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = -9
        tail = "<killed by wall clock>"
    elapsed = time.time() - started

    # result 路径按 task.json 的声明解析，与 agent.py 的 _result_path 一致。
    declared = (task.get("result") or {}).get("path")
    result_path = (work / declared) if declared else (work / "result.json")
    if declared and Path(declared).is_absolute():
        result_path = Path(declared)

    rollup = _read_rollup(result_path)
    probe = ProbeResult(
        exit_code=exit_code,
        rollup=rollup,
        timed_out=timed_out,
        error="" if exit_code is not None else "",
    )
    if tail.strip():
        print(f"    └ 输出尾部：{tail.strip().splitlines()[-1][:150]}")
    return probe, rollup, elapsed


def main() -> int:
    """跑完全部场景并汇总。返回 0 表示契约通过。"""
    url = "https://contract-check.invalid/"
    scenarios: list[tuple[str, dict[str, Any], dict[str, str] | None, float]] = [
        # ① dry run：平台最常执行的一次，必须秒退且不碰靶机。
        (
            "dry_run",
            {
                "schema_version": 2,
                "run_mode": "instance",
                "challenge": {"id": "CHK-1", "name": "dry", "description": "noop"},
                "scope": [url],
                "dry_run": True,
                "max_turns": 3,
            },
            None,
            60.0,
        ),
        # ② 没有靶机：常见于 qa/engagement 模式误投，必须仍写出文件。
        (
            "no_scope",
            {
                "schema_version": 2,
                "run_mode": "instance",
                "challenge": {"id": "CHK-2", "name": "noscope", "description": "x"},
                "scope": [],
                "max_turns": 3,
            },
            None,
            60.0,
        ),
        # ③ 相对 result.path：平台可能改路径，必须跟着改而不是写死。
        (
            "declared_path",
            {
                "schema_version": 2,
                "run_mode": "qa",
                "challenge": {"id": "CHK-3", "name": "custom", "description": "x"},
                "scope": [],
                "result": {"path": "out/r.json"},
                "max_turns": 1,
            },
            None,
            60.0,
        ),
        # ④ 依赖缺失（模拟镜像里 strix 没装上）：必须走 except 分支仍写文件。
        (
            "import_crash",
            {
                "schema_version": 2,
                "run_mode": "instance",
                "challenge": {"id": "CHK-4", "name": "crash", "description": "x"},
                "scope": [url],
                "max_turns": 1,
            },
            {"PYTHONPATH": str(ROOT / "src")},
            90.0,
        ),
    ]

    print("CTFY result 契约本地校验（判据来自 ctfy.core.harness_conformance）")
    print("=" * 78)

    failures = 0
    for name, task, env_patch, timeout_s in scenarios:
        print(f"\n▶ {name}")
        probe, rollup, elapsed = _run_scenario(
            name, task, env_patch=env_patch, timeout_s=timeout_s
        )
        findings = inspect_probe(probe)
        blocking = [f for f in findings if f.severity == "blocking"]

        extra: list[str] = []
        if name == "dry_run":
            if elapsed > DRY_RUN_EXPECT_S:
                extra.append(f"dry run 耗时 {elapsed:.1f}s > {DRY_RUN_EXPECT_S}s")
            if rollup and rollup.get("stop_reason") != "dry_run":
                extra.append(f"stop_reason={rollup.get('stop_reason')!r} 应为 'dry_run'")
        if rollup is not None and rollup.get("schema_version") != 2:
            extra.append(f"schema_version={rollup.get('schema_version')!r} 应为 2")

        ok = not blocking and not extra
        if not ok:
            failures += 1
        print(f"    {'PASS' if ok else 'FAIL'}  耗时 {elapsed:.1f}s  exit={probe.exit_code}")
        for f in findings:
            mark = "blocking" if f.severity == "blocking" else "advisory"
            print(f"      · [{mark}] {f.code}: {f.detail}")
        for e in extra:
            print(f"      · [本脚本] {e}")

    print("\n" + "=" * 78)
    if failures:
        print(f"契约校验未通过：{failures}/{len(scenarios)} 个场景有问题")
        return 1
    print(f"契约校验通过：{len(scenarios)}/{len(scenarios)} 个场景")
    print("残余风险：镜像层（entrypoint/架构/拉取）本地无法验证，仍需一次真机 dry run。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
