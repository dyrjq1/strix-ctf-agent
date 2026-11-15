"""派单闸门：环境不可用 ≠ 题目失败。

背景（台账 §4.199 / docs/40 §7）：2026-11-13 一个失效的 LLM key 连续烧掉
10 道题的派单，``compete`` 还把每题记成 failed，两连败后整题 deferred。
这里钉三件事：

1. 闸门只在**凭据/权限**明确失败时停队；网络抖动/5xx 放行（交给 launch 重试）。
2. 闸门停跑时 batch_eval 不写结果行。
3. compete 收车时若本轮没有新结果行，记 INFRA：不计 fails、不降级成失败。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import batch_eval  # noqa: E402
import compete  # noqa: E402


# ------------------------------------------------------------------ 假平台


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text


class _Session:
    def __init__(self, resp=None, exc: Exception | None = None) -> None:
        self.headers: dict[str, str] = {}
        self._resp = resp
        self._exc = exc
        self.calls: list[tuple] = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params, timeout))
        if self._exc is not None:
            raise self._exc
        return self._resp


def _client(resp=None, exc=None) -> batch_eval.Client:
    c = batch_eval.Client("pf_test")
    c.s = _Session(resp=resp, exc=exc)
    return c


def test_platform_canary_ok_on_200() -> None:
    ok, detail = _client(_Resp(200)).canary()
    assert ok is True
    assert detail == "ok"


def test_platform_canary_passes_when_only_competition_scope_missing() -> None:
    """403 + competition_required 是用法问题，不是凭据问题（误判过一次）。"""
    ok, detail = _client(_Resp(403, '{"detail":"competition_required"}')).canary()
    assert ok is True
    assert "competition_required" in detail


def test_platform_canary_refuses_on_real_auth_failure() -> None:
    ok, detail = _client(_Resp(401, '{"detail":"invalid token"}')).canary()
    assert ok is False
    assert detail.startswith("auth:")


def test_platform_canary_does_not_stop_the_batch_on_5xx() -> None:
    """平台抖动交给 launch 的退避重试；一次 503 升级成整批停跑更糟。"""
    ok, detail = _client(_Resp(503, "busy")).canary()
    assert ok is True
    assert detail.startswith("skip:http")


def test_platform_canary_does_not_stop_the_batch_on_network_error() -> None:
    import requests

    ok, detail = _client(exc=requests.ConnectionError("boom")).canary()
    assert ok is True
    assert detail.startswith("skip:network")


# ------------------------------------------------------------------ LLM 探针


def test_llm_canary_passes_when_disabled(monkeypatch) -> None:
    from ctf_strix import llm_preflight

    monkeypatch.setattr(llm_preflight, "enabled", lambda env=None: False)
    ok, detail = batch_eval._canary_llm({})
    assert ok is True
    assert detail == "skip:disabled"


def test_llm_canary_refuses_on_credential_verdict(monkeypatch) -> None:
    from ctf_strix import llm_preflight

    monkeypatch.setattr(llm_preflight, "enabled", lambda env=None: True)
    monkeypatch.setattr(
        llm_preflight,
        "probe",
        lambda **kw: llm_preflight.ProbeResult(False, "http_401", kind="credential"),
    )
    ok, detail = batch_eval._canary_llm({})
    assert ok is False
    assert detail == "credential:http_401"


def test_llm_canary_passes_a_healthy_endpoint(monkeypatch) -> None:
    from ctf_strix import llm_preflight

    monkeypatch.setattr(llm_preflight, "enabled", lambda env=None: True)
    monkeypatch.setattr(
        llm_preflight, "probe", lambda **kw: llm_preflight.ProbeResult(True, "ok")
    )
    ok, detail = batch_eval._canary_llm({})
    assert ok is True
    assert detail == "ok"


def test_canary_switch_env() -> None:
    assert batch_eval._canary_enabled({}) is True
    for off in ("0", "false", "off", "no", "NO"):
        assert batch_eval._canary_enabled({"CTF_CANARY": off}) is False
    assert batch_eval._canary_enabled({"CTF_CANARY": "1"}) is True


# ------------------------------------------------------------------ 收车口径


def _state_dir(tmp_path: Path, cid: str, rows: list[dict]) -> Path:
    d = tmp_path / "state"
    (d / "runs").mkdir(parents=True)
    if rows:
        (d / "runs" / f"{cid}.jsonl").write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
        )
    return d


def test_collect_without_new_row_is_infra_not_failure(tmp_path: Path) -> None:
    """闸门停跑：本轮没写行 ⇒ INFRA，fails 不动、状态回到 active。"""
    cid = "A"
    old = {"challenge": cid, "correct": False, "error": "old failure"}
    state_dir = _state_dir(tmp_path, cid, [old])
    state = {cid: {"status": compete.RUNNING, "runs": 1, "fails": 1, "rows_before": 1}}

    status = compete._collect(cid, state, state_dir, exit_code=3)

    assert status == compete.INFRA
    assert state[cid]["status"] == compete.ACTIVE
    assert state[cid]["fails"] == 1, "旧失败不得被重复计一次"
    assert state[cid]["infra_stops"] == 1


def test_collect_with_new_row_still_judges_normally(tmp_path: Path) -> None:
    cid = "B"
    row = {"challenge": cid, "correct": False, "stop_reason": "unknown"}
    state_dir = _state_dir(tmp_path, cid, [row])
    state = {cid: {"status": compete.RUNNING, "runs": 0, "fails": 0, "rows_before": 0}}

    status = compete._collect(cid, state, state_dir, exit_code=1)

    assert status == compete.FAILED
    assert state[cid]["fails"] == 1


def test_collect_skipped_row_still_counts_as_infra_skip(tmp_path: Path) -> None:
    """有结果行但标了 skipped：沿用 B-23 口径（计 skips，不计 fails）。"""
    cid = "C"
    row = {"challenge": cid, "correct": False, "skipped": True,
           "error": "SKIPPED(需隧道)"}
    state_dir = _state_dir(tmp_path, cid, [row])
    state = {cid: {"status": compete.RUNNING, "runs": 0, "fails": 0,
                   "skips": 0, "rows_before": 0}}

    status = compete._collect(cid, state, state_dir, exit_code=0)

    assert status == compete.FAILED
    assert state[cid]["skips"] == 1
    assert state[cid]["fails"] == 0