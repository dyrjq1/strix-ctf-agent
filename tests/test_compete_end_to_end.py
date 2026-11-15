"""compete.py 的端到端离线冒烟：真 socket、真 HTTP 客户端、假平台。

单测覆盖的是策略函数（``test_compete_strategy.py``），但调度器真正会出事的
地方在**接线**：URL 拼错、认证头漏带、``items`` 分页形状变了、提交后本地
账本没升级——这些在任何纯函数测试里都看不见，而它们一旦在比赛日出现，
表现是"进程在跑、分数不涨"。

所以这里起一个真 HTTP 服务当平台，把 ``compete.PLATFORM`` 指过去，只把
``_spawn``（真正会起实例、烧钱的子进程）换成假的。跑的是 main() 本身。

这些用例不碰真平台、不需要 token、不占实例配额。
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "src"))

import compete  # noqa: E402

CID = "deadbeefcafe"


def _chal(cid: str, **kw) -> dict:
    base = {
        "id": cid,
        "category": "web",
        "difficulty": "easy",
        "solves_count": 0,
        "questions": [],
        "closed": False,
        "is_qa_only": False,
    }
    base.update(kw)
    return base


class _Platform:
    """最小平台：只要能回答 compete.py 会问的那四个 GET。"""

    def __init__(self, challenges, solves=()):
        self.challenges = list(challenges)
        self.solves = list(solves)
        self.paths: list[str] = []
        self.auth: list[str | None] = []

    def handler(self):
        platform = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *args):  # 别把访问日志写进测试输出
                pass

            def _json(self, body) -> None:
                raw = json.dumps(body).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler 约定
                path = self.path.split("?", 1)[0]
                platform.paths.append(self.path)
                platform.auth.append(self.headers.get("Authorization"))
                if path == "/api/v1/me/solves":
                    self._json(
                        {"items": [{"challenge_id": c} for c in platform.solves]}
                    )
                elif path.endswith("/challenges"):
                    self._json({"items": platform.challenges})
                elif path.endswith("/scoreboard"):
                    self._json({"my_rank": 1, "my_score": 0})
                elif "/competitions/" in path:
                    self._json({"sessions": []})
                else:
                    self._json({})

        return H


@pytest.fixture()
def platform():
    """起服务 → 交出 (base_url, 平台对象) → 关服务。"""
    servers: list[ThreadingHTTPServer] = []

    def start(challenges, solves=()):
        p = _Platform(challenges, solves)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), p.handler())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}", p

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


class _FakeProc:
    def __init__(self, code: int = 0):
        self.returncode = code

    def poll(self):
        return self.returncode

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return self.returncode


def _run(monkeypatch, base: str, state_dir: Path, spawned: list, *,
         correct: bool = True, argv_extra: tuple[str, ...] = ()) -> int:
    """跑一次 main()，把子进程换成"写一条结果行就退出"的假货。"""
    monkeypatch.setattr(compete, "PLATFORM", base)

    def fake_spawn(chal, args, sdir, failure_path=None, lane=0):
        runs = Path(sdir) / "runs"
        runs.mkdir(parents=True, exist_ok=True)
        # 真 _spawn 会先把派单 plan 落盘再起子进程；这里照做，好让"派单项里
        # 到底有什么"可断言（隔离不变量）。
        plan = [
            compete.build_plan_item(
                str(chal["id"]), chal,
                allow_pools=getattr(args, "allow_pools", False),
            )
        ]
        (runs / f"plan-{chal['id']}.json").write_text(
            json.dumps(plan), encoding="utf-8"
        )
        spawned.append({"id": str(chal["id"]), "lane": lane, "plan": plan})
        rec = {"challenge": str(chal["id"]), "correct": correct}
        if not correct:
            rec["stop_reason"] = "turns_exhausted"
        with (runs / f"{chal['id']}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return _FakeProc(0)

    monkeypatch.setattr(compete, "_spawn", fake_spawn)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "compete.py",
            "--token", "test-token",
            "--competition", CID,
            "--state-dir", str(state_dir),
            "--lanes", "1",
            "--once",
            "--poll", "0.02",
            *argv_extra,
        ],
    )
    return compete.main()


def test_the_loop_solves_what_the_fake_agent_solves(platform, monkeypatch, tmp_path):
    """派单 → 收车 → 写 state → 不再重派。这是整条链路最短的一条。"""
    base, p = platform([_chal("CHAL-1")])
    spawned: list = []
    rc = _run(monkeypatch, base, tmp_path, spawned)

    assert rc == 0
    assert [s["id"] for s in spawned] == ["CHAL-1"]
    assert spawned[0]["lane"] == 0
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["CHAL-1"]["status"] == compete.SOLVED
    assert state["CHAL-1"]["runs"] == 1
    # 索引用的是题号与难度，不含任何题面/靶机信息（隔离不变量）。
    assert spawned[0]["plan"] == [{"id": "CHAL-1", "difficulty": "easy"}]


def test_every_platform_call_carries_the_token(platform, monkeypatch, tmp_path):
    """认证头漏带会表现为 401，而 401 在日志里长得像"平台故障"。"""
    base, p = platform([_chal("CHAL-1")])
    _run(monkeypatch, base, tmp_path, [])
    assert p.auth, "一次请求都没发出去"
    assert all(h == "Bearer test-token" for h in p.auth), p.auth


def test_platform_solved_is_not_dispatched(platform, monkeypatch, tmp_path):
    """B-28：别处（浏览器/另一个 harness）解出的题不能再起一个实例。"""
    base, p = platform([_chal("CHAL-1"), _chal("CHAL-2")], solves=["CHAL-1"])
    spawned: list = []
    _run(monkeypatch, base, tmp_path, spawned)
    assert [s["id"] for s in spawned] == ["CHAL-2"]


def test_closed_challenge_is_never_dispatched(platform, monkeypatch, tmp_path):
    base, p = platform([_chal("CHAL-1", closed=True), _chal("CHAL-2")])
    spawned: list = []
    _run(monkeypatch, base, tmp_path, spawned)
    assert [s["id"] for s in spawned] == ["CHAL-2"]


def test_a_failed_challenge_spends_its_tail_budget_then_defers(
    platform, monkeypatch, tmp_path
):
    """失败要进 fails、留一行失败路径，并且把尾巴题的重试预算真的用掉。

    顺带钉住一个容易误读的语义：``--once`` 是"队列跑空就退出"，不是"每题
    只派一次"。一道零解出的题（尾巴题，预算 5）在同一次 --once 里会被派到
    预算耗尽才 deferred——独立重试是弱模型上证据最强的杠杆（见
    ``_TAIL_RETRY_BUDGET`` 的注释），冒烟时看到的 5 次不是重复派单 bug。
    """
    base, p = platform([_chal("CHAL-1")])
    spawned: list = []
    _run(monkeypatch, base, tmp_path, spawned, correct=False)
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    rec = state["CHAL-1"]
    assert rec["fails"] == compete._TAIL_RETRY_BUDGET
    assert len(spawned) == compete._TAIL_RETRY_BUDGET
    assert rec["status"] == compete.DEFERRED
    assert rec["failure_path"] and "turns_exhausted" in rec["failure_path"][-1]


def test_a_deadline_in_the_past_exits_without_touching_the_platform(
    platform, monkeypatch, tmp_path
):
    """--until 早于现在 = 立刻收工，不派单也不拉题表（19:45 那道闸门）。

    启动时仍会拉一次已解列表与会话窗口（都在主循环之前），所以这里断言的是
    "没有派单、没拉题表"，不是"零请求"。
    """
    base, p = platform([_chal("CHAL-1")])
    spawned: list = []
    rc = _run(monkeypatch, base, tmp_path, spawned,
              argv_extra=("--until", "2020-01-01T00:00:00+08:00"))
    assert rc == 0
    assert spawned == []
    assert not any(path.endswith("/challenges") for path in p.paths), p.paths


def test_digest_is_written_beside_the_state(platform, monkeypatch, tmp_path):
    """digest 是跨题记忆的简略层，必须在每轮之后落盘。"""
    base, p = platform([_chal("CHAL-1")])
    _run(monkeypatch, base, tmp_path, [])
    text = (tmp_path / "digest.md").read_text(encoding="utf-8")
    assert "CHAL-1" in text and "solved" in text