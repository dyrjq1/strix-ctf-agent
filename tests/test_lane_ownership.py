"""实例清理必须按所有权收敛，不能按账号清空，更不能按时间猜。

并行跑批时同 token 下同时活着多个实例是正常状态（正式套件配额实测为 3）。
旧实现 ``reap_orphans`` 把本账号名下所有 ready/starting 实例全删；中间一版
按"创建时刻早于本进程启动"判尸体，但并行车道几乎同时起跑，兄弟的创建时刻
同样早于我 → 同样被整片拔掉。靶面在宽限期里还能访问，可该车道之后所有
``/check``、``/submissions`` 全变成 ``instance_not_found``。

现在所有权以跨进程台账为准：只有台账里主人进程已死的实例才允许清。
这里守住四件事：别人的实例不动、自己的实例要清、没登记的不删、
主人死掉的尸体要删。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import batch_eval  # noqa: E402


class FakeResponse:
    """requests.Response 的最小替身。"""

    def __init__(self, status_code: int = 200, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self) -> dict:
        return self._payload


class FakeSession:
    """按调用顺序回放实例列表，并记录删了谁。

    ``vanish_after_get``: 被删的实例在第 N 次列表读取后从列表里消失，
    用来验证轮询等的是"被删的那几个"而不是"列表为空"。
    """

    def __init__(self, items: list[dict], vanish_after_get: int = 1) -> None:
        self.items = [dict(i) for i in items]
        self.deleted: list[str] = []
        self.get_calls = 0
        self._vanish_after = vanish_after_get

    def get(self, url: str, timeout: int = 40) -> FakeResponse:
        self.get_calls += 1
        if self.deleted and self.get_calls > self._vanish_after:
            self.items = [i for i in self.items if i["id"] not in self.deleted]
        return FakeResponse(200, {"items": self.items})

    def delete(self, url: str, timeout: int = 90) -> FakeResponse:
        self.deleted.append(url.rsplit("/", 1)[-1])
        return FakeResponse(200)


#: 一个必然不存在的 pid：Linux 上超过 pid_max、Windows 上 OpenProcess 直接失败。
DEAD_PID = 2**31 - 1


@pytest.fixture()
def no_sleep(monkeypatch):
    """轮询里的 3 秒等待对单测没有信息量，直接跳过。"""
    monkeypatch.setattr(batch_eval.time, "sleep", lambda _s: None)


@pytest.fixture()
def isolated_ledger(_isolated_instance_ledger):
    """conftest 的隔离台账路径（不用 tmp_path：本机 pytest-of-* 有 WinError 5 前科）。"""
    return Path(_isolated_instance_ledger)


def _client(session: FakeSession, started_at: float | None = None) -> batch_eval.Client:
    client = batch_eval.Client("token-not-real")
    client.s = session
    if started_at is not None:
        client.started_at = started_at
    return client


def _write_ledger(entries: dict) -> None:
    path = Path(batch_eval._ledger_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"instances": entries}), encoding="utf-8")


def test_reap_leaves_brother_lane_instances_alone(no_sleep) -> None:
    """账号下别的实例是兄弟车道，不是残留。"""
    session = FakeSession(
        [
            {"id": "mine", "status": "ready"},
            {"id": "brother", "status": "ready"},
        ]
    )
    client = _client(session)
    client.owned.add("mine")

    reaped = client.reap_orphans()

    assert reaped == ["mine"]
    assert session.deleted == ["mine"]
    assert client.owned == set(), "清完要从台账里划掉"


def test_reap_with_nothing_owned_deletes_nothing(no_sleep) -> None:
    """默认范围只认本进程台账；台账空就一个都不碰。"""
    session = FakeSession([{"id": "brother", "status": "ready"}])

    assert _client(session).reap_orphans() == []
    assert session.deleted == []


def test_reap_with_stale_scope_deletes_only_dead_owner_instances(no_sleep) -> None:
    """撞上配额时按台账清尸体：主人进程死了才删，活着的兄弟不动。

    三个实例创建时刻完全相同（并行起跑），旧实现会把 brother 一起删掉。
    """
    session = FakeSession(
        [
            {"id": "corpse", "status": "ready", "created_at": 1_000.0},
            {"id": "brother", "status": "ready", "created_at": 1_000.0},
            {"id": "stranger", "status": "ready", "created_at": 1_000.0},
        ]
    )
    client = _client(session, started_at=2_000.0)
    now = batch_eval.time.time()
    _write_ledger(
        {
            "corpse": {"pid": DEAD_PID, "ts": now},
            "brother": {"pid": os.getpid(), "ts": now},
        }
    )

    reaped = client.reap_orphans(include_stale=True)

    assert reaped == ["corpse"]
    assert session.deleted == ["corpse"], "兄弟车道与未登记实例都必须留着"


def test_reap_with_stale_scope_ignores_unregistered_instances(no_sleep) -> None:
    """没登记的实例证明不了是尸体——等 TTL，也比误杀并行车道强。"""
    session = FakeSession([{"id": "unknown", "status": "ready", "created_at": 1_000.0}])

    assert _client(session, started_at=1e9).reap_orphans(include_stale=True) == []
    assert session.deleted == []


def test_reap_waits_for_own_instances_not_for_empty_list(no_sleep) -> None:
    """并行时兄弟实例一直都在；等列表空等于每轮白等一分钟。"""
    session = FakeSession(
        [
            {"id": "mine", "status": "ready"},
            {"id": "brother", "status": "ready"},
        ]
    )
    client = _client(session)
    client.owned.add("mine")

    client.reap_orphans()

    assert session.get_calls == 2, "一次列清单 + 一次确认被删的消失即可返回"
    assert "brother" not in session.deleted


def test_launch_records_the_instance_it_created(no_sleep, isolated_ledger) -> None:
    """台账是清理的唯一依据，launch 成功就必须记上。"""
    client = batch_eval.Client("token-not-real")

    class PostSession(FakeSession):
        def post(self, url: str, json: dict | None = None, timeout: int = 120) -> FakeResponse:
            return FakeResponse(200, {"id": "fresh"})

    client.s = PostSession([])

    assert client.launch("SAMPLE-001") == "fresh"
    assert client.owned == {"fresh"}
    ledger = json.loads(isolated_ledger.read_text("utf-8"))
    assert ledger["instances"]["fresh"]["pid"] == os.getpid()


def test_teardown_forgets_the_instance(no_sleep, isolated_ledger) -> None:
    """删掉之后不该再被当成自己的残留重复清。"""
    session = FakeSession([])
    client = _client(session)
    client.owned.add("gone")
    batch_eval._ledger_record("gone")

    client.teardown("gone")

    assert client.owned == set()
    ledger = json.loads(isolated_ledger.read_text("utf-8"))
    assert "gone" not in ledger["instances"]


def test_ledger_dead_ids_reports_only_dead_owners() -> None:
    """活着的 pid 即使在台账里也不算尸体；死 pid 才算。"""
    _write_ledger(
        {
            "dead": {"pid": DEAD_PID, "ts": batch_eval.time.time()},
            "alive": {"pid": os.getpid(), "ts": batch_eval.time.time()},
        }
    )

    assert batch_eval._ledger_dead_ids() == {"dead"}


def test_pid_alive_never_reports_zero_or_negative() -> None:
    """pid<=0 一律当死；Windows 上还得走 OpenProcess 而不是 TerminateProcess。"""
    assert batch_eval._pid_alive(0) is False
    assert batch_eval._pid_alive(-1) is False
    assert batch_eval._pid_alive(os.getpid()) is True


ISO_EPOCH = 1_794_477_600.0  # 2026-11-12T10:00:00Z


@pytest.mark.parametrize(
    ("inst", "expected"),
    [
        ({"created_at": 1_700_000_000.5}, 1_700_000_000.5),
        ({"createdAt": 1_700_000_000}, 1_700_000_000.0),
        ({"started_at": "2026-11-12T10:00:00Z"}, ISO_EPOCH),
        ({"launched_at": "2026-11-12T10:00:00+00:00"}, ISO_EPOCH),
        ({"created_at": "1700000000"}, 1_700_000_000.0),
        ({}, None),
        ({"created_at": "not a time"}, None),
    ],
)
def test_instance_created_at_tolerates_every_spelling(inst: dict, expected: float | None) -> None:
    """平台没承诺字段名；解析不出来必须返回 None 而不是抛异常。"""
    got = batch_eval._instance_created_at(inst)

    if expected is None:
        assert got is None
    else:
        assert got == pytest.approx(expected, abs=1)
