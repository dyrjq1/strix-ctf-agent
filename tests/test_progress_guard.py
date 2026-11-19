"""Stop a run whose probes stop producing new observations, across families.

## Why this file exists

The enumeration guards count *per family*.  The failure that actually burns a
run is the other shape: the model keeps moving -- new path, new tool, new
parameter -- and every single request returns the same Go ``404 page not
found`` or the same default index page.  Each family counter starts at one,
nothing fires, and the turn budget is spent without learning anything.

So the judge here is observation gain, not "did we get a flag": one
``_obs_signature`` seen again is no gain; a signature never seen is gain.  Six
consecutive probes without gain mark the stall and open a three-attempt dive;
three more without gain end the run.

These tests pin four things: the window fires on *identical observations even
across different families*, new information cancels the dive, the dive is what
ends the run, and neither the markers nor the exception carry a response body.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import negative_guard as ng  # noqa: E402
from ctf_strix import progress_guard as pg  # noqa: E402

#: Every URL below carries one of the business keywords the family extractor
#: looks for; without one, ``_fingerprint`` returns ``None`` and the call is not
#: judged at all (a local command, not a probe).
_ADMIN = "http://h.test/admin/panel"
_CONFIG = "http://h.test/config/panel"
_DEBUG = "http://h.test/debug/panel"
_STATIC = "http://h.test/static/panel"
_ASSETS = "http://h.test/assets/panel"
_API = "http://h.test/api/panel"
_FLAG = "http://h.test/flag/panel"

#: The same response an unconfigured reverse proxy returns for every path.
NOT_FOUND = "[HTTP 404] 0.01s\n404 page not found\n"
#: A response the run has never seen: head status differs, body differs.
LANDED = "[HTTP 200] 0.02s\n<html><body>console loaded</body></html>\n"
#: A third distinct observation, used to show gain resumes after a forced miss.
ERRORED = "[HTTP 500] 0.03s\nupstream connect error\n"

#: Window plus the one probe that first looks new.  Stated as a formula so the
#: test does not silently drift if the shared threshold changes.
_STALL_IN = pg._STALL_WINDOW + 1


def _args(url: str) -> str:
    """Probe arguments in the shape the http tool takes."""
    return json.dumps({"url": url})


def _exec_args(command: str) -> str:
    """Shell-tool arguments, the only shape the negative guard reads."""
    return json.dumps({"command": command})


def _drive(guard: pg.ProgressGuard, url: str, body: str, times: int):
    """Feed the same observation ``times`` times; return the last hint."""
    hint = None
    for _ in range(times):
        hint = guard.observe("http_probe", _args(url), body)
    return hint


@pytest.fixture(autouse=True)
def _clean_negative_groups():
    """Neither side of the coupling may leak a closed group into a test."""
    ng.reset_for_tests()
    yield
    ng.reset_for_tests()


@pytest.fixture
def guard(tmp_path):
    """A standalone guard with its own marker file (no global singleton)."""
    return pg.ProgressGuard(markers_path=str(tmp_path / "markers.jsonl"))


# -- the window fires on observations, not on families ---------------------


def test_identical_observations_open_a_dive_after_the_window(guard):
    hint = _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)

    assert guard.probes == _STALL_IN
    assert guard.fresh == 1  # only the first of them was news
    assert guard.streak == pg._STALL_WINDOW
    assert guard.deep_active is True
    assert guard.deep_left == pg._DEEP_DIVE_ROUNDS
    assert guard.marks == 1
    assert hint is not None and "[NO PROGRESS]" in hint
    assert f"{pg._DEEP_DIVE_ROUNDS} attempts left" in hint


def test_seven_families_returning_one_page_still_count_as_no_progress(guard):
    """The regression this guard exists for: a new family is not new information.

    Before the fix the seen-set was keyed by ``(family fingerprint, signature)``,
    so ten different paths were ten new observations and the guard never fired
    -- exactly the blind spot that made the per-family counters useless here.
    """
    urls = (_ADMIN, _CONFIG, _DEBUG, _STATIC, _ASSETS, _API, _FLAG)
    hints = [guard.observe("http_probe", _args(url), NOT_FOUND) for url in urls]

    assert guard.probes == len(urls)
    assert guard.fresh == 1
    assert guard.streak == len(urls) - 1
    assert guard.deep_active is True
    assert hints[-1] is not None and "[NO PROGRESS]" in hints[-1]


def test_a_new_observation_cancels_the_dive(guard):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)
    assert guard.deep_active is True

    assert guard.observe("http_probe", _args(_ADMIN), LANDED) is None

    assert guard.deep_active is False
    assert guard.deep_left == 0
    assert guard.streak == 0
    assert guard.fresh == 2
    assert guard.tripped is False


# -- the dive is what ends the run ----------------------------------------


def test_three_dive_attempts_without_gain_trip_the_guard(guard):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)

    first = guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    second = guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    assert first is not None and "2 focused attempt(s) left" in first
    assert second is not None and "1 focused attempt(s) left" in second
    assert guard.tripped is False

    third = guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)

    assert third is None  # the stop is the exception, not another hint
    assert guard.tripped is True
    assert guard.trip_stage == "deep_exhausted"
    assert guard.marks == 2
    assert guard.stats()["tripped"] is True


def test_the_stop_exception_carries_the_marked_probe_without_a_body(guard):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)
    for _ in range(pg._DEEP_DIVE_ROUNDS):
        guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    host, family, mechanism, signature = guard.last_probe

    exc = pg.NoProgress(guard.trip_detail(), stats=guard.stats(), host=host,
                        family=family, mechanism=mechanism, signature=signature)

    assert exc.host == "h.test"
    assert exc.family == "http://h.test/admin"
    assert exc.mechanism == "access-control"
    assert re.fullmatch(r"[0-9a-f]{12}", exc.signature)
    assert "no progress" in str(exc)
    assert "page not found" not in str(exc)
    assert "page not found" not in repr(exc.stats)


# -- what is written down -------------------------------------------------


def test_each_marker_carries_the_stall_facts_and_no_response_body(guard, tmp_path):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)

    text = (tmp_path / "markers.jsonl").read_text(encoding="utf-8")
    lines = text.splitlines()
    assert len(lines) == 1
    marker = json.loads(lines[0])

    assert set(marker) == {
        "ts", "host", "family", "mechanism", "signature",
        "streak", "fresh_rate", "probes", "stage",
    }
    assert marker["host"] == "h.test"
    assert marker["family"] == "http://h.test/admin"
    assert marker["mechanism"] == "access-control"
    assert re.fullmatch(r"[0-9a-f]{12}", marker["signature"])
    assert marker["stage"] == "stall"
    assert marker["streak"] == pg._STALL_WINDOW
    assert marker["probes"] == _STALL_IN
    assert "page not found" not in text
    assert "flag{" not in text.lower()


def test_the_trip_writes_a_second_marker_with_the_other_stage(guard, tmp_path):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)
    for _ in range(pg._DEEP_DIVE_ROUNDS):
        guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)

    stages = [
        json.loads(line)["stage"]
        for line in (tmp_path / "markers.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert stages == ["stall", "deep_exhausted"]


def test_no_marker_path_keeps_the_guard_in_memory_only():
    guard = pg.ProgressGuard(markers_path="")
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN)
    assert guard.marks == 1


# -- an answer outranks the guard -----------------------------------------


def test_recording_an_answer_clears_the_stall_state(guard):
    _drive(guard, _ADMIN, NOT_FOUND, _STALL_IN + pg._DEEP_DIVE_ROUNDS)
    assert guard.tripped is True

    guard.note_answer()

    assert guard.tripped is False
    assert guard.trip_stage == ""
    assert guard.streak == 0
    assert guard.deep_active is False
    assert guard.deep_left == 0
    fresh_before = guard.fresh
    guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    assert guard.fresh == fresh_before + 1  # the same page is news again


# -- guard scoping ---------------------------------------------------------


def test_calls_that_do_not_reach_a_target_are_not_judged(guard):
    quiet = [
        guard.observe("think", '{"thought": "the 404 body is the same"}', "ok"),
        guard.observe("exec_command", _exec_args("ls -la /tmp"), "a\nb\n"),
        guard.observe("exec_command", _exec_args("curl -sS http://h.test/healthz"), "ok"),
        guard.observe("http_probe", _args("http://h.test/healthz"), "ok"),
    ]

    assert quiet == [None, None, None, None]
    assert guard.probes == 0


def test_a_closed_negative_evidence_group_forces_a_miss(guard, monkeypatch):
    """Two independent judges: a new-looking response can still be a dead end."""

    class _Stub:
        def __init__(self) -> None:
            self.n = 0

        def stuck_groups(self):
            return [(f"args{i}", f"sha{i}") for i in range(self.n)]

    stub = _Stub()
    monkeypatch.setattr(ng, "current", lambda: stub)

    guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    assert guard.fresh == 1

    stub.n = 1  # a group closed: the previous call was a dead end
    guard.observe("http_probe", _args(_CONFIG), LANDED)
    assert guard.fresh == 1
    assert guard.streak == 1
    # A forced observation still enters the seen-set: the dead end is part of
    # what this run now knows, so returning to it is no gain either.
    guard.observe("http_probe", _args(_DEBUG), LANDED)
    assert guard.fresh == 1
    assert guard.streak == 2

    guard.observe("http_probe", _args(_DEBUG), ERRORED)
    assert guard.fresh == 2  # a genuinely new body, with no new closed group
    assert guard.streak == 0


# -- the other half of the coupling: stuck_groups() -----------------------


def test_a_group_closes_only_at_the_third_identical_response():
    guard = ng.NegativeEvidenceGuard()
    args = _exec_args("curl -sS http://h.test/admin")

    assert guard.observe("exec_command", args, "same body") is None
    assert guard.observe("exec_command", args, "same body") is None
    assert guard.stuck_groups() == []

    hint = guard.observe("exec_command", args, "same body")

    assert hint is not None and "NEGATIVE EVIDENCE GUARD" in hint
    assert len(guard.stuck_groups()) == 1


def test_a_different_response_keeps_the_group_open():
    guard = ng.NegativeEvidenceGuard()
    args = _exec_args("curl -sS http://h.test/admin")

    for body in ("one", "one", "two"):
        guard.observe("exec_command", args, body)

    assert guard.stuck_groups() == []


def test_groups_past_the_injection_ceiling_still_report_as_stuck():
    """'Count but do not nag': silent groups must stay visible to the caller."""
    guard = ng.NegativeEvidenceGuard()
    groups = ng.LIMITS[ng.L4] + 1

    last = None
    for index in range(groups):
        args = _exec_args(f"curl -sS http://h.test/admin{index}")
        for _ in range(ng.K):
            last = guard.observe("exec_command", args, "same body")

    assert last is None  # the ceiling is spent, so the third group is silent
    assert len(guard.stuck_groups()) == groups
    assert guard.stats()["injections"] == ng.LIMITS[ng.L4]


# -- every ending leaves a marker, not just the stalled ones ---------------


def _last_marker(tmp_path: Path) -> dict:
    lines = (tmp_path / "markers.jsonl").read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1])


def test_a_wallclock_stop_leaves_a_marker_although_nothing_tripped(guard, tmp_path):
    """wallclock 从不触发停滞判据，但下一轮必须有东西可读。

    2026-11-19：三道题全部以 wallclock 收场，盒子里一个 markers 文件都没有
    （``observe`` 只在判据响的时候落盘），重试提示因此只剩「收场：wallclock」。
    """
    guard.observe("http_probe", _args(_ADMIN), NOT_FOUND)
    assert guard.tripped is False

    guard.record_stop("wallclock")

    marker = _last_marker(tmp_path)
    assert marker["stage"] == "stop:wallclock"
    assert marker["host"] == "h.test"
    assert marker["probes"] == 1
    assert marker["cards_state"] in {"no_menu", "menu_no_pick", "picked", "unknown"}
    assert "page not found" not in json.dumps(marker, ensure_ascii=False)


def test_the_stop_marker_lists_the_paths_already_tried(guard, tmp_path, monkeypatch):
    """下一轮的原罪是重复踩坑：标记必须带上去重后的请求面。"""
    from ctf_strix import traffic

    monkeypatch.setattr(traffic, "_LEDGER", traffic.TrafficLedger(None))
    traffic.record(
        request_id="r1", method="GET", url="http://h.test/admin/panel", status=404
    )
    traffic.record(
        request_id="r2",
        method="POST",
        url="http://h.test/api/login?token=abc",
        status=401,
    )
    traffic.record(
        request_id="r3", method="GET", url="http://h.test/admin/panel", status=404
    )

    guard.record_stop("wallclock")

    marker = _last_marker(tmp_path)
    assert marker["tried"] == ["GET /admin/panel→404", "POST /api/login→401"]
    assert "token" not in json.dumps(marker, ensure_ascii=False)
    assert marker["surface"].startswith("GET /admin/panel → 404")
    assert "404×2" in marker["surface"]


def test_a_session_like_path_segment_is_masked(guard, tmp_path, monkeypatch):
    """路径要进下一轮提示，长串（会话号/密钥）不进任何落盘文件。"""
    from ctf_strix import traffic

    monkeypatch.setattr(traffic, "_LEDGER", traffic.TrafficLedger(None))
    traffic.record(
        request_id="r1",
        method="GET",
        url="http://h.test/reset/abcdef0123456789abcdef0123456789",
        status=200,
    )

    guard.record_stop("wallclock")

    text = json.dumps(_last_marker(tmp_path), ensure_ascii=False)
    assert "abcdef0123456789abcdef0123456789" not in text
    assert "…" in text


def test_the_stop_marker_records_the_picked_method_cards(guard, tmp_path, monkeypatch):
    """「选了什么方法卡」是失败描述的另一半。"""
    from ctf_strix import card_menu, card_pick, method_cards

    monkeypatch.setattr(card_menu, "_GUARD", None)
    monkeypatch.delenv("CTF_CARDS_STATE", raising=False)
    pool = method_cards.pool("web", "", ["sqli"])[:2]
    card_pick.set_pool(pool)
    try:
        card_pick._pick([pool[0].cid])

        guard.record_stop("turn_capped")

        marker = _last_marker(tmp_path)
        assert marker["cards"] == [pool[0].cid]
        assert marker["cards_state"] == "picked"
    finally:
        card_pick.set_pool([])


def test_a_menu_that_was_never_shown_is_not_reported_as_a_refusal(
    guard, tmp_path, monkeypatch
):
    """「没摆菜单」和「摆了没点」是两种失败，混成一个空列表就分不开了。"""
    from ctf_strix import card_menu, card_pick

    monkeypatch.setattr(card_menu, "_GUARD", None)
    card_pick.set_pool([])

    guard.record_stop("wallclock")

    assert _last_marker(tmp_path)["cards_state"] == "no_menu"