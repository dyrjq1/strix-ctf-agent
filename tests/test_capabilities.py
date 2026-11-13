"""Shared installer: parity and failure visibility.

The regression this guards against is silent: the official entrypoint used
to skip the v2 primitives while the eval harness installed them, so a green
eval said nothing about the submitted image.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import capabilities  # noqa: E402


def test_installs_all_capabilities():
    installed, errors = capabilities.install_web_capabilities(
        http_register=lambda: ["http_probe"],
        discovery_register=lambda: ["route_map", "method_sweep"],
        variants_register=lambda: ["path_variants"],
        traffic_register=lambda: ["list_requests", "view_request"],
        web_cve_register=lambda: ["web_cve_lookup"],
    )

    assert errors == []
    assert installed == {
        "http_probe": ["http_probe"],
        "discovery": ["route_map", "method_sweep"],
        "variants": ["path_variants"],
        "traffic": ["list_requests", "view_request"],
        "web_cve": ["web_cve_lookup"],
    }


def test_one_failure_does_not_skip_the_other():
    def boom():
        raise RuntimeError("registry closed")

    installed, errors = capabilities.install_web_capabilities(
        http_register=boom,
        discovery_register=lambda: ["route_map"],
        variants_register=lambda: ["path_variants"],
        traffic_register=lambda: ["list_requests", "view_request"],
        web_cve_register=lambda: ["web_cve_lookup"],
    )

    assert installed["http_probe"] == []
    assert installed["discovery"] == ["route_map"]
    assert installed["variants"] == ["path_variants"]
    assert installed["traffic"] == ["list_requests", "view_request"]
    assert installed["web_cve"] == ["web_cve_lookup"]
    assert len(errors) == 1
    assert "registry closed" in errors[0]


def test_soft_deadline_disabled_when_non_positive():
    assert capabilities.install_soft_deadline(0, 25) is None
    assert capabilities.install_soft_deadline(-1, 25) is None


def test_soft_deadline_builds_guard(monkeypatch):
    captured = {}

    class FakeGuard:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("ctf_strix.deadline_guard.DeadlineGuard", FakeGuard)
    monkeypatch.setattr("ctf_strix.deadline_guard.install", lambda guard: guard)

    guard = capabilities.install_soft_deadline(300, 25)

    assert isinstance(guard, FakeGuard)
    assert captured["soft"] == 300
    assert captured["turns"] == 25
    # 硬上限仍由这里给（soft*2）；停滞/宽限的阈值不归子进程管，已随
    # should_kill() 一起删除，判定只在父进程看门狗里有一份。
    assert captured["wall"] == 600
