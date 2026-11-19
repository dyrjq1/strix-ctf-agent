# -*- coding: utf-8 -*-
"""The official entry has no tags in task.json; it asks the platform once.

Without this the tag-keyed card block is empty on every scored competition run
(the harness path gets ``--tags``; ``agent.py`` had nothing to pass).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from ctf_strix import agent


class _Resp:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def read(self, _n: int = -1) -> bytes:
        return self._payload

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


@pytest.fixture
def platform_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CTFY_PLATFORM_URL", "https://ctfy.example/api-root/")
    monkeypatch.setenv("CTFY_TOKEN", "tok-1")
    monkeypatch.delenv("CTF_PLATFORM_TOKEN", raising=False)


TASK = {"challenge": {"id": "DEMO-001", "name": "x", "description": "y"}}


def test_reads_tags_from_the_detail_endpoint(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, object] = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        seen["auth"] = req.get_header("Authorization")
        seen["timeout"] = timeout
        return _Resp(json.dumps({"data": {"tags": ["ssrf", " cve_2021_41773 "]}}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert agent._platform_tags(TASK) == ["ssrf", "cve_2021_41773"]
    assert seen["url"] == "https://ctfy.example/api-root/api/v1/challenges/DEMO-001"
    assert seen["auth"] == "Bearer tok-1"
    assert seen["timeout"] == 8


def test_accepts_a_bare_payload_without_the_data_wrapper(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(json.dumps({"tags": ["idor"]}).encode()),
    )
    assert agent._platform_tags(TASK) == ["idor"]


def test_no_credentials_means_no_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CTFY_PLATFORM_URL", raising=False)
    monkeypatch.delenv("CTFY_TOKEN", raising=False)
    monkeypatch.delenv("CTF_PLATFORM_TOKEN", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("must not call the network without credentials")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert agent._platform_tags(TASK) == []


def test_transport_errors_degrade_to_no_tags(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a, **_k):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert agent._platform_tags(TASK) == []


def test_a_non_list_tags_field_is_ignored(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(json.dumps({"data": {"tags": "web"}}).encode()),
    )
    assert agent._platform_tags(TASK) == []


def test_garbage_bodies_degrade_to_no_tags(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(b"<html>502 bad gateway</html>"),
    )
    assert agent._platform_tags(TASK) == []


def test_category_comes_back_from_the_same_request(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """task.json carries no category either; the fallback card keys on it."""
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(
            json.dumps({"data": {"tags": ["heap"], "category": "Pwn"}}).encode()
        ),
    )
    assert agent._platform_meta(TASK) == (["heap"], "Pwn")


def test_a_non_string_category_is_dropped(
    platform_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _Resp(
            json.dumps({"data": {"tags": [], "category": {"id": 3}}}).encode()
        ),
    )
    assert agent._platform_meta(TASK) == ([], "")


def test_the_hint_uses_it_only_when_the_task_carries_no_tags() -> None:
    src = agent.__file__
    with open(src, encoding="utf-8") as fh:
        text = fh.read()
    assert "tags = skillpack.tags_of(task)" in text
    assert "tags, declared = _platform_meta(task)" in text