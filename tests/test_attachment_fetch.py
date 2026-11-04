"""Platform attachment fetch: the QA-only path must stop exiting at no_target.

The platform does not copy attachments into the container (verified run: the
work dir held only ``mcp.json`` / ``README.md`` / ``result.json`` /
``task.json``), and ``task.json`` may advertise ``"attachments": []`` even when
the challenge has files.  The player REST API is authoritative, so ``main()``
fetches before deciding the challenge kind.

Every test uses a real loopback HTTP server rather than a mock: the parts that
break are the exact URL shape, the bearer header, and what happens when a
non-200 body is read anyway.  A mock would prove none of those.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from ctf_strix import agent


class _StubPlatform:
    """A tiny player-API stand-in: ``/attachments`` list + per-file download."""

    def __init__(
        self,
        files: dict[str, bytes] | None = None,
        *,
        list_status: int = 200,
        download_status: dict[str, int] | None = None,
        delay: float = 0.0,
    ) -> None:
        self.files = files or {}
        self.list_status = list_status
        self.download_status = download_status or {}
        self.delay = delay
        self.requests: list[tuple[str, str | None]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "_StubPlatform":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def _handler(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                if stub.delay:
                    import time

                    time.sleep(stub.delay)
                stub.requests.append((self.path, self.headers.get("Authorization")))
                prefix = "/api/v1/challenges/CHAL/attachments"
                if self.path == prefix:
                    body = json.dumps(
                        {
                            "files": [
                                {"name": name, "size": len(blob), "per_team": False}
                                for name, blob in stub.files.items()
                            ]
                        }
                    ).encode()
                    self._respond(stub.list_status, body, "application/json")
                    return
                if self.path.startswith(prefix + "/"):
                    name = self.path[len(prefix) + 1 :]
                    if name in stub.files:
                        self._respond(
                            stub.download_status.get(name, 200),
                            stub.files[name],
                            "application/octet-stream",
                        )
                        return
                self._respond(404, b"not found", "text/plain")

            def _respond(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler


def _task(platform_url: str, **extra: object) -> dict:
    task = {
        "run_mode": "qa",
        "challenge": {"id": "CHAL", "name": "sample", "description": ""},
        "questions": [{"id": "flag", "prompt": "p"}],
        "platform_url": platform_url,
        "scope": [],
        "target_instance": None,
        "target_endpoints": [],
        "attachments": [],
    }
    task.update(extra)
    return task


def _prepare(monkeypatch, tmp_path: Path, task: dict, runtime) -> None:
    """Lay out a container work dir and neutralise the host environment."""
    (tmp_path / "task.json").write_text(json.dumps(task), encoding="utf-8")
    (tmp_path / "README.md").write_text("player API is available", encoding="utf-8")
    (tmp_path / "mcp.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CTFY_WORK_DIR", str(tmp_path))
    for key in (
        "CTFY_EVAL_DRY_RUN",
        "CTFY_WALL_DEADLINE",
        "CTFY_SOFT_DEADLINE",
        "CTFY_TARGET_URL",
        "CTFY_PLATFORM_URL",
        "CTFY_EVAL_CHALLENGE_ID",
        "CTFY_TOKEN",
        "CTF_PLATFORM_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(agent, "_run_agent", runtime)


def _run_main(monkeypatch, tmp_path: Path, task: dict) -> dict:
    """Run ``main()`` with a fake runtime and return the written result.json."""
    _prepare(monkeypatch, tmp_path, task, lambda *a, **k: (0, {}))
    try:
        assert agent.main() == 0
    finally:
        os.environ.pop("CTFY_SOFT_DEADLINE", None)
    return json.loads((tmp_path / "result.json").read_text(encoding="utf-8"))


def test_qa_task_without_target_fetches_attachments_and_runs_as_file(
    tmp_path: Path, monkeypatch
) -> None:
    """a. No target + empty attachment array, but the API has a file."""
    blob = b"PK\x03\x04 fake archive body"
    with _StubPlatform({"bundle.dat": blob}) as platform:
        task = _task(platform.url)
        payload = _run_main(monkeypatch, tmp_path, task)

    assert (tmp_path / "attachments" / "bundle.dat").read_bytes() == blob
    assert payload["stop_reason"] == "completed"
    assert "no_target" not in payload["writeup"]


def test_fetched_attachment_makes_kind_file(tmp_path: Path, monkeypatch) -> None:
    """a. The fetch must happen before the kind decision, not after."""
    seen: dict[str, object] = {}

    def _fake_run(task, answers, qid="flag", **kwargs):
        seen["kind"] = kwargs.get("kind")
        seen["attachments"] = list(kwargs.get("attachments") or [])
        return 0, {}

    with _StubPlatform({"evidence.txt": b"admin path is /console"}) as platform:
        _prepare(monkeypatch, tmp_path, _task(platform.url), _fake_run)
        try:
            assert agent.main() == 0
        finally:
            os.environ.pop("CTFY_SOFT_DEADLINE", None)

    assert seen["kind"] == "file"
    paths = [entry["workspace_path"] for entry in seen["attachments"]]
    assert "/workspace/attachments/evidence.txt" in paths


def test_targeted_challenge_still_fetches_attachments(
    tmp_path: Path, monkeypatch
) -> None:
    """b. Web/tcp challenges carry clues in attachments too; kind stays web."""
    seen: dict[str, object] = {}

    def _fake_run(task, answers, qid="flag", **kwargs):
        seen["kind"] = kwargs.get("kind")
        seen["attachments"] = list(kwargs.get("attachments") or [])
        return 0, {}

    with _StubPlatform({"notes.txt": b"slug: /admin"}) as platform:
        task = _task(
            platform.url,
            run_mode="instance",
            scope=[],
            target_instance="abc123",
            target_endpoints=[
                {"label": "web", "type": "http", "url": "http://127.0.0.1:9"}
            ],
        )
        _prepare(monkeypatch, tmp_path, task, _fake_run)
        try:
            assert agent.main() == 0
        finally:
            os.environ.pop("CTFY_SOFT_DEADLINE", None)

    assert (tmp_path / "attachments" / "notes.txt").read_text() == "slug: /admin"
    assert seen["kind"] == "web"
    paths = [entry["workspace_path"] for entry in seen["attachments"]]
    assert "/workspace/attachments/notes.txt" in paths


def test_empty_attachment_list_keeps_no_target(tmp_path: Path, monkeypatch) -> None:
    """c. Nothing on the platform means exactly the old behaviour."""
    with _StubPlatform({}) as platform:
        payload = _run_main(monkeypatch, tmp_path, _task(platform.url))

    assert payload["stop_reason"] == "no_target"
    assert "无可扫描目标" in payload["writeup"]
    assert not (tmp_path / "attachments").exists()


def test_download_forbidden_does_not_crash_and_keeps_no_target(
    tmp_path: Path, monkeypatch
) -> None:
    """d. A 403 on the file is a warning, not a crash, and not a fake success."""
    with _StubPlatform(
        {"secret.bin": b"nope"}, download_status={"secret.bin": 403}
    ) as platform:
        payload = _run_main(monkeypatch, tmp_path, _task(platform.url))

    assert payload["stop_reason"] == "no_target"
    assert not (tmp_path / "attachments" / "secret.bin").exists()
    assert not (tmp_path / "attachments").exists()


def test_list_timeout_does_not_crash_and_keeps_no_target(
    tmp_path: Path, monkeypatch
) -> None:
    """d. A stalled platform is bounded by the timeout and degrades cleanly."""
    monkeypatch.setattr(agent, "_ATTACHMENT_TIMEOUT", 0.2)
    with _StubPlatform({"slow.bin": b"late"}, delay=1.0) as platform:
        payload = _run_main(monkeypatch, tmp_path, _task(platform.url))

    assert payload["stop_reason"] == "no_target"
    assert not (tmp_path / "attachments").exists()


def test_fetch_sends_bearer_token_and_skips_when_local_files_exist(
    tmp_path: Path, monkeypatch
) -> None:
    """The fetch uses CTFY_TOKEN, and does not re-download existing attachments."""
    monkeypatch.setenv("CTFY_TOKEN", "tok-123")
    task = _task("http://unused.invalid")
    with _StubPlatform({"one.txt": b"1"}) as platform:
        task["platform_url"] = platform.url
        fetched = agent._fetch_platform_attachments(task, tmp_path)
        assert [p.name for p in fetched] == ["one.txt"]
        assert platform.requests[0][1] == "Bearer tok-123"
        before = len(platform.requests)

        again = agent._fetch_platform_attachments(task, tmp_path)
        assert again == []
        assert len(platform.requests) == before


def test_unsafe_attachment_name_is_refused(tmp_path: Path) -> None:
    """Attachment names come from the wire; ``../`` must not escape work/."""
    task = _task("http://unused.invalid")
    assert agent._safe_attachment_name("../../escape") is None
    assert agent._safe_attachment_name("dir/file") is None
    assert agent._safe_attachment_name("ok.txt") == "ok.txt"
    assert not (tmp_path / "escape").exists()


def test_missing_platform_url_makes_no_request(tmp_path: Path, monkeypatch) -> None:
    """No platform_url means no host to call: stay offline by construction."""
    task = _task("")
    with _StubPlatform({"x.txt": b"x"}) as platform:
        assert agent._platform_url(task) == ""
        assert agent._fetch_platform_attachments(task, tmp_path) == []
        assert platform.requests == []
    assert not (tmp_path / "attachments").exists()


def test_download_that_is_not_200_leaves_no_directory(tmp_path: Path) -> None:
    """A 500 body must never be written as if it were the attachment."""
    with _StubPlatform({"bad.bin": b"err"}, download_status={"bad.bin": 500}) as platform:
        task = _task(platform.url)
        assert agent._fetch_platform_attachments(task, tmp_path) == []
    assert not (tmp_path / "attachments").exists()


def test_declared_attachment_already_on_disk_is_not_downloaded(tmp_path: Path) -> None:
    """Platform-delivered files at the work root must not be fetched twice."""
    (tmp_path / "given.bin").write_bytes(b"original")
    task = _task("http://unused.invalid", attachments=[{"name": "given.bin"}])
    with _StubPlatform({"given.bin": b"from-api"}) as platform:
        task["platform_url"] = platform.url
        assert agent._fetch_platform_attachments(task, tmp_path) == []
        assert platform.requests == []
    assert (tmp_path / "given.bin").read_bytes() == b"original"
    assert not (tmp_path / "attachments").exists()


def test_partial_declared_attachments_trigger_the_fetch(tmp_path: Path) -> None:
    """One declared file missing means the API still has work to do."""
    (tmp_path / "have.bin").write_bytes(b"local")
    task = _task(
        "http://unused.invalid",
        attachments=[{"name": "have.bin"}, {"name": "missing.bin"}],
    )
    with _StubPlatform({"have.bin": b"api", "missing.bin": b"new"}) as platform:
        task["platform_url"] = platform.url
        fetched = agent._fetch_platform_attachments(task, tmp_path)

    assert [p.name for p in fetched] == ["missing.bin"]
    assert (tmp_path / "attachments" / "missing.bin").read_bytes() == b"new"
    assert (tmp_path / "have.bin").read_bytes() == b"local"


def test_declared_name_with_traversal_is_ignored_locally(tmp_path: Path) -> None:
    """A hostile task.json name must not be used to probe outside work/."""
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    task = _task("http://unused.invalid", attachments=[{"name": "../outside.txt"}])
    with _StubPlatform({"../outside.txt": b"x"}) as platform:
        task["platform_url"] = platform.url
        assert agent._fetch_platform_attachments(task, tmp_path) == []
    assert not (tmp_path / "attachments").exists()
