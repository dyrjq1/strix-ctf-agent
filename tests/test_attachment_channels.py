"""Attachment channel degradation, verified against a real loopback server.

The failures this file exists for are transport-shaped: which URL is probed,
which header is sent, whether a ``data:`` field split across lines is joined
before parsing, and whether a listing with one forbidden file still lets the
next channel finish the job.  A mock proves none of that, so every test binds
an HTTP server on ``127.0.0.1`` and lets the real client talk to it.

The fallback contract is *per file*: a failed download for one name must not
discard the names that did arrive, and an existing file in ``attachments/``
must not hide the ones the listing says are missing.
"""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf_strix import agent
from ctf_strix import platform_attach as attach

TOKEN = "tok-secret-123"


class _Server:
    """One loopback HTTP server with a user-supplied request handler."""

    def __init__(self, handler_factory) -> None:
        self.requests: list[dict] = []
        # Handler factories may hang state off the server (the MCP stub keeps
        # the calls it saw); keep it reachable from the ``with`` target.
        self.state = getattr(handler_factory, "state", None)
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(self))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "_Server":
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _read_body(handler: BaseHTTPRequestHandler) -> bytes:
    length = int(handler.headers.get("Content-Length") or 0)
    return handler.rfile.read(length) if length else b""


def _respond(handler: BaseHTTPRequestHandler, status: int, body: bytes, ctype: str,
             extra: dict[str, str] | None = None) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    for key, value in (extra or {}).items():
        handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def _rest_handler(server: "_Server", files: dict[str, bytes], *,
                  list_status: int = 200,
                  download_status: dict[str, int] | None = None,
                  list_override: bytes | None = None,
                  instance_files: dict[str, bytes] | None = None,
                  delay: float = 0.0):
    download_status = download_status or {}
    instance_files = instance_files or {}
    prefix = "/api/v1/challenges/CHAL/attachments"
    inst_prefix = "/api/v1/instances/INST/attachments"

    def factory(srv: "_Server"):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                if delay:
                    time.sleep(delay)
                srv.requests.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "accept": self.headers.get("Accept"),
                    }
                )
                if self.path == inst_prefix:
                    body = json.dumps(
                        {"files": [{"name": n, "size": len(b), "per_team": True}
                                   for n, b in instance_files.items()]}
                    ).encode()
                    _respond(self, 200, body, "application/json")
                    return
                if self.path.startswith(inst_prefix + "/"):
                    name = self.path[len(inst_prefix) + 1:]
                    if name in instance_files:
                        _respond(self, 200, instance_files[name], "application/octet-stream")
                        return
                if self.path == prefix:
                    if list_override is not None:
                        _respond(self, list_status, list_override, "application/json")
                        return
                    body = json.dumps(
                        {"files": [{"name": n, "size": len(b), "per_team": False}
                                   for n, b in files.items()]}
                    ).encode()
                    _respond(self, list_status, body, "application/json")
                    return
                if self.path.startswith(prefix + "/"):
                    name = self.path[len(prefix) + 1:]
                    if name in files:
                        _respond(self, download_status.get(name, 200), files[name],
                                 "application/octet-stream")
                        return
                _respond(self, 404, b"not found", "text/plain")

        return Handler

    return factory


class _Mcp:
    """State for an MCP-shaped loopback server.

    ``__call__`` lets an instance be handed to :class:`_Server` like the plain
    handler factories used by the REST stub.
    """

    def __init__(self, *, listing=None, downloads=None, status: int = 200,
                 transport: str = "sse-inline", rpc_error: bool = False,
                 is_error: bool = False, wrong_id: bool = False,
                 split_data: bool = False, delay: float = 0.0,
                 auth_status: int | None = None,
                 auth_body: bytes | None = None,
                 resource_downloads: dict[str, bytes] | None = None) -> None:
        self.listing = listing if listing is not None else []
        self.downloads = downloads or {}
        self.status = status
        self.transport = transport
        self.rpc_error = rpc_error
        self.is_error = is_error
        self.wrong_id = wrong_id
        self.split_data = split_data
        self.delay = delay
        self.auth_status = auth_status
        self.auth_body = auth_body
        self.resource_downloads = resource_downloads or {}
        self.calls: list[tuple[str, dict]] = []
        self.server: _Server | None = None
        self.state = self

    def _tool_result(self, name: str, args: dict) -> dict:
        self.calls.append((name, args))
        if self.rpc_error:
            return {"error": {"code": -32602, "message": "invalid params"}}
        if name == "list_challenge_attachments":
            payload = {"files": self.listing}
        elif name == "download_challenge_attachment":
            filename = str(args.get("filename"))
            if filename in self.resource_downloads:
                blob = self.resource_downloads[filename]
                return {"result": {
                    "content": [{"type": "resource", "resource": {
                        "uri": f"file:///{filename}",
                        "blob": base64.b64encode(blob).decode(),
                    }}],
                    "isError": False,
                }}
            payload = self.downloads.get(args.get("filename"), {})
        else:
            payload = {}
        if self.is_error:
            return {"result": {"content": [{"type": "text", "text": "denied"}],
                               "isError": True}}
        return {
            "result": {
                "content": [{"type": "text", "text": json.dumps(payload)}],
                "structuredContent": payload,
                "isError": False,
            }
        }

    def __call__(self, srv: "_Server"):
        mcp = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:  # noqa: D401
                pass

            def do_POST(self) -> None:  # noqa: N802 - http.server API
                body = _read_body(self)
                try:
                    request = json.loads(body.decode("utf-8"))
                except ValueError:
                    _respond(self, 400, b"bad json", "text/plain")
                    return
                if mcp.delay:
                    time.sleep(mcp.delay)
                srv.requests.append(
                    {
                        "path": self.path,
                        "auth": self.headers.get("Authorization"),
                        "accept": self.headers.get("Accept"),
                        "request": request,
                    }
                )
                if mcp.auth_status is not None:
                    _respond(self, mcp.auth_status,
                             mcp.auth_body or b"forbidden", "text/plain")
                    return
                method = request.get("method")
                rid = request.get("id")
                if method == "notifications/initialized":
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if method == "initialize":
                    response = {"jsonrpc": "2.0", "id": rid,
                                "result": {"protocolVersion": "2025-06-18",
                                           "capabilities": {},
                                           "serverInfo": {"name": "stub", "version": "0"}}}
                elif method == "tools/call":
                    params = request.get("params") or {}
                    response = mcp._tool_result(params.get("name"), params.get("arguments") or {})
                    response = {"jsonrpc": "2.0", "id": rid, **response}
                else:
                    response = {"jsonrpc": "2.0", "id": rid,
                                "error": {"code": -32601, "message": "unknown"}}
                if mcp.wrong_id:
                    response["id"] = (rid or 0) + 100
                encoded = json.dumps(response).encode()
                if mcp.transport == "json":
                    _respond(self, mcp.status, encoded, "application/json")
                    return
                if mcp.transport == "html":
                    _respond(self, mcp.status, b"<html>bad gateway</html>", "text/html")
                    return
                if mcp.split_data:
                    # One JSON document spread across several data: lines, as
                    # a pretty-printing server emits it.  The receiver must
                    # join the lines with "\n" before parsing.
                    lines = json.dumps(response, indent=1).splitlines()
                    payload = (
                        "event: message\n"
                        + "\n".join(f"data: {line}" for line in lines)
                        + "\n\n"
                    ).encode()
                else:
                    payload = b"event: message\ndata: " + encoded + b"\n\n"
                _respond(self, mcp.status, payload, "text/event-stream")

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


def _write_mcp(work: Path, url: str, *, token: str = "${CTFY_TOKEN}") -> None:
    config = {
        "mcpServers": {
            "ctfy": {
                "type": "http",
                "url": url,
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    }
    (work / "mcp.json").write_text(json.dumps(config), encoding="utf-8")


def _base_blob(blob: bytes) -> dict:
    return {
        "filename": "x",
        "size": len(blob),
        "encoding": "base64",
        "content": base64.b64encode(blob).decode(),
    }


def _text_blob(blob: bytes) -> dict:
    text = blob.decode("utf-8")
    return {
        "filename": "x",
        "size": len(blob),
        "encoding": "utf-8",
        "content": text,
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("CTFY_TOKEN", TOKEN)
    for key in ("CTFY_PLATFORM_URL", "CTFY_EVAL_CHALLENGE_ID",
                "CTFY_EVAL_TARGET_INSTANCE"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def _fetch(task: dict, work: Path) -> list[Path]:
    return agent._fetch_platform_attachments(task, work)


def test_rest_success_never_touches_mcp(tmp_path: Path) -> None:
    """a. Full REST success must not spend a request on MCP."""
    blob = b"PK\x03\x04 full archive"
    with _Server(_rest_handler(None, {"archive.zip": blob})) as rest, \
            _Server(_Mcp(listing=[{"name": "archive.zip", "size": len(blob)}])) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert [p.name for p in written] == ["archive.zip"]
    assert (tmp_path / "attachments" / "archive.zip").read_bytes() == blob
    assert mcp.requests == []
    assert rest.requests[0]["auth"] == f"Bearer {TOKEN}"


def test_one_forbidden_download_is_completed_by_mcp(tmp_path: Path) -> None:
    """b. Listing succeeded; only the rejected file goes to the next channel."""
    with _Server(_rest_handler(
        None,
        {"good.txt": b"kept", "blocked.bin": b"secret-bytes"},
        download_status={"blocked.bin": 403},
    )) as rest, _Server(_Mcp(
        listing=[{"name": "good.txt", "size": 4},
                 {"name": "blocked.bin", "size": 12}],
        downloads={"blocked.bin": _base_blob(b"secret-bytes")},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert sorted(p.name for p in written) == ["blocked.bin", "good.txt"]
    assert (tmp_path / "attachments" / "good.txt").read_bytes() == b"kept"
    assert (tmp_path / "attachments" / "blocked.bin").read_bytes() == b"secret-bytes"
    # MCP was asked for the missing file only, and did not re-list.
    assert [name for name, _ in mcp.state.calls] == ["download_challenge_attachment"]
    assert mcp.state.calls[0][1]["filename"] == "blocked.bin"


def test_rest_403_falls_back_to_mcp_listing_and_two_shapes(tmp_path: Path) -> None:
    """c. 403 listing: MCP lists, then base64 and text payloads both land."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "bin.dat", "size": 3}, {"name": "note.txt", "size": 5}],
        downloads={"bin.dat": _base_blob(b"\x00\x01\x02"),
                   "note.txt": _text_blob(b"hello")},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert sorted(p.name for p in written) == ["bin.dat", "note.txt"]
    assert (tmp_path / "attachments" / "bin.dat").read_bytes() == b"\x00\x01\x02"
    assert (tmp_path / "attachments" / "note.txt").read_bytes() == b"hello"
    assert [name for name, _ in mcp.state.calls] == [
        "list_challenge_attachments",
        "download_challenge_attachment",
        "download_challenge_attachment",
    ]


def test_empty_rest_listing_uses_declared_names_on_mcp(tmp_path: Path) -> None:
    """A 200 empty list does not erase names task.json already declared."""
    with _Server(_rest_handler(None, {})) as rest, _Server(_Mcp(
        downloads={"declared.bin": _base_blob(b"declared")},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        task = _task(rest.url, attachments=[{"name": "declared.bin"}])
        written = _fetch(task, tmp_path)

    assert [p.name for p in written] == ["declared.bin"]
    assert (tmp_path / "attachments" / "declared.bin").read_bytes() == b"declared"
    assert [name for name, _ in mcp.state.calls] == ["download_challenge_attachment"]


def test_rest_403_mcp_resource_blob_shape(tmp_path: Path) -> None:
    """c. A ``resource.blob`` block carries base64 by structure, over the wire."""
    blob = b"\x89PNG\r\n"
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "pic.png", "size": len(blob)}],
        resource_downloads={"pic.png": blob},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert [p.name for p in written] == ["pic.png"]
    assert (tmp_path / "attachments" / "pic.png").read_bytes() == blob


def test_mcp_plain_json_transport_is_accepted(tmp_path: Path) -> None:
    """d. A server may answer with application/json instead of SSE."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "a.txt", "size": 1}],
        downloads={"a.txt": _text_blob(b"a")},
        transport="json",
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path)[0].name == "a.txt"
    assert (tmp_path / "attachments" / "a.txt").read_bytes() == b"a"


def test_mcp_sse_multi_line_data_is_reassembled(tmp_path: Path) -> None:
    """d. A data field split across lines must be joined before parsing."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "a.txt", "size": 1}],
        downloads={"a.txt": _text_blob(b"a")},
        split_data=True,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path)[0].name == "a.txt"


def test_mcp_json_rpc_error_is_a_failure(tmp_path: Path) -> None:
    """d. A JSON-RPC error object must not be read as a listing."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        rpc_error=True,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []
    assert not (tmp_path / "attachments").exists()


def test_mcp_is_error_result_is_a_failure(tmp_path: Path) -> None:
    """d. isError:true is an explicit failure even with HTTP 200."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "a.txt", "size": 1}],
        downloads={"a.txt": _text_blob(b"a")},
        is_error=True,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []


def test_mcp_id_mismatch_is_a_failure(tmp_path: Path) -> None:
    """d. A response for another request id must never be consumed."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "a.txt", "size": 1}],
        downloads={"a.txt": _text_blob(b"a")},
        wrong_id=True,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []


def test_mcp_html_error_page_is_a_failure(tmp_path: Path) -> None:
    """d. A 200 HTML gateway page is not JSON and must not crash the run."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        transport="html",
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []


def test_mcp_403_logs_both_levels_and_returns_empty(tmp_path: Path, capsys) -> None:
    """e. Two channels refused: no exception, and both failures logged."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        auth_status=403,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []
    out = capsys.readouterr().out
    assert "rest-challenge" in out and "HTTP 403" in out
    # The MCP failure must name the channel and the status, so a future run
    # can tell "token rejected here" from "endpoint unreachable".
    assert "channel=mcp" in out
    # The error detail precedes the channel summary line; grep the whole log.
    assert "mcp: list" in out
    assert "HTTP 403" in out.split("mcp: list", 1)[1]


def test_rest_timeout_still_leaves_mcp_a_usable_slice(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """e. REST gets half the budget; the remainder is enough for MCP."""
    monkeypatch.setattr(agent, "_ATTACHMENT_TIMEOUT", 1.0)
    with _Server(_rest_handler(None, {"late.txt": b"late"}, delay=0.8)) as rest, \
            _Server(_Mcp(listing=[{"name": "late.txt", "size": 4}],
                         downloads={"late.txt": _text_blob(b"late")})) as mcp:
        _write_mcp(tmp_path, mcp.url)
        started = time.monotonic()
        written = _fetch(_task(rest.url), tmp_path)
        elapsed = time.monotonic() - started

    assert [p.name for p in written] == ["late.txt"]
    assert elapsed < 2.5
    out = capsys.readouterr().out.lower()
    assert "rest-challenge" in out and "timeout" in out
    assert "channel=mcp" in out and "fatal=false" in out


def test_mcp_timeout_is_bounded_and_silent(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """e. A stalled MCP response is bounded by the shared deadline."""
    monkeypatch.setattr(agent, "_ATTACHMENT_TIMEOUT", 0.6)
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "a.txt", "size": 1}], delay=2.0,
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        started = time.monotonic()
        assert _fetch(_task(rest.url), tmp_path) == []
        assert time.monotonic() - started < 3.0
    assert not (tmp_path / "attachments").exists()
    out = capsys.readouterr().out.lower()
    assert "channel=mcp" in out
    assert "timed out" in out or "timeout" in out


@pytest.mark.parametrize(
    "mode", ["missing", "broken", "unexpanded", "noauth", "stdio"]
)
def test_bad_mcp_config_skips_the_channel(
    tmp_path: Path, mode: str, capsys
) -> None:
    """f. A missing/broken template disables MCP instead of guessing an endpoint."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest:
        if mode == "broken":
            (tmp_path / "mcp.json").write_text("{not json", encoding="utf-8")
        elif mode == "unexpanded":
            _write_mcp(tmp_path, "http://127.0.0.1:9/mcp", token="${NOPE_MISSING}")
        elif mode == "noauth":
            (tmp_path / "mcp.json").write_text(
                json.dumps({"mcpServers": {"ctfy": {
                    "type": "http", "url": "http://127.0.0.1:9/mcp", "headers": {}}}}),
                encoding="utf-8",
            )
        elif mode == "stdio":
            (tmp_path / "mcp.json").write_text(
                json.dumps({"mcpServers": {"ctfy": {
                    "type": "stdio", "command": "nope"}}}),
                encoding="utf-8",
            )
        assert _fetch(_task(rest.url), tmp_path) == []
    assert not (tmp_path / "attachments").exists()
    out = capsys.readouterr().out
    assert "rest-challenge" in out and "HTTP 403" in out
    assert "mcp attachment channel skipped" in out


def test_mcp_config_template_is_expanded_from_environment(tmp_path: Path) -> None:
    """f. The platform's own URL and header are used verbatim after expansion."""
    with _Server(_Mcp(listing=[{"name": "a.txt", "size": 1}],
                      downloads={"a.txt": _text_blob(b"a")})) as mcp:
        _write_mcp(tmp_path, mcp.url)
        config, why = attach.load_mcp_config(tmp_path)
        assert why == ""
        assert config is not None and config.url == mcp.url
        assert config.headers["Authorization"] == f"Bearer {TOKEN}"


def test_unsafe_names_are_refused_on_both_channels(tmp_path: Path) -> None:
    """g. Neither a listing nor a download may steer writes outside work/."""
    listing = [{"name": "../escape", "size": 1},
               {"name": "/etc/passwd", "size": 1},
               {"name": "ok.txt", "size": 1}]
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, \
            _Server(_Mcp(listing=listing, downloads={
                "../escape": _text_blob(b"x"),
                "/etc/passwd": _text_blob(b"x"),
                "ok.txt": _text_blob(b"o"),
            })) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url, attachments=[
            {"name": "../escape"}, {"name": "ok.txt"}]), tmp_path)

    assert [p.name for p in written] == ["ok.txt"]
    assert not (tmp_path.parent / "escape").exists()
    assert attach.safe_attachment_name("C:\\x") is None
    assert attach.safe_attachment_name("a/b") is None


def test_mcp_listing_unsafe_names_are_never_downloaded(tmp_path: Path) -> None:
    """g. With no declared names, the MCP listing itself supplies the names."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, \
            _Server(_Mcp(listing=[
                {"name": "../escape", "size": 1},
                {"name": "/etc/passwd", "size": 1},
                {"name": "ok.txt", "size": 1},
            ], downloads={
                "../escape": _text_blob(b"x"),
                "/etc/passwd": _text_blob(b"x"),
                "ok.txt": _text_blob(b"o"),
            })) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert [p.name for p in written] == ["ok.txt"]
    assert not (tmp_path.parent / "escape").exists()
    downloaded = [args["filename"] for name, args in mcp.state.calls
                  if name == "download_challenge_attachment"]
    assert downloaded == ["ok.txt"]


def test_second_channel_must_match_the_first_listing_size(tmp_path: Path) -> None:
    """h. REST listed 5 bytes; an MCP payload of 3 must not be written."""
    with _Server(_rest_handler(
        None, {"blocked.bin": b"abcde"}, download_status={"blocked.bin": 403},
    )) as rest, _Server(_Mcp(
        downloads={"blocked.bin": _base_blob(b"abc")},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []

    assert not (tmp_path / "attachments").exists()


def test_size_mismatch_and_empty_files_are_refused(
    tmp_path: Path, capsys
) -> None:
    """h. Declared size is the integrity check; zero bytes is never an attachment."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "short.bin", "size": 10},
                 {"name": "empty.bin", "size": 0},
                 {"name": "good.bin", "size": 2}],
        downloads={"short.bin": _base_blob(b"abc"),
                   "empty.bin": _base_blob(b""),
                   "good.bin": _base_blob(b"ok")},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(_task(rest.url), tmp_path)

    assert [p.name for p in written] == ["good.bin"]
    assert not (tmp_path / "attachments" / "short.bin").exists()
    assert not (tmp_path / "attachments" / "empty.bin").exists()
    out = capsys.readouterr().out
    assert "short.bin" in out and "size mismatch" in out
    assert "empty.bin" in out and "empty" in out


def test_oversize_attachment_is_refused_before_decoding(tmp_path: Path, monkeypatch,
                                                        capsys) -> None:
    """h. The cap is enforced on the wire size so a huge blob cannot OOM."""
    monkeypatch.setattr(attach, "MAX_ATTACHMENT_BYTES", 16)
    payload = _base_blob(b"A" * 64)
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "big.bin", "size": 64}],
        downloads={"big.bin": payload},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path) == []
    assert not (tmp_path / "attachments").exists()
    assert "big.bin" in capsys.readouterr().out


def test_text_that_looks_like_base64_is_not_decoded(tmp_path: Path) -> None:
    """h. ``test`` is valid base64; the encoding field alone decides."""
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        listing=[{"name": "t.txt", "size": 4}],
        downloads={"t.txt": {"filename": "t.txt", "size": 4,
                             "encoding": "utf-8", "content": "test"}},
    )) as mcp:
        _write_mcp(tmp_path, mcp.url)
        assert _fetch(_task(rest.url), tmp_path)
    assert (tmp_path / "attachments" / "t.txt").read_bytes() == b"test"


def test_resource_blob_is_decoded_and_checked(tmp_path: Path) -> None:
    """c. A resource.blob block is base64 by structure, not by appearance."""
    blob = b"\x89PNG\r\n"
    result = {"content": [{"type": "resource", "resource": {
        "uri": "file:///x", "blob": base64.b64encode(blob).decode()}}]}
    assert attach._decode_download(result) == (blob, None)


def test_token_never_appears_in_logs_or_errors(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    """i. Both the REST token and the MCP header secret stay out of logs."""
    mcp_token = "mcp-secret-456"
    monkeypatch.setenv("MCP_TOKEN", mcp_token)
    with _Server(_rest_handler(None, {}, list_status=403)) as rest, _Server(_Mcp(
        auth_status=403,
        auth_body=f"rejected {TOKEN} and {mcp_token}".encode(),
    )) as mcp:
        _write_mcp(tmp_path, mcp.url, token="${MCP_TOKEN}")
        assert _fetch(_task(rest.url), tmp_path) == []
    captured = capsys.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err
    assert mcp_token not in captured.out
    assert mcp_token not in captured.err
    config, _why = attach.load_mcp_config(tmp_path)
    assert config is not None
    assert mcp_token in config.secrets
    err = attach._McpHttpError(403, f"echo {mcp_token}".encode())
    assert mcp_token not in attach.redact(err, config.secrets)


def test_existing_file_does_not_hide_missing_ones(tmp_path: Path) -> None:
    """j. ``attachments/`` already has one file; the listing names two."""
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments" / "old.txt").write_bytes(b"old")
    with _Server(_rest_handler(None, {"old.txt": b"old", "new.txt": b"new"})) as rest:
        written = _fetch(_task(rest.url), tmp_path)

    assert [p.name for p in written] == ["new.txt"]
    assert (tmp_path / "attachments" / "old.txt").read_bytes() == b"old"
    assert (tmp_path / "attachments" / "new.txt").read_bytes() == b"new"


def test_declared_names_are_the_only_files_requested(tmp_path: Path) -> None:
    """A declaration limits downloads to the missing names, not the listing."""
    blobs = {"have.txt": b"have", "need.txt": b"need"}
    (tmp_path / "have.txt").write_bytes(b"have")
    task = _task("http://unused.invalid", attachments=[
        {"name": "have.txt"}, {"name": "need.txt"}])
    with _Server(_rest_handler(None, blobs)) as rest:
        task["platform_url"] = rest.url
        written = _fetch(task, tmp_path)
    assert [p.name for p in written] == ["need.txt"]
    paths = [r["path"] for r in rest.requests]
    assert paths[0] == "/api/v1/challenges/CHAL/attachments"
    assert paths[1:] == ["/api/v1/challenges/CHAL/attachments/need.txt"]


def test_declared_all_present_skips_network_entirely(tmp_path: Path) -> None:
    """No listing needed when task.json names every file and all are on disk."""
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments" / "a.bin").write_bytes(b"a")
    task = _task("http://unused.invalid", attachments=[{"name": "a.bin"}])
    with _Server(_rest_handler(None, {"a.bin": b"a"})) as rest:
        task["platform_url"] = rest.url
        assert _fetch(task, tmp_path) == []
        assert rest.requests == []


def test_instance_channel_covers_files_the_challenge_route_lacks(tmp_path: Path) -> None:
    """Per-team artifacts exist only on the instance route."""
    task = _task("http://unused.invalid", target_instance="INST")
    with _Server(_rest_handler(
        None, {}, instance_files={"team.bin": b"per-team"},
    )) as rest, _Server(_Mcp(listing=[])) as mcp:
        task["platform_url"] = rest.url
        _write_mcp(tmp_path, mcp.url)
        written = _fetch(task, tmp_path)
    assert (tmp_path / "attachments" / "team.bin").read_bytes() == b"per-team"
    assert [p.name for p in written] == ["team.bin"]


def test_mcp_json_document_may_span_data_lines_unit() -> None:
    """The SSE parser joins data lines per event, then parses one document."""
    body = b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":3,"result":{}}\n\n'
    events = attach._sse_events(body)
    assert events == [{"jsonrpc": "2.0", "id": 3, "result": {}}]


def test_duplicate_listing_names_are_kept_once() -> None:
    """A repeated name must not turn into two downloads or two sizes."""
    specs = attach._specs_from_rows([
        {"name": "a.txt", "size": 3},
        {"name": "a.txt", "size": 99},
        {"filename": "b.txt", "size": 1},
    ])
    assert [(s.name, s.size) for s in specs] == [("a.txt", 3), ("b.txt", 1)]


@pytest.mark.parametrize("block", [
    {"type": "text", "text": "A" * 64},
    {"type": "text", "text": base64.b64encode(b"A" * 64).decode(),
     "encoding": "base64"},
])
def test_text_content_block_is_capped(monkeypatch, block: dict) -> None:
    """The text-block path must enforce the same cap as resource.blob."""
    monkeypatch.setattr(attach, "MAX_ATTACHMENT_BYTES", 8)
    with pytest.raises(attach._McpToolError, match="exceeds"):
        attach._decode_download({"content": [block]})


def test_unknown_encoding_is_refused() -> None:
    """Only declared encodings are decoded; anything else is a failure."""
    with pytest.raises(attach._McpToolError):
        attach._decode_payload({"content": "x", "encoding": "rot13"})


# --- DEF-12/DEF-13: competition-scoped tokens and independent REST slices ---


def _scoped_handler(files: dict[str, bytes]):
    """Stand-in for a competition-scoped eval token: 403 without the query."""
    prefix = "/api/v1/challenges/CHAL/attachments"
    inst_prefix = "/api/v1/instances/INST/attachments"

    def factory(srv: "_Server"):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                srv.requests.append({"path": self.path})
                parsed = urllib.parse.urlparse(self.path)
                if urllib.parse.parse_qs(parsed.query).get("competition_id") != ["COMP"]:
                    _respond(self, 403, b'{"detail":"token_competition_forbidden"}',
                             "application/json")
                    return
                path = parsed.path
                if path == inst_prefix:
                    _respond(self, 200, b'{"files": []}', "application/json")
                    return
                if path == prefix:
                    body = json.dumps({"files": [
                        {"name": n, "size": len(b), "per_team": False}
                        for n, b in files.items()
                    ]}).encode()
                    _respond(self, 200, body, "application/json")
                    return
                if path.startswith(prefix + "/"):
                    name = path[len(prefix) + 1:]
                    if name in files:
                        _respond(self, 200, files[name], "application/octet-stream")
                        return
                _respond(self, 404, b"not found", "text/plain")

        return Handler

    return factory


def test_scoped_url_helper_is_additive() -> None:
    """An existing query survives, and an empty id changes nothing."""
    assert attach._scoped("http://h/p", "") == "http://h/p"
    assert attach._scoped("http://h/p", "C 1") == "http://h/p?competition_id=C%201"
    assert attach._scoped("http://h/p?a=1", "C") == "http://h/p?a=1&competition_id=C"


def test_competition_id_unblocks_scoped_attachment_routes(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for the 69 official runs that logged 'list HTTP 403'.

    The eval token only works when ``competition_id`` is on BOTH the listing
    and the per-file download; without it the channel is fatal and the run
    starts with no attachment bytes at all.
    """
    monkeypatch.delenv("CTFY_EVAL_COMPETITION_ID", raising=False)
    blob = b"scoped-bytes"
    task = _task("http://unused.invalid", competition_id="COMP",
                 target_instance="INST")
    with _Server(_scoped_handler({"readme.txt": blob})) as rest:
        task["platform_url"] = rest.url
        written = _fetch(task, tmp_path)

    assert (tmp_path / "attachments" / "readme.txt").read_bytes() == blob
    assert [p.name for p in written] == ["readme.txt"]
    assert rest.requests, "no request was made"
    queries = [
        urllib.parse.parse_qs(urllib.parse.urlparse(r["path"]).query)
        for r in rest.requests
    ]
    assert all(q.get("competition_id") == ["COMP"] for q in queries), rest.requests


def test_env_competition_id_is_honoured(tmp_path: Path, monkeypatch) -> None:
    """The platform may pass the competition id as an env var, not task.json."""
    monkeypatch.setenv("CTFY_EVAL_COMPETITION_ID", "COMP")
    blob = b"from-env"
    task = _task("http://unused.invalid", target_instance="INST")
    with _Server(_scoped_handler({"readme.txt": blob})) as rest:
        task["platform_url"] = rest.url
        _fetch(task, tmp_path)
    assert (tmp_path / "attachments" / "readme.txt").read_bytes() == blob


def test_hung_instance_listing_does_not_starve_challenge_listing(
    tmp_path: Path, monkeypatch
) -> None:
    """Regression for the 59 official 'budget spent before listing' runs.

    Three independent slices mean the instance hop can burn its entire slice
    on a TLS handshake that never completes and the challenge hop still gets
    a fresh attempt instead of being skipped outright.
    """
    monkeypatch.delenv("CTFY_EVAL_COMPETITION_ID", raising=False)
    monkeypatch.setattr(agent, "_ATTACHMENT_TIMEOUT", 0.9)
    prefix = "/api/v1/challenges/CHAL/attachments"
    inst_prefix = "/api/v1/instances/INST/attachments"

    def factory(srv: "_Server"):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                srv.requests.append({"path": self.path})
                if self.path == inst_prefix:
                    time.sleep(0.5)  # longer than one 0.3s slice
                if self.path == prefix:
                    _respond(self, 200, b'{"files": []}', "application/json")
                    return
                _respond(self, 200, b'{"files": []}', "application/json")

        return Handler

    task = _task("http://unused.invalid", target_instance="INST")
    with _Server(factory) as rest:
        task["platform_url"] = rest.url
        _fetch(task, tmp_path)

    paths = [r["path"] for r in rest.requests]
    assert prefix in paths, f"challenge listing was starved: {paths}"
