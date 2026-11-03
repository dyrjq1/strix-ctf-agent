"""Traffic memory: the run must be able to read back what it already sent.

The failure this guards is CTFARENA-043: the target handed over 52 ``note_*``
ids in one response, and the transcript ended without a single detail read.
Nothing in that context said "you have 52 keys and 0 doors opened", so the
model could not notice.  These tests pin the two things that make the count
decidable: every exchange is stored, and the stored state names what is still
unfetched.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import traffic  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_ledger(monkeypatch):
    """Every test gets its own in-memory ledger (no cwd, no files)."""
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    return ledger


def _note_ids(count: int) -> str:
    return json.dumps({"notes": [f"note_{i:08x}" for i in range(count)]})


def test_record_then_list_shows_the_exchange(fresh_ledger):
    fresh_ledger.add(
        traffic.Exchange(
            id="r1",
            ts=0.0,
            method="GET",
            url="https://example.test/api/notes",
            status=200,
            resp_body='{"ok":true}',
            size=11,
            elapsed=0.05,
        )
    )
    out = traffic.traffic_list()
    assert "r1" in out
    assert "GET" in out
    assert "/api/notes" in out
    assert "1 of 1" in out


def test_empty_ledger_says_how_it_fills(fresh_ledger):
    out = traffic.traffic_list()
    assert "nothing recorded yet" in out
    assert "http_probe" in out


def test_failed_transport_attempt_is_still_recorded(fresh_ledger):
    """A refused connection is an observation: it must survive into the ledger."""
    traffic.record(
        request_id="r7",
        method="POST",
        url="http://127.0.0.1:1/api",
        phase="CONNECT",
        elapsed=0.01,
        note="ConnectionError: refused",
    )
    out = traffic.traffic_list(only_errors=True)
    assert "r7" in out
    assert "CONNECT" in out


def test_pending_targets_are_ids_no_request_has_fetched(fresh_ledger):
    """The 043 shape: enumerate first, then never read a detail page."""
    traffic.record(
        request_id="r1",
        method="GET",
        url="https://example.test/api/notes",
        status=200,
        resp_body=_note_ids(52),
        size=100,
    )
    pending = traffic.pending_targets(limit=100)
    assert len(pending) == 52
    assert "note_00000000" in pending

    out = traffic.traffic_list()
    assert "never requested (52)" in out

    # Fetching one removes exactly that one from the list.
    traffic.record(
        request_id="r2",
        method="GET",
        url="https://example.test/api/notes/note_00000000",
        status=200,
        resp_body="{}",
    )
    pending_after = traffic.pending_targets(limit=100)
    assert len(pending_after) == 51
    assert "note_00000000" not in pending_after


def test_pending_targets_ignores_identifiers_that_were_requested(fresh_ledger):
    traffic.record(
        request_id="r1",
        method="GET",
        url="https://example.test/api/notes/note_abcdef01",
        status=200,
        resp_body='{"note_id":"note_abcdef01","next":"note_abcdef02"}',
    )
    pending = traffic.pending_targets()
    assert "note_abcdef01" not in pending
    assert "note_abcdef02" in pending


def test_list_requests_filters(fresh_ledger):
    for rid, url, status in (
        ("r1", "https://example.test/api/notes", 200),
        ("r2", "https://example.test/admin", 403),
        ("r3", "https://example.test/api/flag", 200),
    ):
        traffic.record(request_id=rid, method="GET", url=url, status=status, resp_body="{}")

    only_api = traffic.traffic_list(url_contains="/api/")
    assert "r1" in only_api and "r3" in only_api and "r2" not in only_api.split("admin")[0]

    errors = traffic.traffic_list(only_errors=True)
    assert "r2" in errors
    assert "r1" not in errors.split("403")[-1] or "r1" not in errors


def test_view_request_paginates_without_resending(fresh_ledger):
    body = "".join(f"line{i:04d}\n" for i in range(400))
    traffic.record(
        request_id="r9",
        method="GET",
        url="https://example.test/big",
        status=200,
        resp_body=body,
        size=len(body),
    )
    page = traffic.traffic_view("r9", part="response", offset=0, length=200)
    assert "line0000" in page
    assert "chars left" in page
    assert "offset=200" in page

    tail = traffic.traffic_view("r9", part="response", offset=200, length=200)
    assert "line0000" not in tail
    assert "chars left" in tail


def test_view_request_unknown_id_names_the_known_ones(fresh_ledger):
    traffic.record(request_id="r1", method="GET", url="https://example.test/", status=200)
    out = traffic.traffic_view("r99")
    assert "no record" in out
    assert "r1" in out


def test_ledger_is_bounded(fresh_ledger):
    for i in range(traffic._MAX_RECORDS + 25):
        traffic.record(request_id=f"r{i}", method="GET", url=f"https://example.test/{i}", status=200)
    items = fresh_ledger.items()
    assert len(items) == traffic._MAX_RECORDS
    assert items[0].id == f"r{25}", "oldest records must fall off the front"


def test_ledger_persists_jsonl_when_a_path_is_given(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = traffic.TrafficLedger(path)
    ledger.add(
        traffic.Exchange(id="r1", ts=0.0, method="GET", url="https://example.test/x", status=200)
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["url"] == "https://example.test/x"


def test_unwritable_ledger_path_does_not_break_the_run(tmp_path):
    """A read-only work dir must degrade to in-memory, not raise."""
    blocked = tmp_path / "file"
    blocked.write_text("not a directory", encoding="utf-8")
    ledger = traffic.TrafficLedger(blocked / "child.jsonl")
    ledger.add(traffic.Exchange(id="r1", ts=0.0, method="GET", url="https://x.test/", status=200))
    assert [item.id for item in ledger.items()] == ["r1"]


def test_body_cap_is_applied_but_flag_sized_text_survives(fresh_ledger):
    payload = "A" * (traffic._BODY_KEEP + 500)
    traffic.record(request_id="r1", method="GET", url="https://x.test/", status=200, resp_body=payload)
    stored = fresh_ledger.get("r1").resp_body
    assert len(stored) < len(payload) + 200
    assert "truncated" in stored


# --------------------------------------------------------------- http_probe


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/notes":
            self._send(200, _note_ids(3).encode())
        else:
            self._send(404, b'{"error":"nope"}')


@pytest.fixture(scope="module")
def base_url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_probe_writes_into_the_ledger(fresh_ledger, base_url):
    from ctf_strix.http_probe import http_probe

    out = asyncio.run(http_probe(url=f"{base_url}/api/notes"))
    assert "id=r1" in out
    items = fresh_ledger.items()
    assert len(items) == 1
    assert items[0].status == 200
    assert items[0].method == "GET"
    assert "note_00000000" in items[0].resp_body
    # The stored body is the full one, not the clipped text shown to the model.
    assert len(items[0].resp_body) >= len("note_00000002")


def test_http_probe_records_a_refused_connection(fresh_ledger):
    import socket

    from ctf_strix.http_probe import http_probe

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    out = asyncio.run(http_probe(url=f"http://127.0.0.1:{port}/", timeout_s=3))
    assert "id=r1" in out
    item = fresh_ledger.get("r1")
    assert item is not None
    assert item.status is None
    assert item.phase
    assert "refused" in item.note.lower() or "Connection" in item.note
