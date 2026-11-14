"""Viability probe: one call, three mechanism-class ladders, three verdicts.

The failure this guards is direction, not budget: failed runs sat at p50 37
turns and 551s against a 40-turn budget, generating new *names* for one dead
mechanism.  These tests pin the property that makes the call useful -- each
ladder says ``hit`` when the mechanism is live and ``dead`` only on positive
evidence (every probe came back identical), never on "I did not find it".
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import http_probe, traffic, viability  # noqa: E402

BODY_MARKER = "UNIQUE-BODY-MARKER-9f3a"


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    """Own ledger, own cookie jars; never the real working directory."""
    ledger = traffic.TrafficLedger(None)
    monkeypatch.setattr(traffic, "_LEDGER", ledger)
    http_probe.reset_sessions()
    yield ledger
    http_probe.reset_sessions()


@pytest.fixture()
def server():
    """A local target whose routes are set per test by ``state['handler']``."""
    state: dict = {"handler": lambda method, path, body: (404, "not found"), "hits": []}

    class Handler(BaseHTTPRequestHandler):
        def _dispatch(self):
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length).decode("utf-8") if length else ""
            state["hits"].append((self.command, self.path, raw_body))
            status, body = state["handler"](self.command, self.path, raw_body)
            payload = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = _dispatch
        do_POST = _dispatch

        def log_message(self, *args):  # noqa: A003 - silence the test output
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        yield base, state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _record(method, url, status, body, req_body=""):
    traffic.record(
        request_id=traffic.ledger().next_id(),
        method=method,
        url=url,
        req_body=req_body,
        status=status,
        resp_body=body,
        size=len(body),
        elapsed=0.01,
    )


def _lines(out: str) -> dict[str, str]:
    """Map ladder name -> the verdict line."""
    rows = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if parts:
            rows[parts[0]] = line
    return rows


def _state(out: str, name: str) -> str:
    return _lines(out)[name].split()[1]


# --------------------------------------------------------------- dead fixture

def test_all_three_ladders_are_dead_on_an_inert_target(server):
    """A page with a form that ignores input, a 403 wall, and closed ids.

    Nothing here reflects, splits or answers a neighbour, so every ladder must
    say ``dead`` -- and ``dead`` must cite the identical-response evidence.
    """
    base, state = server

    def handler(method, raw_path, body):
        parts = urlsplit(raw_path)
        path = parts.path
        if path in ("/", "/search"):
            return 200, (
                "<html><body><form action='/search' method='get'>"
                "<input name='q'></form>results: nothing</body></html>"
            )
        if path == "/api/notes":
            return 200, json.dumps({"notes": ["note_00000010"]})
        if path == "/api/notes/note_00000010":
            return 200, "note ten content"
        if path.startswith("/api/notes/"):
            return 404, "not found"
        # A blanket gate: every spelling of every other route gets the same
        # 403, which is exactly the "identical response" that makes ``dead``
        # positive evidence rather than an absence of findings.
        return 403, "denied by policy"

    state["handler"] = handler
    _record("GET", base + "/?q=seed", 200, handler("GET", "/", "")[1])
    _record("GET", base + "/admin", 403, "denied by policy")
    _record("GET", base + "/api/notes", 200, handler("GET", "/api/notes", "")[1])

    out = viability.viability_probe()
    for name in ("reflection_canary", "auth_variant_split", "reference_enum"):
        assert _state(out, name) == "dead", out


# ---------------------------------------------------------------- hit fixtures

def test_reflection_ladder_hits_a_raw_echo(server):
    base, state = server

    def handler(method, raw_path, body):
        query = parse_qs(urlsplit(raw_path).query)
        value = (query.get("q") or [""])[0]
        return 200, f"<html><body>you said: {value}</body></html>"

    state["handler"] = handler
    _record("GET", base + "/?q=seed", 200, handler("GET", "/?q=seed", "")[1])

    out = viability.viability_probe(classes="reflection_canary")
    assert _state(out, "reflection_canary") == "hit", out
    assert "verbatim" in out


def test_reflection_ladder_hits_an_escaped_echo(server):
    """HTML-encoding is ``transformed``: the value survived into the page and
    the sink escaped it, which is exactly the case the model must know about."""
    base, state = server

    def handler(method, raw_path, body):
        query = parse_qs(urlsplit(raw_path).query)
        value = (query.get("q") or [""])[0]
        escaped = (
            value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("'", "&#x27;").replace('"', "&quot;")
        )
        return 200, f"<html><body>you said: {escaped}</body></html>"

    state["handler"] = handler
    _record("GET", base + "/?q=seed", 200, handler("GET", "/?q=seed", "")[1])

    out = viability.viability_probe(classes="reflection_canary")
    assert _state(out, "reflection_canary") == "hit", out
    assert "encoded" in out


def test_auth_ladder_hits_a_case_split(server):
    """A gate that matches ``/admin`` as a string but the router does not."""
    base, state = server

    def handler(method, raw_path, body):
        path = urlsplit(raw_path).path
        if path == "/admin":
            return 403, "denied by policy"
        if path == "/ADMIN":
            return 200, "<html><body>admin panel: users, secrets, export</body></html>"
        return 403, "denied by policy"

    state["handler"] = handler
    _record("GET", base + "/admin", 403, "denied by policy")

    out = viability.viability_probe(classes="auth_variant_split")
    assert _state(out, "auth_variant_split") == "hit", out
    assert "upper->200" in out


def test_reference_ladder_hits_a_sequential_neighbour(server):
    base, state = server

    def handler(method, raw_path, body):
        path = urlsplit(raw_path).path
        if path == "/api/notes/note_00000010":
            return 200, "note ten content"
        if path.startswith("/api/notes/"):
            return 200, "note content of different length for a neighbour record"
        return 404, "not found"

    state["handler"] = handler
    _record(
        "GET", base + "/api/notes", 200,
        json.dumps({"notes": ["note_00000010"]}),
    )

    out = viability.viability_probe(classes="reference_enum")
    assert _state(out, "reference_enum") == "hit", out


# ------------------------------------------------------------ unknown fixtures

def test_every_ladder_is_unknown_without_recorded_traffic():
    """No ledger and no url: unknown, but say how to bootstrap."""
    out = viability.viability_probe()
    for name in ("reflection_canary", "auth_variant_split", "reference_enum"):
        assert _state(out, name) == "unknown", out
    assert "pass url=" in out


def test_url_bootstrap_decides_reflection_on_an_empty_ledger(server):
    """A form page passed as ``url`` must be fetched, recorded, then probed.

    Without the bootstrap the ledger is empty here and every ladder would say
    ``unknown``; the point of ``url`` is that reflection becomes a verdict.
    """
    base, state = server

    def handler(method, raw_path, body):
        if urlsplit(raw_path).path == "/":
            return 200, (
                "<html><body><form action='/search' method='get'>"
                "<input name='q'></form>results: nothing</body></html>"
            )
        query = parse_qs(urlsplit(raw_path).query)
        value = (query.get("q") or [""])[0]
        return 200, f"<html><body>you said: {value}</body></html>"

    state["handler"] = handler

    out = viability.viability_probe(url=base + "/", classes="reflection_canary")
    assert _state(out, "reflection_canary") in ("hit", "dead"), out
    assert _state(out, "reflection_canary") == "hit", out


def test_bootstrap_request_is_counted_in_the_budget(server):
    base, state = server

    def handler(method, raw_path, body):
        query = parse_qs(urlsplit(raw_path).query)
        value = (query.get("q") or [""])[0]
        return 200, f"<html><body>q={value}</body></html>"

    state["handler"] = handler

    out = viability.viability_probe(url=base + "/?q=seed", classes="reflection_canary")
    assert len(state["hits"]) >= 2, state["hits"]
    assert f"viability ({len(state['hits'])} reqs" in out, out


def test_reference_is_unknown_when_the_target_handed_over_no_ids(server):
    base, state = server

    def handler(method, raw_path, body):
        return 200, "<html><body>no identifiers here</body></html>"

    state["handler"] = handler
    _record("GET", base + "/", 200, handler("GET", "/", "")[1])

    out = viability.viability_probe(classes="reference_enum")
    assert _state(out, "reference_enum") == "unknown", out


# -------------------------------------------------------------------- nonce

def test_two_calls_use_different_nonces(server):
    base, state = server

    def handler(method, raw_path, body):
        query = parse_qs(urlsplit(raw_path).query)
        value = (query.get("q") or [""])[0]
        return 200, value

    state["handler"] = handler
    _record("GET", base + "/?q=seed", 200, handler("GET", "/?q=seed", "")[1])

    viability.viability_probe(classes="reflection_canary")
    viability.viability_probe(classes="reflection_canary")

    injected = [
        (parse_qs(urlsplit(path).query).get("q") or [""])[0]
        for _method, path, _body in state["hits"]
        if "q=" in path
    ]
    nonces = [value[:6] for value in injected if len(value) >= 6]
    assert len(nonces) >= 2
    assert nonces[-1] != nonces[-2]
    assert all(len(n) == 6 and all(c in "0123456789abcdef" for c in n) for n in nonces)


# -------------------------------------------------------------------- budget

def test_request_cap_binds_on_a_target_that_always_answers(server):
    """20 surfaces + 14 variants + 10 probes = 44 planned, so the 40 cap is
    reachable.  The call must stop at 40 and still return a table."""
    base, state = server

    def handler(method, raw_path, body):
        return 200, "<html><body>" + BODY_MARKER + "</body></html>"

    state["handler"] = handler
    for index in range(20):
        _record("GET", f"{base}/p{index}?f{index}=seed", 200, handler("GET", "/", "")[1])
    for path in ("/admin", "/private", "/dashboard"):
        _record("GET", base + path, 401, "login required", )

    out = viability.viability_probe()
    assert len(state["hits"]) <= viability._MAX_REQUESTS, len(state["hits"])
    assert f"{viability._MAX_REQUESTS} reqs" in out or " reqs," in out
    assert "viability (" in out


def test_output_is_bounded_and_never_contains_a_response_body(server):
    base, state = server

    def handler(method, raw_path, body):
        return 200, "<html><body>" + BODY_MARKER + "</body></html>"

    state["handler"] = handler
    for index in range(20):
        _record("GET", f"{base}/p{index}?f{index}=seed", 200, handler("GET", "/", "")[1])
    _record("GET", base + "/admin", 401, "login required")

    out = viability.viability_probe()
    assert len(out) <= viability._MAX_OUT
    assert BODY_MARKER not in out
    assert "<body>" not in out


def test_dead_verdicts_carry_positive_evidence(server):
    base, state = server

    def handler(method, raw_path, body):
        return 403, "denied by policy"

    state["handler"] = handler
    _record("GET", base + "/admin", 403, "denied by policy")

    out = viability.viability_probe(classes="auth_variant_split")
    line = _lines(out)["auth_variant_split"]
    assert "dead" in line
    assert "matched baseline" in line and "len=" in line


def test_unknown_class_is_reported_not_run():
    out = viability.viability_probe(classes="nope")
    assert "unknown class" in out
    assert "skipped" in out


def test_dedup_reuses_an_identical_request_within_one_call(server):
    """Two identical surfaces must cost one request, not two."""
    base, state = server

    def handler(method, raw_path, body):
        return 200, "nothing"

    state["handler"] = handler
    _record("GET", base + "/?q=seed", 200, "nothing")
    _record("GET", base + "/?q=seed", 200, "nothing")

    viability.viability_probe(classes="reflection_canary")
    probed = [h for h in state["hits"] if "q=" in h[1]]
    assert len(probed) == 1, probed


def test_classify_distinguishes_the_three_shapes():
    nonce, payload = "abc123", "abc123'\"<>"
    assert viability._classify("nothing", nonce, payload) == "absent"
    assert viability._classify(f"v={payload}", nonce, payload) == "verbatim"
    assert viability._classify("v=abc123&#x27;&quot;&lt;&gt;", nonce, payload) == "transformed"
    assert viability._classify("v=abc123", nonce, payload) == "partial"