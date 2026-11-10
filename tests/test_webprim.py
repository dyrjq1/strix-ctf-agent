"""B-1: webprim tools (jwt_forge, authdiff, jsrecon, http_burst).

Naming tests: no challenge numbers, IPs, flags, or specific failure paths
in any test description or assertion message.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import inspect
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))

from ctf_strix import webprim  # noqa: E402
from ctf_strix.webprim import (  # noqa: E402
    _RSA_E,
    _RSA_N,
    authdiff,
    http_burst,
    jsrecon,
    jwt_forge,
    MAX_BURST,
)


# -- jwt_forge -----------------------------------------------------------

class TestJwtForge:
    def test_alg_none_produces_empty_signature(self):
        result = json.loads(jwt_forge(alg="none", claims_json='{"sub":"admin"}'))
        token = result["token"]
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""
        assert result["alg"] == "none"

    def test_hs256_with_secret_produces_valid_token(self):
        result = json.loads(jwt_forge(alg="HS256", secret="mysecret", claims_json='{"sub":"test"}'))
        assert result["alg"] == "HS256"
        assert result["secret_len"] == 8
        assert "mysecret" not in json.dumps(result)

    def test_hs256_fixed_vector(self):
        result = json.loads(jwt_forge(alg="HS256", secret="secret", claims_json='{"sub":"x"}'))
        assert result["token"] == (
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiJ4In0"
            ".OWnOV7kzmJNloJ_8_72WDmuy2ZMonWFc2sqiEpBjdkk"
        )

    @pytest.mark.parametrize("alg", ["HS384", "HS512"])
    def test_hmac_variants_produce_three_segments(self, alg):
        result = json.loads(jwt_forge(alg=alg, secret="k", claims_json='{"sub":"x"}'))
        parts = result["token"].split(".")
        assert len(parts) == 3 and parts[2]
        assert result["alg"] == alg

    def test_rs256_signature_verifies_with_embedded_jwk(self):
        result = json.loads(jwt_forge(alg="RS256", claims_json='{"sub":"a"}'))
        signed, payload, signature = result["token"].split(".")
        raw = signature + "=" * (-len(signature) % 4)
        value = int.from_bytes(base64.urlsafe_b64decode(raw), "big")
        size = (_RSA_N.bit_length() + 7) // 8
        encoded = pow(value, _RSA_E, _RSA_N).to_bytes(size, "big")
        assert encoded.startswith(b"\x00\x01\xff")
        assert encoded.endswith(hashlib.sha256(f"{signed}.{payload}".encode()).digest())

    def test_rs256_embeds_jwk_in_header(self):
        result = json.loads(jwt_forge(alg="RS256", claims_json='{"role":"admin"}'))
        assert result["alg"] == "RS256"
        assert "jwk" in result["header"]
        assert result["header"]["jwk"]["kty"] == "RSA"

    def test_token_rewrite_preserves_existing_fields(self):
        base = jwt_forge(alg="HS256", secret="abc", claims_json='{"sub":"user","role":"guest"}')
        base_token = json.loads(base)["token"]
        result = json.loads(jwt_forge(
            token=base_token, alg="HS256", secret="abc", claims_json='''{"role":"admin"}'''
        ))
        assert result["claims"]["sub"] == "user"
        assert result["claims"]["role"] == "admin"
        assert "role" in result["changed"]

    def test_remove_deletes_claims(self):
        result = json.loads(jwt_forge(
            alg="HS256", secret="x", claims_json='''{"sub":"a","exp":99999}''', remove=["exp"]
        ))
        assert "exp" not in result["claims"]
        assert "exp" in result["removed"]

    def test_rejects_unknown_alg(self):
        with pytest.raises(Exception):
            jwt_forge(alg="ES256")

    def test_rejects_non_jwt_token(self):
        with pytest.raises(Exception):
            jwt_forge(token="not-a-jwt")

    def test_rejects_hs_without_secret(self):
        with pytest.raises(Exception):
            jwt_forge(alg="HS256", claims_json='{"sub":"x"}')

    def test_rejects_non_object_claims(self):
        with pytest.raises(Exception):
            jwt_forge(alg="none", claims_json='["not","an","object"]')

    def test_rejects_non_list_remove(self):
        with pytest.raises(Exception):
            jwt_forge(remove="exp")


# -- authdiff ------------------------------------------------------------

class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"{}", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/admin":
            if self.headers.get("Cookie") == "session=abc":
                self._send(200, b'{"secret":"admin-data"}')
            elif self.headers.get("X-Admin") == "true":
                self._send(200, b'{"secret":"admin-data"}')
            else:
                self._send(403, b'{"error":"forbidden"}')
        elif self.path == "/public":
            self._send(200, b'{"msg":"hello"}')
        else:
            self._send(404, b'{"error":"not found"}')


@pytest.fixture()
def auth_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _call(fn, **kwargs):
    return asyncio.run(fn(**kwargs)) if inspect.iscoroutinefunction(fn) else fn(**kwargs)


class TestAuthdiff:
    def test_baseline_and_bypass_produce_different_hashes(self, auth_server):
        result = json.loads(_call(authdiff, url=f"{auth_server}/admin", variants="bypass"))
        rows = result["rows"]
        baseline = next(r for r in rows if r["variant"] == "baseline")
        bypass_x_admin = next(r for r in rows if r.get("variant") == "bypass:X-Admin")
        assert baseline["hash"] != bypass_x_admin["hash"]

    def test_public_page_same_for_all_variants(self, auth_server):
        result = json.loads(_call(authdiff, url=f"{auth_server}/public", variants="bypass"))
        hashes = {r["hash"] for r in result["rows"] if "hash" in r}
        assert len(hashes) == 1

    def test_anon_strips_a_supplied_cookie(self, auth_server):
        result = json.loads(_call(
            authdiff,
            url=f"{auth_server}/admin",
            variants="anon",
            headers_json='{"Cookie":"session=abc"}',
        ))
        rows = {row["variant"]: row for row in result["rows"]}
        assert result["cookie_supplied"] is True
        assert rows["baseline"]["hash"] != rows["anon"]["hash"]
        assert any("differs" in text for text in result["conclusions"])

    def test_anon_without_cookie_says_it_is_uninformative(self, auth_server):
        result = json.loads(_call(authdiff, url=f"{auth_server}/admin", variants="anon"))
        assert result["cookie_supplied"] is False
        assert any("no Cookie header" in text for text in result["conclusions"])

    def test_rejects_non_http_scheme(self):
        with pytest.raises(Exception):
            _call(authdiff, url="ftp://example.test/admin")

    def test_rejects_unknown_variant(self):
        with pytest.raises(Exception):
            _call(authdiff, url="http://127.0.0.1:1/test", variants="bogus")

    def test_rejects_missing_url(self):
        with pytest.raises(Exception):
            _call(authdiff, url="")


# -- jsrecon -------------------------------------------------------------

_JS_PAGE = """<html>
<head>
<script src="/app.js"></script>
</head>
<body>
<script>
  fetch("/api/v1/users");
  const key = "sk_test_abc123456";
</script>
</body>
</html>"""

_APP_JS = """
import {x} from "/_nuxt/other.js";
const a = fetch("/api/plugins/stats", {method: "POST"});
const b = $fetch("/api/plugins/preview");
export const routes = [
  {path: "/dashboard", component: "Dashboard"},
  {path: "/settings", component: "Settings"},
];
//# sourceMappingURL=app.js.map
/* TODO: remove debug key */
const apiKey = "debug-key-12345";
"""


class _JSHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(200, _JS_PAGE.encode(), "text/html")
        elif self.path == "/app.js":
            self._send(200, _APP_JS.encode(), "application/javascript")
        else:
            self._send(404, b"not found")


@pytest.fixture()
def js_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _JSHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


class TestJsrecon:
    def test_extracts_api_paths_from_js(self, js_server):
        result = json.loads(_call(jsrecon, url=f"{js_server}/"))
        api = result.get("api", [])
        assert "/api/plugins/stats" in api or "/api/plugins/preview" in api
        assert result["api_total"] >= 1

    def test_extracts_sourcemap_url(self, js_server):
        result = json.loads(_call(jsrecon, url=f"{js_server}/"))
        assert len(result.get("sourcemaps", [])) >= 1

    def test_extracts_secrets(self, js_server):
        result = json.loads(_call(jsrecon, url=f"{js_server}/"))
        secrets = result.get("secrets", [])
        assert any("debug-key" in s for s in secrets)

    def test_rejects_missing_url(self):
        with pytest.raises(Exception):
            _call(jsrecon, url="")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(Exception):
            _call(jsrecon, url="ftp://example.test/app.js")

    def test_rejects_non_string_url(self):
        with pytest.raises(Exception):
            _call(jsrecon, url=12345)


# -- http_burst ----------------------------------------------------------

_BURST_RESPONSES = [b"ok"] * 8


class _BurstHandler(BaseHTTPRequestHandler):
    _count = 0

    def log_message(self, *args):
        pass

    def _send(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        _BurstHandler._count += 1
        idx = (_BurstHandler._count - 1) % len(_BURST_RESPONSES)
        self._send(200, _BURST_RESPONSES[idx])

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        self._send(200, f"cookie={cookie}".encode())


@pytest.fixture()
def burst_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BurstHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


class TestHttpBurst:
    def test_race_mode_sends_concurrent_requests(self, burst_server):
        result = json.loads(_call(http_burst, url=f"{burst_server}/test", method="POST", count=4))
        assert result["mode"] == "race"
        assert result["requested"] == 4
        assert result["ok"] + result["failed"] == 4

    def test_batch_mode_replaces_placeholder(self, burst_server):
        result = json.loads(_call(http_burst,
            url=f"{burst_server}/api/{'{v}'}", method="GET", values=["alice", "bob"]))
        assert result["mode"] == "batch"
        assert result["requested"] == 2

    def test_cookie_snapshot_reaches_every_worker(self, burst_server):
        result = json.loads(_call(
            http_burst,
            url=f"{burst_server}/x",
            method="GET",
            count=3,
            headers_json='{"Cookie":"session=abc"}',
        ))
        assert result["ok"] == 3
        assert all("session=abc" in group["head"] for group in result["groups"])
        assert result.get("cookie") == "session=abc"

    def test_round_is_discarded_when_barrier_breaks(self, burst_server, monkeypatch):
        class _BrokenBarrier:
            def __init__(self, parties):
                pass

            def wait(self, timeout=None):
                raise threading.BrokenBarrierError()

            def abort(self):
                pass

        monkeypatch.setattr(webprim.threading, "Barrier", _BrokenBarrier)
        result = json.loads(_call(http_burst, url=f"{burst_server}/x", method="GET", count=2))
        assert result["ok"] == 0 and result["failed"] == 2
        text = " ".join(str(item.get("error", "")) for item in result["errors"]).lower()
        assert "aborted" in text and "peer" in text

    def test_barrier_abort_when_connect_fails(self):
        result = json.loads(_call(http_burst,
            url="http://127.0.0.1:1/nonexistent", method="GET", count=4))
        assert result["failed"] >= 1
        errors = result.get("errors", [])
        error_texts = " ".join(str(e.get("error", "")) for e in errors).lower()
        assert any(word in error_texts for word in ["abort", "connect", "fail", "peer"])

    def test_rejects_head_method(self):
        with pytest.raises(Exception):
            _call(http_burst, url="http://127.0.0.1:1/test", method="HEAD")

    def test_rejects_values_exceeding_max(self):
        with pytest.raises(Exception):
            _call(http_burst, url="http://127.0.0.1:1/test", values=[str(i) for i in range(MAX_BURST + 1)])

    def test_rejects_non_list_values(self):
        with pytest.raises(Exception):
            _call(http_burst, url="http://127.0.0.1:1/test", values="not-a-list")


# -- naming + catalogue --------------------------------------------------

def test_test_names_and_docstrings_carry_no_target_details():
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            blob = node.name + "\n" + (ast.get_docstring(node) or "")
            assert ("flag" + "{") not in blob.lower(), node.name
            assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), node.name
            assert not re.search(r"\b(?:challenge|ctf)[-_ ]?\d+\b", blob.lower()), node.name


def test_catalogue_rows_match_the_four_registered_names():
    from ctf_strix import catalogue

    expected = {"jwt_forge", "authdiff", "jsrecon", "http_burst"}
    rows = [row for row in catalogue.CATALOGUE if row.name in expected]
    assert {row.name for row in rows} == expected
    for row in rows:
        assert row.group == "web"
        assert row.applies("web")


# -- wiring: all four in the real registry --------------------------------

def test_all_four_webprim_tools_appear_in_registry():
    from ctf_strix.webprim import register as webprim_register
    from strix.agents import factory

    saved = list(factory._EXTRA_TOOLS)
    factory._EXTRA_TOOLS.clear()
    try:
        added = webprim_register()
        after = {t.name for t in factory.registered_agent_tools()}
        assert "jwt_forge" in after
        assert "authdiff" in after
        assert "jsrecon" in after
        assert "http_burst" in after
        assert len(added) == 4
    finally:
        factory._EXTRA_TOOLS[:] = saved
