"""附件下载的 302 链路（台账 §4.283）。

平台 2026-11-19 起把 ``…/attachments/<name>`` 改成 ``302`` 指向短时有效的
Cloudflare R2 签名 URL。两个真客户端各跑一遍：

* 镜像路径 ``platform_attach`` 用 ``urllib``：它会把**所有**请求头原样带到
  跳转目标，而 S3 兼容存储拒绝「签名 + Authorization」双认证（HTTP 400）。
  所以 bearer 必须走 ``add_unredirected_header``——首跳仍带，跳转丢。
* 车道路径 ``batch_eval.Client`` 用 ``requests.Session``：跨主机会自己剥掉
  Authorization，只需确认它确实跟随跳转、拿到完整字节。

平台号是模拟的（本地两个端口，127.0.0.1 → localhost 构成跨主机跳转）；
平台真链路的实测见台账 §4.283。
"""

from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "vendor" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

PAYLOAD = b"PK\x03\x04" + b"redirect-test" * 64
NAME = "challenge.zip"
TOKEN = "test-token"

#: (hop, was Authorization present) for every request the two servers saw.
SEEN: list[tuple[str, bool]] = []


def _serve(handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Blob(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: D102, ANN002
        pass

    def do_GET(self):  # noqa: N802
        SEEN.append(("blob", bool(self.headers.get("Authorization"))))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)


@pytest.fixture()
def fake_platform():
    SEEN.clear()
    blob = _serve(_Blob)
    redirect_port = blob.server_address[1]

    class _Api(BaseHTTPRequestHandler):
        def log_message(self, *args):  # noqa: D102, ANN002
            pass

        def do_GET(self):  # noqa: N802
            if self.path.endswith("/attachments"):
                body = json.dumps(
                    {"files": [{"name": NAME, "size": len(PAYLOAD)}]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.endswith(f"/attachments/{NAME}"):
                SEEN.append(("api", bool(self.headers.get("Authorization"))))
                # Cross-host on purpose: requests strips the bearer, urllib
                # would forward it unless the caller says otherwise.
                self.send_response(302)
                self.send_header(
                    "Location", f"http://localhost:{redirect_port}/blob/{NAME}"
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

    api = _serve(_Api)
    try:
        yield f"http://127.0.0.1:{api.server_address[1]}"
    finally:
        for srv in (api, blob):
            srv.shutdown()
            srv.server_close()


def test_platform_attach_follows_the_redirect_without_the_bearer(fake_platform):
    """urllib 路径：拿到字节，且跳转目标**看不到** Authorization。"""
    from ctf_strix import platform_attach

    res = platform_attach.fetch_rest_challenge(
        fake_platform, "CHAL-1", TOKEN, deadline=time.monotonic() + 30
    )

    assert res.blobs.get(NAME) == PAYLOAD
    assert not res.errors, res.errors
    assert ("api", True) in SEEN, "首跳必须带 bearer，平台 API 靠它认证"
    assert ("blob", False) in SEEN, "bearer 被带到签名 URL 上 = S3 双认证 400"
    assert ("blob", True) not in SEEN


def test_the_harness_client_follows_the_redirect(fake_platform):
    """requests 路径：默认跟随，字节完整（防有人加 allow_redirects=False）。"""
    batch = pytest.importorskip("batch_eval", reason="harness not importable here")
    batch.PLATFORM = fake_platform
    got = batch.Client(TOKEN).fetch_attachments("CHAL-1")

    assert got.get(NAME) == PAYLOAD
    assert ("blob", True) not in SEEN, "requests 跨主机本应剥掉 bearer"