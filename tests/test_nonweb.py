"""Non-web primitives: what they must do, and what they must refuse.

Two failure modes are covered here, because both are silent in production:

1. A tool that "works" on the happy path but returns a wall of raw bytes --
   the model then spends its next turn reading instead of solving.
2. A tool that trusts archive member names -- CTF attachments are hostile by
   construction, so ``../../`` is not an edge case, it is the default.

The tests use real archives and a real loopback socket.  A mocked socket would
prove the formatting and nothing else; the banner-then-payload ordering is the
part that actually breaks.
"""

from __future__ import annotations

import base64
import gzip
import io
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import threading
import time
import zipfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import nonweb  # noqa: E402


# --------------------------------------------------------------------------
# decode_blob
# --------------------------------------------------------------------------


def test_decode_blob_single_layer_reports_flag() -> None:
    out = nonweb.decode_blob("ZmxhZ3tiNjRfc2luZ2xlX2xheWVyfQ==")
    assert "flag{b64_single_layer}" in out
    assert "base64" in out


def test_decode_blob_walks_a_chain() -> None:
    inner = "flag{two_layers}".encode().hex()
    outer = inner.encode().hex()
    out = nonweb.decode_blob(outer)
    assert "flag{two_layers}" in out
    assert out.count("->") >= 2


def test_decode_blob_refuses_to_dig_on_plain_prose() -> None:
    """Without the printable/English gate every sentence decodes to noise.

    The failure is not cosmetic: a bogus layer hides the real one behind a
    wrong ``cur`` value on the next iteration.
    """
    out = nonweb.decode_blob("the quick brown fox jumps over the lazy dog")
    assert "no decoding chain" in out


def test_decode_blob_empty_input_is_a_hint() -> None:
    assert "empty" in nonweb.decode_blob("")


def test_decode_blob_oversized_input_points_at_hexpeek() -> None:
    out = nonweb.decode_blob("A" * (nonweb._BLOB_MAX_CHARS + 10))
    assert "hexpeek" in out


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58(data: bytes) -> str:
    """Bitcoin-alphabet base58, written out here on purpose.

    Reading ``nonweb._B58_ALPHA`` would make the test agree with a wrong
    alphabet; the fixture must encode with the published one.
    """
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = _B58_ALPHABET[remainder] + out
    return out


def _rot47(text: str) -> str:
    """ROT47 over the 94 printable ASCII characters (33..126)."""
    return "".join(
        chr(33 + (ord(char) - 33 + 47) % 94) if 33 <= ord(char) <= 126 else char
        for char in text
    )


def test_decode_blob_handles_base85() -> None:
    """base85 is common in CTF attachments and was absent from the old table."""
    out = nonweb.decode_blob(base64.b85encode(b"flag{b85_layer}").decode())
    assert "flag{b85_layer}" in out
    assert "base85" in out


def test_decode_blob_handles_base58() -> None:
    out = nonweb.decode_blob(_b58(b"flag{b58_layer}"))
    assert "flag{b58_layer}" in out
    assert "base58" in out


def test_decode_blob_handles_rot47() -> None:
    """ROT47 is a bijection, so it needs the flag/English gate to be accepted."""
    cipher = _rot47("flag{rot47_layer}")
    assert cipher != "flag{rot47_layer}"
    out = nonweb.decode_blob(cipher)
    assert "flag{rot47_layer}" in out
    assert "rot47" in out


def test_decode_blob_unwraps_zlib_before_decoding() -> None:
    """Compressed bytes under an encoding are a layer, not a dead end."""
    blob = base64.b64encode(zlib.compress(b"flag{zlib_inside_b64}")).decode()
    out = nonweb.decode_blob(blob)
    assert "flag{zlib_inside_b64}" in out
    assert "base64+zlib" in out


def test_decode_blob_unwraps_gzip_before_decoding() -> None:
    blob = base64.b64encode(gzip.compress(b"flag{gzip_inside_b64}")).decode()
    out = nonweb.decode_blob(blob)
    assert "flag{gzip_inside_b64}" in out
    assert "base64+gzip" in out


def test_decode_blob_reads_utf16_text() -> None:
    """UTF-16 is byte-for-byte valid UTF-8, so it must be tested first."""
    blob = base64.b64encode("flag{utf16_inside}".encode("utf-16-le")).decode()
    out = nonweb.decode_blob(blob)
    assert "flag{utf16_inside}" in out
    assert "utf-16-le" in out


def test_decode_blob_reports_the_branch_it_did_not_take() -> None:
    """The search keeps runner-ups; a dead top pick must name the alternative.

    The old greedy walk threw every other candidate away, so the next turn had
    no idea a second plausible reading even existed.
    """
    out = nonweb.decode_blob("%68%74%74%70&#58;//example.com%2F")
    assert "other branches that decoded" in out
    assert "'urlencode' instead of 'html-entity'" in out


def test_decode_blob_says_when_no_other_branch_decoded() -> None:
    out = nonweb.decode_blob(base64.b64encode(b"just some readable text here").decode())
    assert "no other branch decoded" in out
    assert "no decoding chain" not in out


# --------------------------------------------------------------------------
# unpack_archive
# --------------------------------------------------------------------------


def test_unpack_archive_extracts_and_reports(tmp_path: Path) -> None:
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("readme.txt", "flag{inside}")
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "readme.txt" in out
    assert (tmp_path / "out" / "readme.txt").read_text() == "flag{inside}"


def test_unpack_archive_refuses_escapes(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("ok.txt", "fine")
        handle.writestr("../escape.txt", "nope")
        handle.writestr("/abs.txt", "nope")
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "..' segment" in out
    assert "absolute path" in out
    assert not (tmp_path / "escape.txt").exists()


def test_unpack_archive_refuses_symlink_member(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        handle.writestr(info, "/etc/passwd")
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "symlink" in out


def test_unpack_archive_recurses_into_nested_archives(tmp_path: Path) -> None:
    """Nested archives are the norm; one extraction must reach the bottom."""
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as handle:
        handle.writestr("deep.txt", "flag{nested}")
    outer = tmp_path / "outer.tar"
    with tarfile.open(outer, "w") as handle:
        handle.add(inner, arcname="inner.zip")
    out = nonweb.unpack_archive(str(outer), out_dir=str(tmp_path / "out"))
    assert "deep.txt" in out
    assert "flag{nested}" in (tmp_path / "out" / "_d2" / "deep.txt").read_text()


def test_unpack_archive_budget_is_shared_across_depth(tmp_path: Path, monkeypatch) -> None:
    """The limit must not multiply with depth.

    Per-level budgets would allow 5 x 64MB on a 3GB VM; the bomb wins by
    arithmetic even though every single check "passed".
    """
    monkeypatch.setattr(nonweb, "_UNPACK_MAX_BYTES", 8)
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("a.txt", "12345")
        handle.writestr("b.txt", "12345")
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "budget" in out


def test_unpack_archive_missing_file_suggests_ls(tmp_path: Path) -> None:
    out = nonweb.unpack_archive(str(tmp_path / "nope.zip"))
    assert "ls -la" in out


# --------------------------------------------------------------------------
# hexpeek
# --------------------------------------------------------------------------


def test_hexpeek_shows_header_and_continuation(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(bytes(range(64)))
    out = nonweb.hexpeek(str(target), 0, 16)
    assert "00000000" in out
    assert "|" in out
    assert "continue with offset=16" in out


def test_hexpeek_accepts_hex_offset(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"A" * 32)
    out = nonweb.hexpeek(str(target), "0x10", 8)
    assert "range [16, 24)" in out


def test_hexpeek_past_end_is_explained(tmp_path: Path) -> None:
    target = tmp_path / "small.bin"
    target.write_bytes(b"A")
    out = nonweb.hexpeek(str(target), 100, 16)
    assert "past the end" in out


# --------------------------------------------------------------------------
# tcp / tcp_batch
# --------------------------------------------------------------------------


class _Server:
    """Loopback service that prints a banner, then echoes each line."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.sendall(b"ctf ready\n> ")
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(b"echo:" + data)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.sock.close()


def test_tcp_shows_banner_and_reply() -> None:
    server = _Server()
    try:
        out = nonweb.tcp("127.0.0.1", server.port, "hi\n", read_timeout=0.8)
    finally:
        server.close()
    assert "banner" in out
    assert "ctf ready" in out
    assert "echo:hi" in out


def test_tcp_reports_refused_port_as_actionable() -> None:
    out = nonweb.tcp("127.0.0.1", 1)
    # A refused port is a *specific* fact -- the box answered with RST -- and
    # must not be reported with the catch-all "cannot connect" wording that
    # also covers timeouts and unreachable hosts.  See PWN-8: the old text
    # called every OSError "a refused port on a running box", which was false
    # for a black-holed SYN and made the classifier mis-read timeouts.
    assert "connection refused" in out
    assert "next:" in out
    assert nonweb.tcp_connect_state(out) == "refused"


def test_tcp_batch_compares_on_one_connection() -> None:
    server = _Server()
    try:
        out = nonweb.tcp_batch(
            "127.0.0.1", server.port, ["41", "42"], hex_mode=True, read_timeout=0.6
        )
    finally:
        server.close()
    assert "#0" in out and "#1" in out
    assert "echo:A" in out and "echo:B" in out


def test_tcp_batch_caps_the_candidate_list() -> None:
    out = nonweb.tcp_batch("host", 1, [str(i) for i in range(500)])
    assert nonweb._BATCH_MAX == 200
    assert "payloads is empty" not in out


# --- PWN-4：把截断伪装成结论 ------------------------------------------------
#
# 旧 `_render` 打印长度后只给前 256 B hex / 600 B ascii，**切点上没有任何标记**：
# `reply 1100 B` 后面跟一个中途断掉的窗口，和"回复就到这里"长得一模一样。
# 字节级 oracle 的判别位几乎总在尾部，所以尾部窗口才是要紧的那个。


class _OneShot:
    """服务端先沉默，收到第一次发送后回一段长响应（两端可辨认）。"""

    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.recv(4096)
                conn.sendall(self.reply)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.sock.close()


def test_tcp_shows_both_edges_of_a_large_reply(tmp_path, monkeypatch) -> None:
    """3008 B 的回复：尾部的 `-TAIL` 必须看得见，中间被砍必须写明，全文可回读。"""
    monkeypatch.setenv("CTF_TCP_DUMP_DIR", str(tmp_path))
    reply = b"HEAD-" + b"M" * 3000 + b"-TAIL"
    server = _OneShot(reply)
    try:
        out = nonweb.tcp(
            "127.0.0.1", server.port, "go\n", read_timeout=0.6, max_recv=8192
        )
    finally:
        server.close()

    assert f"{len(reply)} B" in out, "总长度必须报，别让读者以为窗口就是全部"
    assert "-TAIL" in out, "尾部窗口缺失 —— 判别位常在最后几个字节"
    assert "NOT shown" in out, "中间被砍掉必须明写，不能安静地截断"
    assert str(tmp_path) in out, "全文应落盘并给出路径"
    assert "hexpeek" in out, "必须告诉模型怎么按偏移回读"


def test_tcp_render_small_body_says_nothing_was_cut() -> None:
    """反例：短回复不许出现任何截断标记，否则每行都在喊狼来了。"""
    text = nonweb._render(b"ok\n", "reply")

    assert "omitted" not in text
    assert "NOT stored" not in text
    assert len(text) < 200


def test_tcp_says_the_read_was_capped() -> None:
    """读满 max_recv 时必须说"这是前缀"，而不是把它当完整回复。"""
    server = _OneShot(b"X" * 3000)
    try:
        out = nonweb.tcp(
            "127.0.0.1", server.port, "go\n", read_timeout=0.6, max_recv=256
        )
    finally:
        server.close()

    assert "cap:" in out
    assert "NOT the whole reply" in out


def test_tcp_batch_row_shows_both_edges_of_a_long_response() -> None:
    """每行给两端：只比前 48 B 会把尾部不同的响应判成"一样"。"""
    body = b"A" * 24 + b"M" * 200 + b"Z" * 24
    row = nonweb._batch_row(3, 5, body, 1024, 4096)

    assert "#3" in row and "@1024" in row
    assert body[:24].hex() in row
    assert body[-24:].hex() in row, "尾部窗口缺失 —— oracle 判别位常在这里"
    assert "omitted" in row


def test_tcp_batch_row_keeps_short_bodies_whole() -> None:
    """短响应整段给：把 `echo:A` 拆成两段反而更难扫。"""
    row = nonweb._batch_row(0, 1, b"echo:A", 0, 1024)

    assert "echo:A" in row
    assert "omitted" not in row


def test_tcp_batch_dump_is_readable_by_offset(tmp_path, monkeypatch) -> None:
    """落盘的 body 必须能被 hexpeek 按偏移读回——否则"改落盘"等于没改。"""
    monkeypatch.setenv("CTF_TCP_DUMP_DIR", str(tmp_path))
    payload = b"HEAD" + b"." * 40 + bytes(range(16))

    path = nonweb._dump(payload, "batch")
    assert path, "有可写目录时必须落盘"
    assert Path(path).exists()
    assert Path(path).read_bytes() == payload

    tail = nonweb.hexpeek(path=path, offset=len(payload) - 16, length=16)
    assert "00 01 02 03" in tail


# --- P0#2：TLS-SNI 接入 ------------------------------------------------------
#
# 练习套的 `tcp_access` 就是 `tls_sni`：平台把所有 TCP 服务放在 TLS 后面，plain
# 连上去一个字节都读不到。`tcp` 早就支持 `tls=` 参数，但提示词里从没出现过它，
# 模型于是把"没有 banner"读成"服务不理我"。这里的三个用例守的是：显式 `tls=True`
# 能读到 banner、plain 空回显会自动重试一次、以及正常明文服务**不**白付一次连接。


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    """写一对一次性自签证书/私钥（不联网、不依赖 trustme）。"""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ctf.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_path / "cert.pem"
    key_pem = tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_pem, key_pem


class _TlsServer:
    """只讲 TLS 的 loopback 服务；plain 连接只会被晾着，这正是平台的形态。"""

    def __init__(self, cert: Path, key: Path) -> None:
        self.sni_seen: list[str] = []
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(str(cert), str(key))
        self.ctx.set_servername_callback(self._on_sni)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _on_sni(self, _sock, name, _ctx) -> None:
        if name:
            self.sni_seen.append(name)

    def _serve(self) -> None:
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                try:
                    raw.close()
                except OSError:
                    pass
                continue
            try:
                conn.sendall(b"tls banner\n> ")
                data = conn.recv(4096)
                if data:
                    conn.sendall(b"tls echo:" + data)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self) -> None:
        self.sock.close()


def test_tcp_reads_a_tls_only_service_with_explicit_tls(tmp_path) -> None:
    """报告 §6.1 第 2 条：TLS 自签 echo 服务，tcp(tls=True, sni=...) 读到 banner。"""
    cert, key = _self_signed(tmp_path)
    server = _TlsServer(cert, key)
    try:
        out = nonweb.tcp(
            "127.0.0.1",
            server.port,
            "hi\n",
            read_timeout=0.8,
            tls=True,
            sni="vhost.ctf.test",
        )
    finally:
        server.close()

    assert " connected in " in out, out
    assert "tls=True" in out
    assert "tls banner" in out
    assert "tls echo:hi" in out
    # 判活契约：TLS 成功仍然算 live，首行前缀一字未动。
    assert nonweb.tcp_connect_state(out) == "live"
    assert "vhost.ctf.test" in server.sni_seen


def test_tcp_retries_once_with_tls_when_plain_gets_nothing(tmp_path) -> None:
    """plain 连上却零字节 -> 自动换 TLS 重试一次，并把这件事说出来。"""
    cert, key = _self_signed(tmp_path)
    server = _TlsServer(cert, key)
    try:
        out = nonweb.tcp("127.0.0.1", server.port, read_timeout=0.5)
    finally:
        server.close()

    assert " connected in " in out, out
    assert "auto-TLS" in out
    assert "tls=True" in out
    assert "tls banner" in out
    assert nonweb.tcp_connect_state(out) == "live"


def test_tcp_does_not_retry_on_a_working_plain_service() -> None:
    """反例：明文服务读到了字节，就不许再为 TLS 付一次连接。"""
    server = _Server()
    try:
        out = nonweb.tcp("127.0.0.1", server.port, "hi\n", read_timeout=0.8)
    finally:
        server.close()

    assert "ctf ready" in out
    assert "auto-TLS" not in out
    assert "tls=False" in out


def test_plain_looks_like_tls_signals() -> None:
    assert nonweb._plain_looks_like_tls(b"ctf ready\n", b"") is False
    assert nonweb._plain_looks_like_tls(b"", b"") is True
    assert nonweb._plain_looks_like_tls(b"", b"\x15\x03\x01\x00\x02\x02\x28") is True
    assert nonweb._plain_looks_like_tls(b"", b"\x16\x03\x01") is True
    assert nonweb._plain_looks_like_tls(b"", b"HTTP/1.1 200 OK") is False


def test_tcp_batch_says_an_all_empty_run_may_be_tls(tmp_path) -> None:
    """整批零回显时不能只留空行：要指向 tls=True，而不是让模型断言"服务无视输入"。"""
    cert, key = _self_signed(tmp_path)
    server = _TlsServer(cert, key)
    try:
        out = nonweb.tcp_batch(
            "127.0.0.1", server.port, payloads=["41", "42"], read_timeout=0.5
        )
    finally:
        server.close()

    assert "every payload came back empty" in out
    assert "tls=True" in out


def test_tcp_batch_keeps_the_tls_note_off_a_live_plain_run() -> None:
    server = _Server()
    try:
        out = nonweb.tcp_batch(
            "127.0.0.1", server.port, payloads=["41", "42"], read_timeout=0.5
        )
    finally:
        server.close()

    assert "every payload came back empty" not in out


# --- BLOCKER 1/2：EOF 不是"还有字节"，TLS 探测不重放 payload -------------------


def test_tcp_complete_one_shot_reply_is_not_called_a_prefix() -> None:
    """对端 FIN 之后不许再说"还在发"：一次性服务每条完整回复都会撞上这句。"""
    server = _OneShot(b"done\n")
    try:
        out = nonweb.tcp("127.0.0.1", server.port, "go\n", read_timeout=0.6)
    finally:
        server.close()

    assert "done" in out
    assert "was still sending" not in out
    assert "Rerun with a larger read_timeout" not in out


def test_tcp_expect_miss_after_fin_is_a_plain_not_found() -> None:
    """EOF 之后的 expect 未命中就是"没有"，不是"读得太少所以不敢说"。"""
    server = _OneShot(b"done\n")
    try:
        out = nonweb.tcp(
            "127.0.0.1", server.port, "go\n", expect="never-here", read_timeout=0.6
        )
    finally:
        server.close()

    assert "expect: not found" in out
    assert "absence here is not evidence of absence" not in out


class _Silent:
    """收连接但永不说话，并记录每条连接收到的字节——重放会在这里现形。"""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.received: list[bytes] = []
        #: Kept open on purpose: a silent plaintext peer must be able to swallow
        #: a whole TLS ClientHello without the handshake ending early, otherwise
        #: the timing assertion below measures a FIN rather than the probe budget.
        self.conns: list[socket.socket] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.conns.append(conn)
            buf = b""
            try:
                conn.settimeout(0.6)
                while True:
                    try:
                        data = conn.recv(4096)
                    except (TimeoutError, socket.timeout):
                        break
                    except OSError:
                        break
                    if not data:
                        break
                    buf += data
            finally:
                self.received.append(buf)

    def close(self) -> None:
        self.sock.close()
        for conn in self.conns:
            try:
                conn.close()
            except OSError:
                pass


def test_tcp_silent_plain_service_does_not_pay_a_full_tls_handshake() -> None:
    """静默明文端口只该付一个短探测窗，并且探测不许重发调用方的 payload。"""
    server = _Silent()
    try:
        started = time.monotonic()
        out = nonweb.tcp("127.0.0.1", server.port, "hi\n", read_timeout=0.5)
        elapsed = time.monotonic() - started
        deadline = time.monotonic() + 2.0
        while len(server.received) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        received = list(server.received)
    finally:
        server.close()

    assert elapsed < 5.0, f"one tcp() took {elapsed:.1f}s"
    assert "auto-TLS" not in out
    assert "tls=True" in out, "the TLS probe never ran -- the timing claim is vacuous"
    assert len(received) >= 2, f"probe connection not seen: {received!r}"
    assert all(b"hi\n" not in chunk for chunk in received[1:]), (
        "the TLS probe replayed the caller's payload"
    )


# --------------------------------------------------------------------------
# elfpeek
# --------------------------------------------------------------------------


def _tiny_elf() -> bytes:
    """One PT_LOAD, ``pop rdi; ret`` at the entry, plus /bin/sh."""
    import struct

    size = 0x400
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    struct.pack_into("<H", data, 16, 2)   # ET_EXEC
    struct.pack_into("<H", data, 18, 62)  # x86-64
    struct.pack_into("<Q", data, 24, 0x400078)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<II", data, 64, 1, 5)
    struct.pack_into("<QQQQ", data, 72, 0, 0x400000, 0x400000, size)
    code = b"\x5f\xc3" + b"/bin/sh\x00"
    return bytes(data[: 0x78] + code + data[0x78 + len(code) :])


def test_elfpeek_info_names_mitigations_and_next_step(tmp_path: Path) -> None:
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target))
    assert "PIE=False" in out
    assert "entry segment" in out
    assert "next:" in out


def test_elfpeek_gadgets_finds_patterns(tmp_path: Path) -> None:
    """Gadget search must work whether or not a decoder is installed."""
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "pop rdi; ret" in out
    assert "/bin/sh" in out


def test_gadgets_fall_back_to_byte_patterns_without_a_decoder(
    tmp_path: Path, monkeypatch
) -> None:
    """The delivery image may ship without capstone; the fixed patterns must hold."""
    monkeypatch.setattr(nonweb, "_capstone", lambda _elf: None)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "pop rdi; ret" in out
    assert "/bin/sh" in out


def test_incomplete_gadget_scan_does_not_claim_absence(
    tmp_path: Path, monkeypatch
) -> None:
    """A walk that ran out of budget must say so, not answer "not there".

    The old code reported "not found" for every needle it had not reached, so
    a real libc hit the 4 s deadline and the tool told the model the binary
    lacks ``pop rdi``.  The budget is negative here so the walk stops at the
    first check, which is the same code path a slow binary takes.
    """
    monkeypatch.setattr(nonweb, "_GADGET_BUDGET_S", -1.0)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "scan INCOMPLETE" in out
    assert "INCOMPLETE SCAN" in out
    assert "decode budget ran out" in out
    # The /bin/sh row is a whole-file byte scan: it stays honest either way.
    assert "/bin/sh" in out


def test_incomplete_scan_states_its_ret_site_cap(tmp_path: Path, monkeypatch) -> None:
    """Hitting the per-segment ret cap is also "did not look", not "not there"."""
    monkeypatch.setattr(nonweb, "_GADGET_RET_CAP", 0)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "ret site(s)" in out
    assert "scan INCOMPLETE" in out
    assert "INCOMPLETE SCAN" in out


def test_complete_gadget_scan_still_reports_a_real_absence(tmp_path: Path) -> None:
    """The honest "not found" must survive: a full walk may still say absent.

    Without this, the fix for the previous two tests would be satisfied by
    shouting INCOMPLETE on every scan, which is the same information loss
    with the sign flipped.
    """
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets", filt="syscall")
    assert "not found (1 executable segment(s) decoded)" in out
    assert "INCOMPLETE" not in out


def test_pattern_scan_names_the_patterns_it_did_not_reach(
    tmp_path: Path, monkeypatch
) -> None:
    """The row limit is the fallback path's only blind spot; it must be named."""
    monkeypatch.setattr(nonweb, "_capstone", lambda _elf: None)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets", limit=2)
    assert "not scanned (limit=2)" in out
    assert "pop rdi; ret" in out
    assert "/bin/sh" in out


def _elf_with_symtab() -> bytes:
    """A linked ELF with .symtab/.strtab, so symbol lookup has something to read.

    Hand-built on purpose: it pins the two header fields that are easy to
    confuse (``sh_name`` vs ``sh_link``, and ``st_info`` type vs binding)
    without depending on whatever toolchain happens to be installed.
    """
    import struct

    size = 0x800
    data = bytearray(size)
    code_off = 0x100
    code = bytes([
        0x55,                                # push rbp
        0x48, 0x89, 0xe5,                    # mov rbp, rsp
        0x8b, 0x45, 0xfc,                    # mov eax, [rbp-4]
        0x83, 0xc0, 0x01,                    # add eax, 1
        0x89, 0x45, 0xfc,                    # mov [rbp-4], eax
        0x5d,                                # pop rbp
        0xc3,                                # ret
    ])
    main_off = code_off + len(code)
    main_code = bytes([0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3])
    data[code_off:code_off + len(code)] = code
    data[main_off:main_off + len(main_code)] = main_code

    base = 0x400000
    data[0:4] = b"\x7fELF"; data[4] = 2; data[5] = 1; data[6] = 1
    struct.pack_into("<H", data, 16, 2)      # ET_EXEC
    struct.pack_into("<H", data, 18, 62)     # x86-64
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 24, base + code_off)
    struct.pack_into("<Q", data, 32, 64)     # e_phoff
    struct.pack_into("<Q", data, 40, 0x400)  # e_shoff
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 5)
    struct.pack_into("<H", data, 62, 4)      # .shstrtab is section 4
    struct.pack_into("<II", data, 64, 1, 5)
    struct.pack_into("<QQQQ", data, 72, 0, base, base, size)

    shstr = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    data[0x200:0x200 + len(shstr)] = shstr        # .text=1 .symtab=7 .strtab=15
    strtab = b"\x00check\x00main\x00"
    data[0x240:0x240 + len(strtab)] = strtab      # check=1 main=7
    sym_off = 0x280
    struct.pack_into("<IBBHQQ", data, sym_off, 0, 0, 0, 0, 0, 0)
    # st_info = (GLOBAL << 4) | FUNC
    struct.pack_into("<IBBHQQ", data, sym_off + 24, 1, 0x12, 0, 1, base + code_off, len(code))
    struct.pack_into("<IBBHQQ", data, sym_off + 48, 7, 0x12, 0, 1, base + main_off, len(main_code))

    def _sh(name, typ, flags, addr, off, sz, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, typ, flags, addr, off, sz,
                           link, info, align, entsize)

    data[0x400:0x440] = _sh(0, 0, 0, 0, 0, 0)
    data[0x440:0x480] = _sh(1, 1, 6, base + code_off, code_off, 0x100)
    data[0x480:0x4C0] = _sh(7, 2, 0, 0, sym_off, 72, 3, 1, 8, 24)
    data[0x4C0:0x500] = _sh(15, 3, 0, 0, 0x240, len(strtab))
    data[0x500:0x540] = _sh(23, 3, 0, 0, 0x200, len(shstr))
    return bytes(data)


def test_symbol_table_is_read_from_the_linked_string_table(tmp_path: Path) -> None:
    """``sh_link`` names the string table; ``sh_name`` is only a name offset.

    Reading ``sh_name`` as a section index made every symbol lookup return
    nothing, so ``elfpeek view=symbols`` claimed "stripped" for binaries that
    had a full symbol table, and ``elffind symbol=`` never resolved anything.
    """
    target = tmp_path / "sym.elf"
    target.write_bytes(_elf_with_symtab())
    out = nonweb.elfpeek(str(target), view="symbols")
    assert "check" in out and "main" in out, out
    assert "stripped" not in out, out


def test_symbol_type_is_the_low_nibble_of_st_info(tmp_path: Path) -> None:
    """``st_info`` packs type low and binding high; FUNC must not read OBJECT."""
    target = tmp_path / "sym.elf"
    target.write_bytes(_elf_with_symtab())
    out = nonweb.elfpeek(str(target), view="symbols")
    assert "FUNC" in out, out
    assert "OBJECT" not in out, out


def test_disasm_by_symbol_returns_the_whole_function(tmp_path: Path) -> None:
    """One call must give one function, not an arbitrary byte window."""
    target = tmp_path / "sym.elf"
    target.write_bytes(_elf_with_symtab())
    out = nonweb.elfpeek(str(target), view="disasm", symbol="check")
    assert "symbol check" in out, out
    if "no disassembler" in out:
        return
    # Every instruction of check(), ending at its ret -- and nothing from main.
    assert "push" in out and "ret" in out, out
    assert "main" not in out.replace("symbol check", ""), out


def test_elffind_reports_offsets(tmp_path: Path) -> None:
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elffind(str(target), search="/bin/sh")
    assert "/bin/sh" in out
    assert "file 0x" in out


def test_elfpeek_rejects_non_elf(tmp_path: Path) -> None:
    target = tmp_path / "not.elf"
    target.write_text("hello")
    out = nonweb.elfpeek(str(target))
    assert "not an ELF" in out


def test_elfpeek_unknown_view_lists_choices(tmp_path: Path) -> None:
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="nope")
    assert "unknown view" in out
    assert "elffind" in out


_EFLPEEK_VIEWS = {"info", "sections", "symbols", "strings", "gadgets", "disasm", "wide"}


def _named_views(text: str) -> set[str]:
    """Every ``view='X'`` an output mentions, without pulling in ``re``."""
    found: set[str] = set()
    marker = "view='"
    start = text.find(marker)
    while start >= 0:
        end = text.find("'", start + len(marker))
        if end < 0:
            break
        found.add(text[start + len(marker): end])
        start = text.find(marker, end + 1)
    return found


def test_elfpeek_only_advertises_views_it_implements(
    tmp_path: Path, monkeypatch
) -> None:
    """Every ``view='X'`` an output names must be one ``elfpeek`` accepts.

    The non-PIE hint used to end with ``view='lookup'`` -- a view that never
    existed, so following it returned "unknown view" exactly where a ret2libc
    run went looking for ``system`` (REVIEW-20261112 REV-3).
    """
    monkeypatch.setattr(nonweb, "_capstone", lambda _elf: None)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    for view in sorted(_EFLPEEK_VIEWS):
        out = nonweb.elfpeek(str(target), view=view)
        named = _named_views(out)
        assert named <= _EFLPEEK_VIEWS, (view, named - _EFLPEEK_VIEWS, out)
    linked = tmp_path / "sym.elf"
    linked.write_bytes(_elf_with_symtab())
    info = nonweb.elfpeek(str(linked), view="info")
    assert "PIE=False" in info
    assert "elffind" in info, "the ret2libc hint must name the address tool"
    assert "lookup" not in info, "elffind is the lookup tool, not a view"


def test_elfpeek_schema_does_not_carry_lookup_parameters(tmp_path: Path) -> None:
    """Lookup parameters belong to the view that uses them.

    Measured: the combined schema was 1,576 chars -- larger than the whole
    ``file_triage`` tool.  Splitting keeps the per-call surface honest.

    ``symbol`` is the one exception and it is deliberate: ``disasm`` without it
    can only read "128 bytes from some offset", which is not how a check
    function gets read.  ``search`` stays on ``elffind`` because resolving a
    byte string to an address is a different question from reading code.
    """
    seen: list = []

    def collect(*tools) -> None:
        seen.extend(tools)

    nonweb.register(register_fn=collect, kind="file")
    schemas = {
        tool.name: set(tool.params_json_schema["properties"]) for tool in seen
    }
    assert "symbol" in schemas["elfpeek"]
    assert "search" not in schemas["elfpeek"]
    assert "utf16" not in schemas["elfpeek"]
    assert {"symbol", "search"} <= schemas["elffind"]


def test_disasm_reports_where_it_stopped(tmp_path: Path) -> None:
    """A truncated disassembly must say so and name the resume offset.

    Silently ending at the row cap reads like "the function ends here"; that
    is how a run concludes the wrong thing about a long check function.
    """
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        # Truncation can only be reported by a real decoder. The image installs
        # capstone; this branch is a developer box without it.
        return
    out = nonweb.elfpeek(str(target), view="disasm", offset=0x100, length=256, limit=3)
    assert "truncated" in out, out
    assert "continue with offset=" in out, out


def _disasm_rows(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if re.match(r"^[0-9a-f]{8}  ", ln)]


def test_disasm_keeps_the_resume_hint_when_the_listing_is_long(
    tmp_path: Path,
) -> None:
    """``_clip`` cuts the tail, and the resume line used to *be* the tail.

    A 4 000-character window is roughly 70 rows against a 600-row cap, so on
    any real function the line saying "continue with offset=..." was the first
    thing ``_clip`` threw away -- the longer the listing, the more certain the
    loss.  The fix spends a byte budget up front and reserves room for that
    line, which also makes ``emitted`` equal to what was actually printed: the
    old code counted rows it then clipped away, so even a surviving hint named
    an offset that skipped instructions the reader never saw.
    """
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        return
    out = nonweb.elfpeek(
        str(target), view="disasm", offset=0x100, length=0x300, limit=600
    )
    assert len(out) <= nonweb._CLIP_DEFAULT, len(out)
    assert "continue with offset=" in out, out[-200:]
    shown = _disasm_rows(out)
    # The sled is ``00 00`` pairs, so each printed instruction is 2 bytes and
    # the next unprinted one sits at 0x100 + 2 * len(shown).  If the offset
    # points anywhere else, rows were dropped without being counted.
    match = re.search(r"continue with offset=0x([0-9a-f]+)", out)
    assert match, out[-200:]
    assert int(match.group(1), 16) == 0x100 + 2 * len(shown), (match.group(1), len(shown))
    counted = re.search(r"truncated at (\d+) instructions", out)
    assert counted and int(counted.group(1)) == len(shown), out[-200:]
    # The 600-row cap is not what stopped this listing, so saying "raise
    # limit" would send the reader after a knob that cannot widen the window.
    assert "output window" in out, out[-200:]
    assert "raise limit" not in out, out[-200:]


def test_disasm_drops_the_resume_hint_when_nothing_is_truncated(
    tmp_path: Path,
) -> None:
    """The counter-case: a window that fits must not claim it was cut."""
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        return
    out = nonweb.elfpeek(
        str(target), view="disasm", offset=0x100, length=16, limit=600
    )
    assert _disasm_rows(out)
    assert "truncated" not in out, out
    assert "continue with offset=" not in out, out


def test_disasm_by_symbol_names_the_symbol(tmp_path: Path) -> None:
    """``symbol=`` resolves through the symbol table instead of guessing."""
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="disasm", symbol="not_a_symbol_here")
    assert "no function symbol" in out, out


def test_disasm_without_a_decoder_names_a_working_command(
    tmp_path: Path, monkeypatch
) -> None:
    """No decoder must degrade to bytes plus a command the image really has."""
    monkeypatch.setattr(nonweb, "_capstone", lambda _elf: None)
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="disasm", offset=0, length=16)
    assert "[elfpeek]" in out
    assert "objdump -d" in out, out


# --------------------------------------------------------------------------
# machine-aware decoding (REVIEW-20261112 PWN-6 / REV-4)
# --------------------------------------------------------------------------


def _elf_image(
    machine: int,
    code: bytes,
    *,
    is64: bool = True,
    endian: str = "<",
    entry_in_code: int = 0,
) -> bytes:
    """Minimal one-PT_LOAD executable whose entry points into ``code``."""
    import struct

    fmt = "<" if endian == "<" else ">"
    size = 0x400
    base = 0x400000
    code_at = 0x78
    data = bytearray(size)
    data[0:4] = b"\x7fELF"
    data[4] = 2 if is64 else 1
    data[5] = 1 if endian == "<" else 2
    struct.pack_into(fmt + "H", data, 16, 2)  # ET_EXEC
    struct.pack_into(fmt + "H", data, 18, machine)
    entry = base + code_at + entry_in_code
    if is64:
        struct.pack_into(fmt + "Q", data, 24, entry)
        struct.pack_into(fmt + "Q", data, 32, 64)  # e_phoff
        struct.pack_into(fmt + "HHHH", data, 52, 64, 56, 1, 64)
        struct.pack_into(fmt + "II", data, 64, 1, 5)  # PT_LOAD | PF_X
        struct.pack_into(fmt + "QQQQ", data, 72, 0, base, base, size)
    else:
        struct.pack_into(fmt + "I", data, 24, entry)
        struct.pack_into(fmt + "I", data, 28, 52)  # e_phoff
        struct.pack_into(fmt + "HHHH", data, 40, 52, 32, 1, 40)
        struct.pack_into(fmt + "I", data, 52, 1)  # PT_LOAD
        struct.pack_into(fmt + "I", data, 56, 0)  # p_offset
        struct.pack_into(fmt + "I", data, 60, base)  # p_vaddr
        struct.pack_into(fmt + "I", data, 64, base)  # p_paddr
        struct.pack_into(fmt + "I", data, 68, size)  # p_filesz
        struct.pack_into(fmt + "I", data, 72, size)  # p_memsz
        struct.pack_into(fmt + "I", data, 76, 5)  # p_flags
    return bytes(data[:code_at] + code + data[code_at + len(code):])


# ``mov fp, #0; bx lr`` -- how an ARM32 function returns.
_ARM_RETURN = bytes.fromhex("00b0a0e31eff2fe1")
# ``stp x29, x30, [sp, #-0x10]!; mov x29, sp; ret`` -- AArch64.
_AARCH64_RETURN = bytes.fromhex("fd7bbfa9fd030091c0035fd6")


def test_disasm_decodes_arm_with_the_arm_backend(tmp_path: Path) -> None:
    """An ARM file must decode as ARM, never as plausible-looking x86.

    ``_capstone`` used to hand every ELF to ``CS_ARCH_X86``: these exact bytes
    came back as ``add byte ptr [eax - 0xe11c60], dh; das`` -- false
    instructions presented as fact.
    """
    target = tmp_path / "arm.elf"
    target.write_bytes(_elf_image(40, _ARM_RETURN, is64=False))
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        return  # developer box without capstone; the image installs it
    out = nonweb.elfpeek(str(target), view="disasm", offset=0x78, length=16)
    assert "disasm arm " in out, out
    assert "bx" in out and "lr" in out, out
    assert "add byte ptr" not in out, out


def test_disasm_decodes_aarch64_with_the_arm64_backend(tmp_path: Path) -> None:
    target = tmp_path / "a64.elf"
    target.write_bytes(_elf_image(183, _AARCH64_RETURN))
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        return
    out = nonweb.elfpeek(str(target), view="disasm", offset=0x78, length=16)
    assert "disasm aarch64 " in out, out
    assert "ret" in out, out
    # The prologue, so a decode of zero bytes cannot pass this test.
    assert "x29" in out, out


def test_disasm_never_fakes_x86_for_an_unknown_machine(tmp_path: Path) -> None:
    """RISC-V gets "no decoder wired", not x86 text and not "this file has no code".

    The message must blame ``elfpeek``'s table, not capstone: capstone 5 ships a
    RISC-V backend, so "capstone has no backend" would be a false claim about a
    library that in fact has one.
    """
    target = tmp_path / "rv.elf"
    target.write_bytes(_elf_image(243, b"\x13\x05\x10\x00"))  # addi a0, zero, 1
    out = nonweb.elfpeek(str(target), view="disasm", offset=0x78, length=16)
    assert "no disassembler available" in out, out
    assert "elfpeek has no decoder wired for e_machine=0xf3 (RISC-V)" in out, out
    assert "capstone is not installed" not in out, out
    assert "-M intel" not in out, f"an x86 objdump flag on a RISC-V file: {out}"
    assert "file offset 0x78" in out, out


def test_arm_entry_bit_selects_thumb_mode() -> None:
    """Bit 0 of an ARM entry point means Thumb; the walk must decode that."""
    elf = nonweb._Elf(_elf_image(40, b"\x70\x47", is64=False, entry_in_code=1))
    assert nonweb._decoder_label(elf) == "thumb"


def test_gadgets_on_a_non_x86_file_name_the_pattern_language(tmp_path: Path) -> None:
    """The fallback patterns are x86 byte sequences; saying so is the fix."""
    target = tmp_path / "arm.elf"
    target.write_bytes(_elf_image(40, _ARM_RETURN + b"/bin/sh\x00", is64=False))
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "x86 byte sequences" in out, out
    assert "e_machine=0x28 (ARM)" in out, out
    assert "/bin/sh" in out, out


def test_disasm_still_labels_x86_and_decodes_it(tmp_path: Path) -> None:
    """The architecture table must not cost x86 its own decoder."""
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    if nonweb._capstone(nonweb._Elf(target.read_bytes())) is None:
        return
    out = nonweb.elfpeek(str(target), view="disasm", offset=0x78, length=16)
    assert "disasm x86-64 " in out, out
    assert "pop" in out and "rdi" in out, out


# --------------------------------------------------------------------------
# RELRO level (REVIEW-20261112 PWN-7)
# --------------------------------------------------------------------------


def _elf_with_relro(
    *,
    relro: bool = True,
    bind_now: str = "none",
    is64: bool = True,
    after_null: tuple[int, int] | None = None,
) -> bytes:
    """Minimal ELF with a ``PT_DYNAMIC`` array and optionally ``PT_GNU_RELRO``.

    ``bind_now`` picks which spelling of "bind eagerly" the linker used:
    ``"tag"`` (DT_BIND_NOW), ``"flags"`` (DT_FLAGS & DF_BIND_NOW) or
    ``"flags1"`` (DT_FLAGS_1 & DF_1_NOW).  glibc honours all three, so a check
    that looks at only one reports Partial RELRO for a Full RELRO binary.
    """
    import struct

    base = 0x400000
    dyn_at = 0x200
    entry_size = 16 if is64 else 8
    entries: list[tuple[int, int]] = []
    if bind_now == "tag":
        entries.append((24, 0))  # DT_BIND_NOW
    elif bind_now == "flags":
        entries.append((30, 0x8))  # DT_FLAGS & DF_BIND_NOW
    elif bind_now == "flags1":
        entries.append((0x6FFFFFFB, 0x1))  # DT_FLAGS_1 & DF_1_NOW
    entries.append((0, 0))  # DT_NULL terminates the array
    if after_null is not None:
        entries.append(after_null)  # padding, never part of the array

    data = bytearray(0x400)
    data[0:4] = b"\x7fELF"
    data[4] = 2 if is64 else 1
    data[5] = 1
    struct.pack_into("<H", data, 16, 2)  # ET_EXEC
    struct.pack_into("<H", data, 18, 62 if is64 else 3)
    phdr_at, phdr_size = (64, 56) if is64 else (52, 32)
    dyn_size = len(entries) * entry_size
    phdrs = [(1, 5, 0, base, len(data))]  # PT_LOAD, PF_R|PF_X
    if relro:
        phdrs.append((0x6474E552, 4, dyn_at, base + dyn_at, dyn_size))  # PT_GNU_RELRO
    phdrs.append((2, 6, dyn_at, base + dyn_at, dyn_size))  # PT_DYNAMIC
    if is64:
        struct.pack_into("<QQ", data, 24, base, phdr_at)  # e_entry, e_phoff
        struct.pack_into("<HHHH", data, 52, 64, 56, len(phdrs), 64)
    else:
        struct.pack_into("<II", data, 24, base, phdr_at)
        struct.pack_into("<HHHH", data, 40, 52, 32, len(phdrs), 40)
    for index, (p_type, p_flags, p_offset, p_vaddr, p_filesz) in enumerate(phdrs):
        at = phdr_at + index * phdr_size
        if is64:
            struct.pack_into("<II", data, at, p_type, p_flags)
            struct.pack_into(
                "<QQQQ", data, at + 8, p_offset, p_vaddr, base + p_offset, p_filesz
            )
            struct.pack_into("<QQ", data, at + 40, p_filesz, 0x1000)
        else:
            struct.pack_into(
                "<IIIIIIII", data, at, p_type, p_offset, p_vaddr,
                base + p_offset, p_filesz, p_filesz, p_flags, 0x1000,
            )
    entry_fmt = "<qQ" if is64 else "<iI"
    for index, (tag, value) in enumerate(entries):
        struct.pack_into(entry_fmt, data, dyn_at + index * entry_size, tag, value)
    return bytes(data)


def test_relro_is_full_when_any_eager_binding_tag_is_present() -> None:
    """All three linker spellings mean Full RELRO; checking one loses the other two."""
    for spelling in ("tag", "flags", "flags1"):
        info = nonweb._Elf(_elf_with_relro(bind_now=spelling)).security()
        assert info["RELRO_level"] == "Full RELRO", spelling
        assert info["BIND_NOW"] is True, spelling
        assert info["RELRO"] is True, spelling


def test_relro_is_partial_with_the_segment_but_lazy_binding() -> None:
    info = nonweb._Elf(_elf_with_relro()).security()
    assert info["RELRO_level"] == "Partial RELRO", info
    assert info["BIND_NOW"] is False, info
    assert info["RELRO"] is True, info


def test_relro_is_absent_without_the_segment() -> None:
    """DF_1_NOW alone does not make Full RELRO: there is no page to protect."""
    info = nonweb._Elf(_elf_with_relro(relro=False, bind_now="flags1")).security()
    assert info["RELRO_level"] == "No RELRO", info
    assert info["RELRO"] is False, info


def test_relro_level_on_a_32_bit_elf() -> None:
    info = nonweb._Elf(_elf_with_relro(bind_now="flags", is64=False)).security()
    assert info["RELRO_level"] == "Full RELRO", info
    assert info["BIND_NOW"] is True, info


def test_dynamic_array_stops_at_dt_null() -> None:
    """A tag after DT_NULL is padding; reading it would invent Full RELRO."""
    info = nonweb._Elf(_elf_with_relro(after_null=(30, 0x8))).security()
    assert info["RELRO_level"] == "Partial RELRO", info


def test_info_prints_the_level_and_what_it_allows(tmp_path: Path) -> None:
    """The GOT/``__free_hook`` fork depends on this line, so it names the effect."""
    partial = tmp_path / "partial.elf"
    partial.write_bytes(_elf_with_relro())
    out = nonweb.elfpeek(str(partial), view="info")
    assert "RELRO=Partial RELRO" in out, out
    assert ".got.plt writable" in out, out
    assert "RELRO=True" not in out, out

    plain = tmp_path / "plain.elf"
    plain.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(plain), view="info")
    assert "RELRO=No RELRO (GOT writable)" in out, out


# --------------------------------------------------------------------------
# registration split
# --------------------------------------------------------------------------


def test_register_splits_by_kind() -> None:
    seen: list = []

    def collector(*tools) -> None:
        seen.extend(tools)

    file_names = nonweb.register(register_fn=collector, kind="file")
    assert set(file_names) == {
        "decode_blob", "unpack_archive", "hexpeek", "elfpeek", "elffind",
    }

    seen.clear()
    tcp_names = nonweb.register(register_fn=collector, kind="tcp")
    # A remote-binary challenge ships the binary: the playbook's first move is
    # "``elffind`` the offset, then send it".  Sockets alone made that
    # instruction unexecutable (REVIEW-20261112 PWN-1).
    assert set(tcp_names) == {
        "decode_blob", "unpack_archive", "hexpeek", "elfpeek", "elffind",
        "tcp", "tcp_batch",
    }
    assert set(file_names) < set(tcp_names), "tcp must be a superset of file"

    seen.clear()
    assert nonweb.register(register_fn=collector, kind="web") == []
    assert seen == []


def test_network_tools_are_not_probe_tools() -> None:
    """Guards must not scream at the correct use of ``tcp_batch``.

    ``sweep_guard`` fires at 24 distinct values in one call; ``tcp_batch``
    exists to send 200.  If it were a probe tool the hint would be permanently
    on, and a permanently-on hint teaches the model to ignore hints.
    """
    from ctf_strix import probe_surface

    assert not (probe_surface.NETWORK_TOOLS & probe_surface.PROBE_TOOLS)
    for name in probe_surface.NETWORK_TOOLS:
        assert not probe_surface.is_probe_tool(name)

def test_unpack_names_7z_instead_of_calling_it_unknown(tmp_path: Path) -> None:
    """A 7z that cannot be extracted must not look like a corrupt file.

    "detected unknown, nothing extracted" invites a retry of the same tool.
    The magic bytes are conclusive, so say what it is and where the reader
    situation stands -- that is the observation that changes the next action.
    """
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 300)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected 7z" in out, out
    assert "unknown" not in out, out
    if shutil.which("7z"):
        # Real binary present: garbage bytes make it fail, and the failure
        # must be attributed to 7z, not to a missing reader.
        assert "7z failed" in out, out
        assert "no 7z reader" not in out, out
    else:
        assert "no 7z reader" in out, out
        assert "offset 0x0" in out, out


def test_unpack_finds_a_rar_signature_behind_an_sfx_stub(tmp_path: Path) -> None:
    """RAR self-extracting stubs put up to 64KB before the signature."""
    archive = tmp_path / "sfx.rar"
    archive.write_bytes(b"MZ" + b"\x00" * 4096 + b"Rar!\x1a\x07\x00" + b"\x00" * 128)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    if shutil.which("7z"):
        # The binary owns RAR now, so garbage after the signature is a 7z
        # failure -- not a "this image has no reader" claim, which would be
        # false on the image (p7zip-full reads RAR/RAR5).
        assert "7z failed" in out, out
        assert "no rar reader" not in out, out
    else:
        assert "no rar reader" in out, out
        # The message must not pretend the file *is* a bare RAR: it is an SFX stub.
        assert "offset 0x1002" in out, out


def test_unpack_says_no_rar_reader_when_the_binary_is_absent(
    tmp_path: Path, monkeypatch
) -> None:
    """Deterministic "no 7z on this host" branch, whatever the real host has."""
    monkeypatch.setattr(nonweb, "_seven_zip", lambda: None)
    archive = tmp_path / "sfx.rar"
    archive.write_bytes(b"MZ" + b"\x00" * 4096 + b"Rar!\x1a\x07\x00" + b"\x00" * 128)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    assert "no rar reader" in out, out
    assert "offset 0x1002" in out, out
    # Retrying the same call cannot help; the tool has to say so.
    assert "Do not retry unpack_archive" in out, out


@pytest.mark.skipif(shutil.which("7z") is None, reason="no 7z binary on this host")
def test_unpack_extracts_7z_when_the_binary_is_present(tmp_path: Path) -> None:
    """With the system 7z available, a real archive must extract and recurse."""
    payload = tmp_path / "work" / "payload.txt"
    payload.parent.mkdir()
    payload.write_bytes(b"payload-7z-roundtrip")
    archive = tmp_path / "a.7z"
    subprocess.run(
        ["7z", "a", "-t7z", str(archive), str(payload)],
        capture_output=True, check=True, cwd=str(tmp_path),
    )
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected 7z" in out, out
    assert "no 7z reader" not in out, out
    assert "payload.txt" in out, out
    assert any(p.name == "payload.txt" for p in (tmp_path / "out").rglob("*"))


@pytest.mark.skipif(shutil.which("7z") is None, reason="no 7z binary on this host")
def test_unpack_recurses_into_a_7z_inside_a_zip(tmp_path: Path) -> None:
    """A 7z nested in a zip must be picked up on the next walk level."""
    payload = tmp_path / "payload.txt"
    payload.write_bytes(b"payload-zip-7z-nesting")
    inner = tmp_path / "inner.7z"
    subprocess.run(
        ["7z", "a", "-t7z", str(inner), str(payload)],
        capture_output=True, check=True, cwd=str(tmp_path),
    )
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as handle:
        handle.write(inner, "inner.7z")
    out = nonweb.unpack_archive(str(outer), out_dir=str(tmp_path / "out"))
    assert "d2" in out, out
    assert "inner.7z" in out, out
    assert "payload.txt" in out, out


def _rar4_with(name: str, payload: bytes) -> bytes:
    """A stored (uncompressed) RAR4 archive, assembled by hand.

    No RAR writer exists on any host we build on, so the fixture is emitted
    from the format's base blocks (main 0x73, file 0x74, end 0x7b).  Verified
    against 7-Zip 25.x, which is what ``p7zip-full`` installs on trixie.
    """
    fname = name.encode()
    file_body = bytearray()
    file_body += struct.pack("<I", len(payload))        # PACK_SIZE
    file_body += struct.pack("<I", len(payload))        # UNP_SIZE
    file_body += b"\x03"                                # HOST_OS = unix
    file_body += struct.pack("<I", zlib.crc32(payload))  # FILE_CRC
    file_body += struct.pack("<I", 0)                   # FTIME
    file_body += b"\x14"                                # UNP_VER 2.0
    file_body += b"\x30"                                # METHOD = stored
    file_body += struct.pack("<H", len(fname))          # NAME_SIZE
    file_body += struct.pack("<I", 0x81A4)              # ATTR = 0644
    file_body += fname

    file_head = bytearray(b"\x00\x00\x74" + struct.pack("<H", 0x8000))  # LONG_BLOCK
    file_head += struct.pack("<H", 32 + len(fname))     # HEAD_SIZE
    file_head += file_body
    struct.pack_into("<H", file_head, 0, zlib.crc32(bytes(file_head[2:])) & 0xFFFF)

    main_head = bytearray(b"\x00\x00\x73" + struct.pack("<H", 0))
    main_head += struct.pack("<H", 13) + struct.pack("<H", 0) + struct.pack("<I", 0)
    struct.pack_into("<H", main_head, 0, zlib.crc32(bytes(main_head[2:])) & 0xFFFF)

    end_head = bytearray(b"\x00\x00\x7b" + struct.pack("<H", 0x4000))
    end_head += struct.pack("<H", 7)
    struct.pack_into("<H", end_head, 0, zlib.crc32(bytes(end_head[2:])) & 0xFFFF)

    return (
        b"Rar!\x1a\x07\x00"
        + bytes(main_head) + bytes(file_head) + payload + bytes(end_head)
    )


def _seven_zip_reads_rar() -> bool:
    """True only when the installed 7z build advertises a RAR codec.

    Old p7zip (bookworm, 16.02) does not, so the capability -- not the binary
    name -- decides whether the RAR extraction test can run.
    """
    binary = shutil.which("7z")
    if binary is None:
        return False
    probe = subprocess.run([binary, "i"], capture_output=True, text=True)
    return "Rar" in probe.stdout


@pytest.mark.skipif(not _seven_zip_reads_rar(), reason="7z build has no RAR codec")
def test_unpack_extracts_a_real_rar_through_7z(tmp_path: Path) -> None:
    """RAR used to be "named but never extracted"; now it must come out."""
    archive = tmp_path / "a.rar"
    archive.write_bytes(_rar4_with("payload.txt", b"rar-through-7z\n"))
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    assert "no rar reader" not in out, out
    assert (tmp_path / "out" / "payload.txt").read_bytes() == b"rar-through-7z\n"


def _zstd_compress(payload: bytes) -> bytes:
    zstandard = pytest.importorskip("zstandard")
    return zstandard.ZstdCompressor().compress(payload)


def test_unpack_extracts_a_zstd_stream_and_keeps_the_inner_name(
    tmp_path: Path,
) -> None:
    """The frame magic is conclusive, and zstandard ships in the image."""
    archive = tmp_path / "payload.bin.zst"
    archive.write_bytes(_zstd_compress(b"zstd-roundtrip\n"))
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected zstd" in out, out
    assert (tmp_path / "out" / "payload.bin").read_bytes() == b"zstd-roundtrip\n"


def test_unpack_recurses_into_a_tar_zst(tmp_path: Path) -> None:
    """``x.tar.zst`` must drop the ``.zst`` so the next level still sees a tar."""
    raw = io.BytesIO()
    payload = b"tar-inside-zstd\n"
    with tarfile.open(fileobj=raw, mode="w") as handle:
        info = tarfile.TarInfo("inner.txt")
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    archive = tmp_path / "bundle.tar.zst"
    archive.write_bytes(_zstd_compress(raw.getvalue()))
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "d2" in out, out
    assert (tmp_path / "out" / "_d2" / "inner.txt").read_bytes() == payload


def test_unpack_reports_missing_zstandard_instead_of_an_empty_success(
    tmp_path: Path, monkeypatch
) -> None:
    """A host without the wheel must get a reason, not an empty directory."""
    monkeypatch.setitem(sys.modules, "zstandard", None)
    archive = tmp_path / "a.zst"
    archive.write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 64)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected zstd" in out, out
    assert "zstandard is not installed" in out, out


def test_unpack_refuses_a_zstd_member_over_the_size_cap(
    tmp_path: Path, monkeypatch
) -> None:
    """A 100-byte stream that expands past the cap must be refused, not written."""
    monkeypatch.setattr(nonweb, "_UNPACK_MEMBER_MAX", 32)
    archive = tmp_path / "big.zst"
    archive.write_bytes(_zstd_compress(b"x" * 100))
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "actual size over limit" in out, out
    assert not (tmp_path / "out" / "big").exists()


def test_unpack_archive_handles_data_appended_after_eocd(tmp_path: Path) -> None:
    """A real misc attachment: 143KB of appended data after the ZIP EOCD.

    ``zipfile`` scans only the last 64KB for the EOCD, so it raises
    ``BadZipFile`` on a perfectly readable archive.  The tool must cut at the
    EOCD, say so, and still extract -- otherwise the model sees "zip failed"
    on a file that is not corrupt at all.
    """
    archive = tmp_path / "polyglot.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("inner.bin", b"payload")
    with archive.open("ab") as handle:
        handle.write(b"\x00" * (200 * 1024))

    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "end-of-central-directory" in out
    assert (tmp_path / "out" / "inner.bin").read_bytes() == b"payload"

def test_decode_blob_handles_per_line_base64() -> None:
    """A real misc attachment: 81 lines, each its own base64 string.

    The whole file is not one base64 stream (per-line padding breaks the
    round-trip), so a whole-text decoder reports "no chain" on a file that
    decodes cleanly.  This was the difference between "looks encrypted" and
    "here is the plain text".
    """
    lines = ["aGVsbG8gd29ybGQ=", "dGhpcyBpcyBhIHRlc3Q=", "b2YgbGluZSB3aXNlIGRlY29kaW5n"]
    out = nonweb.decode_blob("\n".join(lines))
    assert "per-line" in out or "separately encoded" in out
    assert "hello world" in out


def test_decode_blob_recovers_base64_padding_stego() -> None:
    """Payload hidden in the low bits of each line's final character.

    Canonical base64 zeroes those bits; a stego encoder rewrites them, so the
    decoded text is ordinary English and every "decode the base64" attempt
    looks like a dead end.  Two pads = 4 payload bits, one pad = 2.
    """
    alpha = nonweb._B64_ALPHA
    bits = "".join(format(byte, "08b") for byte in b"flag{padding}")
    lines_out = []
    for index in range(0, len(bits), 4):
        value = int(bits[index : index + 4].ljust(4, "0"), 2)
        lines_out.append("YQ" + alpha[0x10 | value] + "==")

    out = nonweb.decode_blob("\n".join(lines_out))
    assert "flag{padding}" in out
    assert "steganography" in out


# --- PWN-8：tcp 结果到「连接到底做了什么」的分类 -----------------------------
#
# `target_absent` 只认 http(s) URL，对 tcp 完全惰性，死服务烧满墙钟。守卫要计数
# 就必须能读懂 tcp 的结果行，而**词汇表的拥有者是这个模块**：措辞哪天改了，分类器
# 必须跟着改，否则守卫会静默地不再计数（fail-open）。所以分类器与措辞同文件。
#
# 三个边界是本组测试的重点：
#   1. 参数错误（host 为空、端口非法、payload 空）根本没上过网，**不能计数**——否则
#      一次写错的调用就能判死一个从没被拨号的靶子；
#   2. TLS 握手失败 / send 失败意味着 **TCP 层已经接受**，是活靶，不能算死；
#   3. 只读首行。tcp_batch 的逐条 `#N send failed` 是行内事件，不是连接结论。


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # 存活：四种证活信号
        ("[tcp] h:1 connected in 4 ms; banner=3 B", "live"),
        ("[tcp_batch] h:1 2 payload(s) same_conn=True in 0.3s", "live"),
        ("[tcp] TLS handshake failed (SSLError: bad). next: ...", "live"),
        ("[tcp] send failed: [Errno 32] Broken pipe. The peer closed after the banner.", "live"),
        # 失败三档
        ("[tcp] DNS failed for nope.invalid: [Errno 11001]. next: ...", "dns"),
        ("[tcp] connection refused by 127.0.0.1:1. next: ...", "refused"),
        ("[tcp] connect timed out to h:1 after 5s. next: ...", "timeout"),
        ("[tcp] cannot reach h:1 (OSError: no route). next: ...", "unreachable"),
        # 参数错误 / 非本模块产出：不计数
        ("[tcp] host is empty. Format: tcp(host='node1.ctfy.run', port=1337)", None),
        ("[tcp] invalid port 'x'. It must be 1-65535.", None),
        ("[tcp] hex_mode payload is not valid hex: odd-length string", None),
        ("[tcp_batch] payloads is empty. Pass a list of candidates.", None),
        ("[tcp_batch] need host and a port in 1-65535 (got None:0).", None),
        ("Chunk ID: 000001\nWall time: 0.1 seconds\n[tcp] connected in 1 ms", None),
        ("", None),
    ],
)
def test_tcp_connect_state_reads_the_first_line(text: str, expected: str | None) -> None:
    assert nonweb.tcp_connect_state(text) == expected


def test_tcp_connect_state_ignores_inline_rows_of_a_batch() -> None:
    """A `#N send failed` *row* is one candidate dying, not the connection.

    The head already says the batch ran on one live socket; letting a row decide
    would turn "three payloads failed to send" into "the target is dead".
    """
    text = (
        "[tcp_batch] h:1 3 payload(s) same_conn=True in 0.4s\n"
        "#0 send failed: [Errno 32] Broken pipe\n"
        "#1 send failed: [Errno 32] Broken pipe\n"
    )
    assert nonweb.tcp_connect_state(text) == "live"


def test_tcp_connect_state_on_a_real_connection() -> None:
    """The banner-and-echo server accepts the socket: that is ``live``, not dead.

    This is the positive control for the guard: a target that answers must never
    accumulate failure counts, no matter how uninformative its banner is.
    """
    server = _Server()
    try:
        out = nonweb.tcp("127.0.0.1", server.port, read_timeout=0.6)
        batch = nonweb.tcp_batch("127.0.0.1", server.port, ["41"], hex_mode=True,
                                 read_timeout=0.6)
    finally:
        server.close()
    assert nonweb.tcp_connect_state(out) == "live"
    assert nonweb.tcp_connect_state(batch) == "live"


def test_tcp_connect_state_on_a_refused_loopback_port() -> None:
    out = nonweb.tcp("127.0.0.1", 1, read_timeout=0.3)
    assert nonweb.tcp_connect_state(out) == "refused"

class _SlamShut:
    """Accept and close immediately: a TLS handshake here fails fast."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self.sock.close()


def test_tls_handshake_failure_points_at_sni_first() -> None:
    """RISK 3/CROSS-CHECK 4：握手失败的 next 指引必须与提示词第 5 条同向。

    平台现实是全 TLS-SNI（提示词第 5 条：空明文回复 => 端口要 TLS）。若握手
    失败的文案把「retry with tls=false」放在第一位，两条指令方向相反，模型
    会被钉在 tls=false <-> tls=True 的来回里。判据：sni 建议先于 tls=false
    出现，且 tls=false 被降级为「题面明说才用」；判活前缀不变。
    """
    server = _SlamShut()
    try:
        out = nonweb.tcp("127.0.0.1", server.port, "hi\n", read_timeout=0.5, tls=True)
    finally:
        server.close()

    assert "TLS handshake failed" in out, out
    assert nonweb.tcp_connect_state(out) == "live"
    assert out.find("sni='<vhost>'") < out.find("tls=false"), out
    assert "task statement" in out
