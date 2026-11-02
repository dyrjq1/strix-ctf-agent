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

import io
import socket
import sys
import tarfile
import threading
import zipfile
from pathlib import Path

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
    assert "cannot connect" in out
    assert "next:" in out


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


def test_elfpeek_gadgets_finds_patterns_without_capstone(tmp_path: Path) -> None:
    target = tmp_path / "tiny.elf"
    target.write_bytes(_tiny_elf())
    out = nonweb.elfpeek(str(target), view="gadgets")
    assert "pop rdi; ret" in out
    assert "/bin/sh" in out


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


def test_elfpeek_schema_does_not_carry_lookup_parameters(tmp_path: Path) -> None:
    """`symbol`/`search` serve one view; the other six must not pay for them.

    Measured: the combined schema was 1,576 chars -- larger than the whole
    ``file_triage`` tool.  Splitting keeps the per-call surface honest.
    """
    seen: list = []

    def collect(*tools) -> None:
        seen.extend(tools)

    nonweb.register(register_fn=collect, kind="file")
    schemas = {
        tool.name: set(tool.params_json_schema["properties"]) for tool in seen
    }
    assert "symbol" not in schemas["elfpeek"]
    assert "utf16" not in schemas["elfpeek"]
    assert {"symbol", "search"} <= schemas["elffind"]


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
    assert set(tcp_names) == {"tcp", "tcp_batch"}

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
