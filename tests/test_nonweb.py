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


def test_register_splits_by_kind() -> None:
    seen: list = []

    def collector(*tools) -> None:
        seen.extend(tools)

    file_names = nonweb.register(register_fn=collector, kind="file")
    assert set(file_names) == {
        "unpack_archive",
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

def test_unpack_names_7z_instead_of_calling_it_unknown(tmp_path: Path) -> None:
    """A 7z that cannot be read must not look like a corrupt file.

    "detected unknown, nothing extracted" invites a retry of the same tool.
    The magic bytes are conclusive, so say what it is and that this image has
    no reader -- that is the observation that changes the next action.
    """
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 300)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected 7z" in out, out
    assert "no 7z reader" in out, out
    assert "offset 0x0" in out, out
    assert "unknown" not in out, out


def test_unpack_finds_a_rar_signature_behind_an_sfx_stub(tmp_path: Path) -> None:
    """RAR self-extracting stubs put up to 64KB before the signature."""
    archive = tmp_path / "sfx.rar"
    archive.write_bytes(b"MZ" + b"\x00" * 4096 + b"Rar!\x1a\x07\x00" + b"\x00" * 128)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    assert "no rar reader" in out, out
    # The message must not pretend the file *is* a bare RAR: it is an SFX stub.
    assert "offset 0x1002" in out, out


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
