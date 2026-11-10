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


def test_unpack_archive_next_hint_uses_produced_family(tmp_path: Path) -> None:
    """_NEXT wiring must sniff the largest *produced* file, not the outer archive.

    Outer is a tar and inner is a zip.  Both families have _NEXT entries now, so
    the hint's *target* discriminates: the produced zip yields an ``unzip -l``
    line pointing at inner.zip, while wiring that sniffed the outer tar would
    emit ``tar -tf outer.tar`` and fail the assertions below.
    """
    inner = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner, "w") as handle:
        handle.writestr("deep.txt", "hello deep")
    outer = tmp_path / "outer.tar"
    with tarfile.open(outer, "w") as handle:
        handle.add(inner, arcname="inner.zip")
    out = nonweb.unpack_archive(str(outer), out_dir=str(tmp_path / "out"))
    hint_lines = [line for line in out.splitlines() if "unzip -l" in line]
    assert hint_lines, "expected zip-specific _NEXT hint (unzip -l) in output"
    assert "inner.zip" in hint_lines[0], "hint must target the produced zip file"
    assert "deep.txt" in out


def test_unpack_archive_next_hint_covers_tar_family(tmp_path: Path) -> None:
    """tar is in _NEXT now, so an all-tar chain must yield the tar hint.

    This was a negative test while tar had no entry ("tar is not in _NEXT").
    Every container _sniff can name has an entry, so the honest expectation is
    that the hint appears and points at the *inner* archive.
    """
    note = tmp_path / "note.txt"
    note.write_text("hello", encoding="utf-8")
    inner = tmp_path / "inner.tar"
    with tarfile.open(inner, "w") as handle:
        handle.add(note, arcname="note.txt")
    outer = tmp_path / "outer.tar"
    with tarfile.open(outer, "w") as handle:
        handle.add(inner, arcname="inner.tar")
    out = nonweb.unpack_archive(str(outer), out_dir=str(tmp_path / "out"))
    hint_lines = [line for line in out.splitlines() if "tar -tf" in line]
    assert hint_lines, "expected tar-specific _NEXT hint (tar -tf) in output"
    assert "inner.tar" in hint_lines[0], "hint must target the inner tar"
    assert "note.txt" in out


def test_unpack_archive_next_hint_for_text_produced_file(tmp_path: Path) -> None:
    """A text member is _NEXT["text"], not "unknown".

    The old test called readme.txt unknown because _sniff returned "".  That
    encoded the H1 defect as an expectation; text is a family the table covers.
    """
    archive = tmp_path / "data.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("readme.txt", "content")
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "readme.txt" in out
    hint_lines = [line for line in out.splitlines() if "head -80" in line]
    assert hint_lines, "expected text-family hint (head -80) in output"
    assert "readme.txt" in hint_lines[0], "hint must target the produced file"
    # The outer archive is a zip; a hint keyed on it would say unzip -l.
    assert "unzip -l" not in out


def test_unpack_archive_unknown_family_gets_investigation_instructions(
    tmp_path: Path,
) -> None:
    """Truly unknown bytes get investigation steps, never a fabricated guess."""
    archive = tmp_path / "blob.zip"
    payload = bytes(range(256)) * 8
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("blob.bin", payload)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "blob.bin" in out
    hint_lines = [line for line in out.splitlines() if "xxd -l" in line]
    assert hint_lines, "expected unknown-family investigation hint (xxd -l)"
    assert "blob.bin" in hint_lines[0], "hint must target the produced file"
    assert "unzip -l" not in out, "outer zip family leaked into the hint"
    assert "readelf" not in out, "unknown bytes must not be guessed as ELF"


def test_unpack_archive_next_hint_uses_content_family_for_elf(tmp_path: Path) -> None:
    """H1: a zip holding one ELF must reach _NEXT["elf"].

    The produced file carries no container magic, so only the content-level
    branch of _content_family can name it -- this is the direct evidence that
    the wiring reaches the ten families _sniff alone could never name.
    """
    payload = b"\x7fELF\x02\x01\x01" + bytes(64)
    archive = tmp_path / "payload.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("payload", payload)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "payload" in out
    hint_lines = [line for line in out.splitlines() if "readelf" in line]
    assert hint_lines, "expected elf-family hint (readelf) for an ELF inside a zip"
    assert "payload" in hint_lines[0], "hint must target the produced ELF"


def test_nothing_came_out_checks_type_before_carving(
    tmp_path: Path, monkeypatch
) -> None:
    """M2: file -b -> carve -> do-not-retry, in that order, in one block.

    A 7z signature that produces nothing is where the generic line used to be
    hoisted to the tail, after the carve advice.  ``which`` is pinned to None so
    a host that ships the 7z binary cannot select the other branch.
    """
    monkeypatch.setattr(nonweb.shutil, "which", lambda name: None)
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 300)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    lines = out.splitlines()
    type_index = next(i for i, line in enumerate(lines) if "file -b" in line)
    carve_index = next(
        i for i, line in enumerate(lines) if "Carve from that offset" in line
    )
    assert type_index < carve_index, "type check must precede carve advice"
    assert "binwalk" in out, "carve advice must offer binwalk (it is in the image)"
    assert "Do not retry unpack_archive" in out


def test_next_hints_survive_output_truncation(tmp_path: Path) -> None:
    """M3: the next: block is appended after _clip, so a long listing cannot eat it."""
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        for index in range(200):
            handle.writestr(f"file{index:03d}.txt", "x" * 40)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert out.startswith("[unpack_archive]"), "header line must survive"
    assert "...[truncated" in out, "the listing must actually have been truncated"
    tail = out[out.index("...[truncated") :]
    assert "head -80" in tail, "family hint must be re-appended after truncation"


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

def test_unpack_names_7z_instead_of_calling_it_unknown(
    tmp_path: Path, monkeypatch
) -> None:
    """A 7z that cannot be read must not look like a corrupt file.

    "detected unknown, nothing extracted" invites a retry of the same tool.
    The magic bytes are conclusive, so say what it is and that this image has
    no reader -- that is the observation that changes the next action.

    ``which`` is pinned to None: the image ships 7z (Dockerfile:36), so on a
    host that has it the walk would take the real extraction branch and never
    print the names-only verdict.
    """
    monkeypatch.setattr(nonweb.shutil, "which", lambda name: None)
    archive = tmp_path / "a.7z"
    archive.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 300)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected 7z" in out, out
    assert "no 7z reader" in out, out
    assert "offset 0x0" in out, out
    assert "unknown" not in out, out


def test_unpack_finds_a_rar_signature_behind_an_sfx_stub(
    tmp_path: Path, monkeypatch
) -> None:
    """RAR self-extracting stubs put up to 64KB before the signature.

    ``which`` is pinned to None so a host that has unar (the image does,
    Dockerfile:39) cannot take the real extraction branch instead of the
    names-only verdict this test is about.
    """
    monkeypatch.setattr(nonweb.shutil, "which", lambda name: None)
    archive = tmp_path / "sfx.rar"
    archive.write_bytes(b"MZ" + b"\x00" * 4096 + b"Rar!\x1a\x07\x00" + b"\x00" * 128)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    assert "no rar reader" in out, out
    # The message must not pretend the file *is* a bare RAR: it is an SFX stub.
    assert "offset 0x1002" in out, out


def test_unpack_rar_with_unar_does_not_claim_no_reader(
    tmp_path: Path, monkeypatch
) -> None:
    """The image has unar, so a RAR must not be reported as having no reader.

    The old guard ``not (kind == "7z" and which("7z"))`` is always true for
    rar, so it claimed "no rar reader" even with unar installed.  ``which``
    returns a present-but-bogus path for unar, so the walk attempts unar, it
    fails (the path does not exist), and the tail must report the attempt
    rather than denying the reader exists.
    """
    monkeypatch.setattr(
        nonweb.shutil, "which", lambda name: "/usr/bin/unar" if name == "unar" else None
    )
    archive = tmp_path / "real.rar"
    archive.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 128)
    out = nonweb.unpack_archive(str(archive), out_dir=str(tmp_path / "out"))
    assert "detected rar" in out, out
    assert "no rar reader" not in out, out
    assert "unar failed" in out or "unar ran" in out, out


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
