"""P12：file_triage 入口原语（非 web 附件题的第一跳）。

断言的重点不是"能跑 file 命令"，而是三条行为：
1. 不存在的路径要说人话，别抛异常；
2. 家族判定必须落到 ELF/ZIP/text 这些**能决定下一步**的标签上；
3. 返回里必须带一条具体命令——这是工具存在的理由（见 docs/14 §1）。
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from ctf_strix import file_triage as ft  # noqa: E402


def test_entropy_zero_and_high() -> None:
    assert ft._entropy(b"") == 0.0
    assert ft._entropy(b"\x00" * 256) < 0.1
    assert ft._entropy(bytes(range(256)) * 8) > 7.9


def test_family_mapping() -> None:
    assert ft._family("ELF 64-bit LSB pie executable, x86-64", Path("a")) == "elf"
    assert ft._family("PE32+ executable (console) x86-64", Path("a")) == "pe"
    assert ft._family("Zip archive data, at least v2.0", Path("a")) == "zip"
    assert ft._family("PNG image data, 1920 x 1080", Path("a")) == "png"
    assert ft._family("Python script, ASCII text executable", Path("a")) == "text"
    assert ft._family("data", Path("a.bin")) == "unknown"


def test_missing_path_is_friendly(tmp_path: Path) -> None:
    out = ft.file_triage(str(tmp_path / "nope.bin"))
    assert "不存在" in out
    assert "ls -la" in out


def test_directory_lists_files_and_points_at_biggest(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "small.txt").write_bytes(b"x")
    (tmp_path / "big.bin").write_bytes(b"A" * 4096)
    monkeypatch.setattr(ft, "_run", lambda argv, *a, **k: "data")
    out = ft.file_triage(str(tmp_path))
    assert "small.txt" in out and "big.bin" in out
    assert "next:" in out and "big.bin" in out.split("next:")[-1]


def test_text_file_reports_flag_and_next_command(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "note.txt"
    target.write_text("hello FLAG{abc12345} end", encoding="utf-8")

    def fake(argv: list[str], *a, **k) -> str:
        if argv[0] == "file":
            return "ASCII text"
        if argv[0] == "strings":
            return "hello FLAG{abc12345} end\nhttps://example.invalid/flag"
        return ""

    monkeypatch.setattr(ft, "_run", fake)
    out = ft.file_triage(str(target))
    assert "FLAG{abc12345}" in out
    assert "family: text" in out
    assert "next: 1) `cat" in out


def test_high_entropy_note_names_a_command_the_image_has(
    tmp_path: Path, monkeypatch
) -> None:
    """The entropy note used to say "run binwalk", which is not installed.

    Same defect class as ``_NEXT``: a hint that cannot be executed costs a
    turn and teaches nothing (docs/27 C2).
    """
    target = tmp_path / "blob.bin"
    target.write_bytes(bytes(range(256)) * 16)

    def fake(argv: list[str], *a, **k) -> str:
        return "data" if argv[0] == "file" else ""

    monkeypatch.setattr(ft, "_run", fake)
    monkeypatch.setattr(ft.shutil, "which", lambda name: None)
    out = ft.file_triage(str(target))
    assert "熵 >7.2" in out
    assert "binwalk" not in out
    assert "xxd" in out
    assert "blob.bin" in out.split("熵 >7.2")[-1]


def test_elf_suggests_static_analysis_not_execution(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "chall"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    def fake(argv: list[str], *a, **k) -> str:
        return "ELF 64-bit LSB executable" if argv[0] == "file" else ""

    monkeypatch.setattr(ft, "_run", fake)
    monkeypatch.setattr(ft.shutil, "which", lambda name: None)
    out = ft.file_triage(str(target))
    assert "family: elf" in out
    # Every hint must be runnable in this image.  ``checksec`` and ``r2`` are
    # not installed (docker/Dockerfile), so suggesting them sent the model at a
    # missing binary on its first call -- docs/27 C2.
    assert "checksec" not in out
    assert "r2" not in out
    assert "readelf" in out
    assert "别一上来跑它" in out


# ---------------------------------------------------------------------------
# P18-4: the triage answer is a decision table, not a pointer to a skill.
# ---------------------------------------------------------------------------

#: Shell programs the image really has.  ``binutils``/``file``/``xxd``/``unzip``
#: come from the Dockerfile apt line; the rest ship with ``python:3.12-slim``.
_IMAGE_BINARIES = frozenset(
    {
        "cat", "cp", "file", "find", "gdb", "git", "grep", "gunzip", "gzip",
        "head", "jq", "less", "ls", "ltrace", "mv", "nc", "objdump", "od",
        "ps", "python3", "readelf", "rm", "sed", "sort", "strace", "strings",
        "tar", "uniq", "unzip", "wc", "wget", "xxd", "zcat", "zip",
    }
)

#: Tool names this module is allowed to recommend.  Anything else in a backtick
#: span must be a shell command, checked against the image above.
_TOOL_NAMES = (
    "decode_blob", "elfpeek", "elffind", "file_triage", "hexpeek",
    "unpack_archive",
)


def _spans(family: str) -> list[str]:
    return re.findall(r"`([^`]+)`", ft._NEXT[family])


def test_decision_table_only_names_binaries_the_image_installs() -> None:
    """Every bare command in ``_NEXT`` must resolve inside this container.

    The first call of a Misc challenge is the most expensive one to waste:
    ``checksec``/``r2``/``binwalk``/``zsteg``/``exiftool``/``tshark`` were all
    suggested here before and none is installed (docs/27 C2).
    """
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    for package in ("binutils", "file", "xxd", "unzip", "zip", "gdb", "curl"):
        assert package in dockerfile, f"Dockerfile no longer installs {package}"

    bad: list[str] = []
    for family in ft._NEXT:
        for span in _spans(family):
            call = re.match(r"([a-z_][a-z0-9_]*)\(", span)
            if call:
                # A Python-level tool call: the name has to be one of ours.
                if call.group(1) not in _TOOL_NAMES:
                    bad.append(f"{family}: invented tool {call.group(1)}()")
                continue
            first = span.split()[0]
            if first not in _IMAGE_BINARIES:
                bad.append(f"{family}: missing binary {first}")
    assert not bad, "decision table names uninstalled commands:\n" + "\n".join(bad)


def test_decision_table_tool_calls_use_real_parameters() -> None:
    """A tool call with an invented kwarg fails at runtime, after a lost turn.

    The previous table said ``elfpeek('x', what='all')``; ``elfpeek`` calls that
    parameter ``view``, so the line raised TypeError on the first call of every
    ELF challenge.
    """
    from ctf_strix import nonweb

    funcs = {fn.__name__: fn for fn in (*ft.TOOLS, *nonweb.FILE_TOOLS)}
    for family in ft._NEXT:
        for span in _spans(family):
            for name in _TOOL_NAMES:
                for call in re.findall(rf"\b{name}\(([^)]*)\)", span):
                    assert name in funcs, f"decision table calls missing tool {name}"
                    allowed = set(inspect.signature(funcs[name]).parameters)
                    used = set(re.findall(r"([a-z_]+)=", call))
                    assert used <= allowed, f"{family}: {name}({used - allowed})"


def test_unknown_family_does_not_borrow_another_family_action(
    tmp_path: Path, monkeypatch
) -> None:
    """A file matching no family must not get ELF/archive/PDF instructions."""
    hint = ft._NEXT["unknown"]
    for foreign in (
        "readelf", "objdump", "unzip", "gunzip", "gzip.open", "marshal",
        "zlib", "gdb", "elfpeek", "elffind", "unpack_archive", "grep",
    ):
        assert foreign not in hint, f"unknown family suggests {foreign}"

    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00\x01\x02\x03" * 64)

    def fake(argv: list[str], *a, **k) -> str:
        return "data" if argv[0] == "file" else ""

    monkeypatch.setattr(ft, "_run", fake)
    monkeypatch.setattr(ft.shutil, "which", lambda name: None)
    out = ft.file_triage(str(target))
    assert "family: unknown" in out
    tail = out.split("next:")[-1]
    assert "hexpeek" in tail
    assert "readelf" not in tail and "unzip" not in tail


def test_each_family_is_a_three_step_decision_table() -> None:
    """Families answer "what next" in order; skills are only deep reads."""
    for family, hint in ft._NEXT.items():
        assert "1)" in hint and "2)" in hint and "3)" in hint, family
        assert "深读:" in hint, f"{family} lost its deep-read pointer"
        for skill in re.findall(r"ctf-[a-z0-9-]+/[a-z0-9-]+", hint):
            index = ROOT / "src" / "ctf_strix" / "skills_strix" / f"{skill}.md"
            assert index.is_file(), f"{family} points at missing skill {skill}"


def test_decision_table_stays_within_its_budget() -> None:
    """The whole table is paid on every attachment challenge; ~1.1k tokens."""
    total = sum(len(hint) for hint in ft._NEXT.values())
    assert total <= 3300, f"decision table grew to {total} chars"


def test_rendered_output_carries_the_numbered_table(
    tmp_path: Path, monkeypatch
) -> None:
    """The value is in the tool return, not in a skill loaded beforehand."""
    target = tmp_path / "chall"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    def fake(argv: list[str], *a, **k) -> str:
        return "ELF 64-bit LSB executable" if argv[0] == "file" else ""

    monkeypatch.setattr(ft, "_run", fake)
    monkeypatch.setattr(ft.shutil, "which", lambda name: None)
    tail = ft.file_triage(str(target)).split("next:")[-1]
    assert "1)" in tail and "2)" in tail and "3)" in tail
    assert "深读:" in tail
