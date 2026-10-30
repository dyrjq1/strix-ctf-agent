"""P12：file_triage 入口原语（非 web 附件题的第一跳）。

断言的重点不是"能跑 file 命令"，而是三条行为：
1. 不存在的路径要说人话，别抛异常；
2. 家族判定必须落到 ELF/ZIP/text 这些**能决定下一步**的标签上；
3. 返回里必须带一条具体命令——这是工具存在的理由（见 docs/14 §1）。
"""

from __future__ import annotations

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
    assert "next: cat" in out


def test_elf_suggests_static_analysis_not_execution(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "chall"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    def fake(argv: list[str], *a, **k) -> str:
        return "ELF 64-bit LSB executable" if argv[0] == "file" else ""

    monkeypatch.setattr(ft, "_run", fake)
    monkeypatch.setattr(ft.shutil, "which", lambda name: None)
    out = ft.file_triage(str(target))
    assert "family: elf" in out
    assert "checksec" in out
    assert "别一上来跑它" in out