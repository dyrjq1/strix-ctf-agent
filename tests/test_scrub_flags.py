"""``scripts/scrub_flags.py`` 自己的闸门测试。

这个脚本是"镜像里读得到的文件不许留答案串"的最后一道门。它最危险的失效方式
不是漏抓，而是**静默什么都不扫**：根路径写错、后缀白名单漏掉 ``.py``、或
不存在的根被 ``continue`` 掉——输出都和"真的干净"一模一样。所以这里钉住
退出码、扫描面与换行。
"""

from __future__ import annotations

import pathlib
import shlex

import pytest

from scrub_loader import load_scrub

scrub = load_scrub()


def _write(path: pathlib.Path, text: str, *, crlf: bool = False) -> None:
    data = text.replace("\n", "\r\n") if crlf else text
    path.write_bytes(data.encode("utf-8"))


_DOCKERFILE = pathlib.Path(__file__).resolve().parents[1] / "docker" / "Dockerfile"

#: 进镜像但明确不进默认扫描面的目录。
#: ``vendor/src`` 是未改动的上游 strix 1.7.0，原样随镜像发布；它有自己的
#: 版本来源与卫生检查，不纳入我们这条 GC 面（否则每次上游升级都要重扫）。
_EXEMPT_IMAGE_DIRS = frozenset({"vendor/src"})


def _image_dir_copies() -> set[str]:
    """从 ``docker/Dockerfile`` 反推被 COPY 进 ``/app`` 的目录（镜像内相对路径）。"""
    text = _DOCKERFILE.read_text(encoding="utf-8")
    copies: set[str] = set()
    for line in text.splitlines():
        if not line.strip().upper().startswith("COPY "):
            continue
        args = [token for token in shlex.split(line)[1:] if not token.startswith("--")]
        if len(args) < 2:
            continue
        try:
            dest_rel = pathlib.PurePosixPath(args[-1]).relative_to("/app").as_posix()
        except ValueError:
            continue
        for src in args[:-1]:
            if not (pathlib.Path(__file__).resolve().parents[1] / src).is_dir():
                continue
            copies.add(src if dest_rel == "." else dest_rel)
    return copies


def test_default_roots_cover_every_image_directory() -> None:
    """默认面必须覆盖 Dockerfile 里 COPY 进镜像的每个源码目录。

    只断言 ``_DEFAULT_ROOTS`` 等于我们刚写下的常量是自证：有人加一行
    ``COPY native /app/native``，agent 在容器里就能 ``cat`` 到，而闸门仍然绿。
    这里从 Dockerfile 反推扫描面；解析不出目录 COPY 就让测试失败，不静默通过。
    """
    copies = _image_dir_copies()
    assert copies, "docker/Dockerfile 里解析不到任何目录 COPY，测试自身已失效"
    uncovered = sorted(copies - set(scrub._DEFAULT_ROOTS) - _EXEMPT_IMAGE_DIRS)
    assert not uncovered, (
        "这些目录被 COPY 进镜像、agent 读得到，但不在扫描面里：" + "、".join(uncovered)
    )


def test_check_missing_root_exits_2(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    """根不存在时不能静默通过。"""
    missing = tmp_path / "nosuchdir"
    assert scrub.main(["--check", str(missing)]) == 2
    err = capsys.readouterr().err
    assert "扫描根不存在" in err
    assert "nosuchdir" in err


def test_check_zero_files_exits_2(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    """空目录退 2：零文件与"真的干净"必须能分辨。"""
    empty = tmp_path / "empty"
    empty.mkdir()
    assert scrub.main(["--check", str(empty)]) == 2
    assert "一个文件都没扫到" in capsys.readouterr().err


def test_summary_reports_roots_and_counts(tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]) -> None:
    """两种模式都要回显扫了哪些根、扫了多少文件。"""
    _write(tmp_path / "a.md", "# clean\n")
    assert scrub.main(["--check", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert str(tmp_path) in out
    assert "scanned 1 files / 1 roots" in out


@pytest.mark.parametrize("name", ["a.py", "b.sh", "c.toml", "d.ini"])
def test_suffix_whitelist_scans_code_and_config(name: str, tmp_path: pathlib.Path) -> None:
    """技能包里的 ``.py`` / ``.sh`` 会被 agent ``cat`` 到，必须在扫描面里。"""
    _write(tmp_path / name, "# x\nFLAG{deadbeef01}\n")
    assert scrub.main(["--check", str(tmp_path)]) == 1


def test_suffix_whitelist_skips_unknown_suffix(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """白名单之外的后缀不扫（二进制读进来只会是噪音）。"""
    _write(tmp_path / "keep.md", "# clean\n")
    _write(tmp_path / "x.bin", "FLAG{deadbeef02}\n")
    assert scrub.main(["--check", str(tmp_path)]) == 0
    assert "x.bin" not in capsys.readouterr().out


def test_apply_preserves_crlf(tmp_path: pathlib.Path) -> None:
    """``--apply`` 只改 flag，不能顺手把整份文件的 CRLF 归一成 LF。

    用字节不变式而不是数 ``\\r\\n``：把 ``FLAG{...}`` 换回原串后必须与原文
    逐字节相等，才能证明除这处 flag 之外一个字节都没动。
    """
    path = tmp_path / "win.md"
    _write(path, "# t\nFLAG{deadbeef03}\nend\n", crlf=True)
    original = path.read_bytes()
    assert scrub.main(["--apply", str(tmp_path)]) == 0
    scrubbed = path.read_bytes()
    assert scrubbed.replace(b"FLAG{...}", b"FLAG{deadbeef03}") == original


def test_apply_preserves_utf8_bom(tmp_path: pathlib.Path) -> None:
    """BOM 不是正文：改写后仍须以 ``EF BB BF`` 开头。"""
    path = tmp_path / "bom.md"
    path.write_bytes(b"\xef\xbb\xbf# t\nFLAG{deadbeef04}\n")
    assert scrub.main(["--apply", str(tmp_path)]) == 0
    raw = path.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert b"FLAG{...}" in raw


def test_undecodable_file_is_skipped_and_reported(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """UTF-16 的 ``.ini`` 不能静默算进覆盖度：跳过要计数并报文件名。"""
    _write(tmp_path / "ok.md", "# clean\n")
    (tmp_path / "win.ini").write_bytes("FLAG{deadbeef05}\n".encode("utf-16"))
    assert scrub.main(["--check", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "scanned 1 files" in captured.out
    assert "win.ini" in captured.err
    assert "解码失败" in captured.err


def test_single_file_root_respects_suffix(tmp_path: pathlib.Path) -> None:
    """直接把单个文件当根时也要过后缀白名单，否则一根就绕开整个扫描面。"""
    binary = tmp_path / "blob.bin"
    binary.write_bytes(b"FLAG{deadbeef06}\n")
    assert scrub.main(["--check", str(binary)]) == 2
    known = tmp_path / "x.md"
    _write(known, "FLAG{deadbeef07}\n")
    assert scrub.main(["--check", str(known)]) == 1


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("fmt.py", 'print("flag{0x%x}" % 1)\n'),
        ("fmt.sh", 'printf "FLAG{0:08x}\\n"\n'),
    ],
)
def test_apply_reports_but_never_rewrites_executable_examples(
    name: str, body: str, tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``flag{0x%x}`` 首字符是字母数字，``is_code_template`` 判不出；只能不改写。"""
    path = tmp_path / name
    _write(path, body)
    assert scrub.main(["--apply", str(tmp_path)]) == 0
    assert path.read_text(encoding="utf-8") == body
    out = capsys.readouterr().out
    assert "would scrub" in out
    assert "跳过 1 处" in out
    assert scrub.main(["--check", str(tmp_path)]) == 1


def test_check_is_stricter_than_is_placeholder(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """四种已知模板放过；宽松 ``is_placeholder`` 放过的残留在 ``--check`` 里算命中。"""
    ok = tmp_path / "ok.md"
    _write(ok, "FLAG{...}\nflag{xxxx}\nCTF{<value>}\nFLAG{***}\n")
    assert scrub.main(["--check", str(tmp_path)]) == 0

    bad = tmp_path / "bad.md"
    _write(bad, "FLAG{__..__}\nFLAG{!!!!}\nFLAG{@@@}\n")
    assert scrub.main(["--check", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert out.count("bad.md:") == 3


def test_code_template_is_not_a_hit(tmp_path: pathlib.Path) -> None:
    """f-string 示例不是答案，抹掉反而把代码改坏。"""
    _write(tmp_path / "t.py", 'print(f"Flag: flag{{{decoded}}}")\n')
    assert scrub.main(["--check", str(tmp_path)]) == 0


def test_apply_fixes_what_check_rejects(tmp_path: pathlib.Path) -> None:
    """``--apply`` 与 ``--check`` 同一口径：否则闸门永远是红的。"""
    path = tmp_path / "bad.md"
    _write(path, "FLAG{!!!!}\n")
    assert scrub.main(["--apply", str(tmp_path)]) == 0
    assert path.read_text(encoding="utf-8") == "FLAG{...}\n"
