"""FMT-3：``/workspace``、进程 CWD、沙箱 root 三方路径口径必须合一。

病理链（每一条都实测过）：

1. ``extra_files`` 的 key 是 strix 的 ``/workspace/<rel>``，于是提示层照着这个
   字符串告诉模型"文件在这儿"；
2. 本地 backend 的 root 是 ``tempfile.mkdtemp`` 出来的私有目录，``/workspace``
   在沙箱里**根本不存在**；
3. shell 的 CWD 是 root（``unix_local._resolved_exec_context``），所以
   ``cat chal.bin`` 成功、``cat /workspace/chal.bin`` 404；
4. 而 ``file_triage`` / ``unpack_archive`` / ``hexpeek`` / ``elffind`` /
   ``elfpeek`` 原先按**进程 CWD** 解析 —— agent 进程从不 ``chdir``，那是启动
   目录。同一个文件名，shell 里在、工具里报"路径不存在"。

本文件锁住两件事：渲染层不再给出沙箱里不存在的绝对路径；工具层把相对路径与
``/workspace/...`` 都解析到同一个 root，且**没有沙箱时**退回旧行为。
"""

from __future__ import annotations

import sys
import types
import zipfile
from pathlib import Path

import pytest

from ctf_strix import file_triage, nonweb
from ctf_strix.agent import _attachment_section
from ctf_strix.file_triage import resolve_path


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """假装本次 run 已在 ``tmp_path/sandbox-root`` 建档。"""
    root = tmp_path / "sandbox-root"
    root.mkdir()
    stub = types.ModuleType("ctf_strix.local_backend")
    stub.workspace_root = lambda: root  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND", stub)
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND_PROBED", True)
    return root


@pytest.fixture
def bare_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    """``local_backend`` 不可导入（Windows / 测试桩）时的降级路径。"""
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND", None)
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND_PROBED", True)


# --- 渲染层：不再给出沙箱里不存在的绝对路径 -------------------------------


def test_attachment_section_renders_paths_relative_to_the_working_directory() -> None:
    section = _attachment_section(
        [
            {"workspace_path": "/workspace/chal.bin", "content": ""},
            {"workspace_path": "/workspace/attachments/hint.txt", "content": ""},
        ]
    )
    assert "- ./chal.bin\n" in section
    assert "- ./attachments/hint.txt" in section
    assert "/workspace/chal.bin" not in section
    # 溢出指针（vendor 写的）仍是 /workspace/...，必须给出映射规则。
    assert "drop the `/workspace/` prefix" in section


def test_attachment_section_is_empty_without_attachments() -> None:
    assert _attachment_section([]) == ""


# --- 工具层：相对路径与 /workspace/... 落到同一个 root ---------------------


def test_relative_and_workspace_paths_agree(sandbox: Path) -> None:
    assert resolve_path("chal.bin") == sandbox / "chal.bin"
    assert resolve_path("/workspace/chal.bin") == sandbox / "chal.bin"
    assert resolve_path("./chal.bin") == sandbox / "chal.bin"


def test_bare_workspace_names_the_root(sandbox: Path) -> None:
    for raw in ("", ".", "./", "/workspace", "/workspace/"):
        assert resolve_path(raw) == sandbox


def test_host_absolute_paths_are_not_rewritten(sandbox: Path, tmp_path: Path) -> None:
    """shell 不 jail 路径：主机绝对路径（超限附件清单里的那种）是真能读的。"""
    outside = tmp_path / "big" / "image.raw"
    outside.parent.mkdir()
    outside.write_bytes(b"x")
    assert resolve_path(str(outside)) == outside


def test_without_a_sandbox_the_process_cwd_is_used(
    bare_backend: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert resolve_path("chal.bin") == tmp_path / "chal.bin"


def test_a_backend_without_workspace_root_is_tolerated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stub = types.ModuleType("ctf_strix.local_backend")  # 老测试桩没有该属性
    monkeypatch.setitem(sys.modules, "ctf_strix.local_backend", stub)
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND", stub)
    monkeypatch.setattr(file_triage, "_LOCAL_BACKEND_PROBED", True)
    monkeypatch.chdir(tmp_path)
    assert resolve_path("chal.bin") == tmp_path / "chal.bin"


# --- 工具真正读到沙箱里的文件 ----------------------------------------------


def test_file_triage_finds_a_file_the_way_the_shell_sees_it(sandbox: Path) -> None:
    target = sandbox / "note.txt"
    target.write_text("FLAG{from-the-sandbox}\n", encoding="utf-8")
    out = file_triage.file_triage("/workspace/note.txt")
    assert "路径不存在" not in out
    assert "note.txt" in out


def test_unpack_archive_defaults_into_the_sandbox_root(sandbox: Path) -> None:
    archive = sandbox / "mini.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("inner.txt", "hello")
    out = nonweb.unpack_archive("mini.zip")
    assert "inner.txt" in out
    assert (sandbox / "extracted" / "inner.txt").is_file()


def test_tcp_dump_defaults_into_the_sandbox_root(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CTF_TCP_DUMP_DIR", raising=False)
    assert nonweb._dump_root() == sandbox / "tcpdump"
    assert (sandbox / "tcpdump").is_dir()