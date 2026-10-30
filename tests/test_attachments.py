"""附件注入：漏一个文件等于丢掉半道题，多塞一个文件等于烧掉注入配额。

``_local_attachments`` 把工作目录读成 strix 的 ``extra_files``。两条相反方向的
错误都要锁住：

- **漏**：``attachments/`` / ``files/`` 子目录、二进制附件（必须转 b64）、
  子目录里的同名附件（不能用假名互相覆盖）；
- **多**：``task.json`` / ``result.json``、点文件、本地源码树。

源码树那条不是洁癖：本地调试时 ``CTFY_WORK_DIR`` 没设，cwd 就是仓库根，
不排除的话会把整棵树当附件打进 sandbox（50 个文件配额一次就满），
agent 还会读到评测脚本里的常量，把套题 id 当 flag 交上去——这真的发生过。
"""

from __future__ import annotations

import base64
from pathlib import Path

from ctf_strix.agent import _local_attachments


def _paths(entries: list[dict[str, str]]) -> dict[str, str]:
    return {entry["workspace_path"]: entry["content"] for entry in entries}


def test_text_attachment_is_injected_with_relative_path(tmp_path: Path) -> None:
    (tmp_path / "setup.txt").write_text("admin slug: /admin-7f3a", encoding="utf-8")
    files = _paths(_local_attachments(tmp_path))
    assert files["/workspace/setup.txt"] == "admin slug: /admin-7f3a"


def test_binary_attachment_is_base64_and_round_trips(tmp_path: Path) -> None:
    """sandbox 注入的是文本：二进制必须编码，且后缀要让 agent 知道要解码。"""
    blob = bytes(range(256))
    (tmp_path / "chal.bin").write_bytes(blob)
    files = _paths(_local_attachments(tmp_path))
    encoded = files["/workspace/chal.bin.b64"]
    assert base64.b64decode(encoded) == blob


def test_platform_files_and_dotfiles_are_excluded(tmp_path: Path) -> None:
    (tmp_path / "task.json").write_text("{}", encoding="utf-8")
    (tmp_path / "result.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.tmp").write_text("x", encoding="utf-8")
    (tmp_path / ".hidden").write_text("x", encoding="utf-8")
    (tmp_path / "real.txt").write_text("keep", encoding="utf-8")
    assert list(_paths(_local_attachments(tmp_path))) == ["/workspace/real.txt"]


def test_local_source_tree_is_not_shipped_as_attachments(tmp_path: Path) -> None:
    (tmp_path / "src" / "ctf_strix").mkdir(parents=True)
    (tmp_path / "src" / "ctf_strix" / "agent.py").write_text("SECRET", encoding="utf-8")
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments" / "hint.txt").write_text("hint", encoding="utf-8")
    assert list(_paths(_local_attachments(tmp_path))) == ["/workspace/attachments/hint.txt"]


def test_attachment_subdir_is_injected_once(tmp_path: Path) -> None:
    """``work`` 与 ``work/attachments`` 两个 root 会扫到同一个文件，不能注入两份。"""
    (tmp_path / "attachments").mkdir()
    (tmp_path / "attachments" / "a.txt").write_text("a", encoding="utf-8")
    entries = _local_attachments(tmp_path)
    assert len(entries) == 1
    assert entries[0]["workspace_path"] == "/workspace/attachments/a.txt"


def test_same_name_in_different_dirs_does_not_collide(tmp_path: Path) -> None:
    """多题各带一个 README 很常见；用相对路径当 workspace 路径才不会互相覆盖。"""
    (tmp_path / "one").mkdir()
    (tmp_path / "two").mkdir()
    (tmp_path / "one" / "README").write_text("one", encoding="utf-8")
    (tmp_path / "two" / "README").write_text("two", encoding="utf-8")
    files = _paths(_local_attachments(tmp_path))
    assert files["/workspace/one/README"] == "one"
    assert files["/workspace/two/README"] == "two"
