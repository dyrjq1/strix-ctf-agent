"""技能包接入的回归测试。

三条不变的约定，任何一条破了都会让"技能在、但模型用不到"：

1. 只注册**索引**（每个分类一个 ``<分类>/<分类>.md``）—— 整包注册会把 190 个文件
   塞进每个 agent 的 system prompt；断言写成"索引数 == 目录数"而不是硬编码 12，
   这样新增一个方向技能只需要加目录，不需要改测试；
2. 索引正文里必须带子文件路径提示 —— 少这行，模型只能猜路径；
3. 索引里 266 条相对链接必须全部有效 —— 链接断了，提示指向的就是空。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ctf_strix import skillpack

#: 索引里 ``[x.md](x.md)`` 形式的相对链接。
_LINK = re.compile(r"\]\(([^)]+\.md)\)")


def test_index_skills_returns_one_per_category() -> None:
    """每个分类只有一个 ``<分类>/<分类>.md`` 索引，数量跟着目录走。"""
    idx = skillpack.index_skills()
    # Excluded categories still exist on disk but must not be offered.
    categories = [
        p.name for p in skillpack.PACK_DIR.iterdir()
        if p.is_dir() and p.name not in skillpack._EXCLUDED
    ]
    assert len(idx) == len(categories), (
        f"索引 {len(idx)} 个但目录 {len(categories)} 个：有分类缺 <分类>/<分类>.md"
    )
    assert len(idx) >= 12, "方向技能只增不减；少于 12 说明有索引被删了"
    assert [c for c, _, _ in idx] == sorted(c for c, _, _ in idx)
    for category, name, path in idx:
        assert category == name
        assert path.is_file()
        assert path.parent.name == category


def test_index_skills_skips_skill_md() -> None:
    """``SKILL.md`` 是上游遗留的重复索引，不能混进来占 prompt。"""
    names = [p.name for _, _, p in skillpack.index_skills()]
    assert "SKILL.md" not in names


def test_render_keeps_frontmatter_first(tmp_path: Path) -> None:
    """路径提示必须插在 frontmatter 之后，否则 strix 解析不到 name/description。"""
    src = skillpack.index_skills()[0][2]
    text = skillpack.render(src, "/var/ctf/jail/skills", "ctf-x")
    assert text.startswith("---"), "frontmatter 被推到第二行了"
    assert text.index("/var/ctf/jail/skills/ctf-x/") < text.index("\n# "), "提示没插到正文之前"


def test_render_without_frontmatter_still_hints() -> None:
    """没有 frontmatter 的文件也要拿到提示（自建技能可能就不写 frontmatter）。"""
    assert skillpack._hint("/p", "ctf-y").startswith("> 子文件目录")


def test_stage_writes_only_indexes(tmp_path: Path) -> None:
    """注册目录里只能有索引；子文件不进注册目录。"""
    reg = skillpack.stage(ref="/var/ctf/jail/skills")
    files = sorted(reg.rglob("*.md"))
    assert len(files) == len(skillpack.index_skills())
    assert all(f.parent.name == f.stem for f in files), "布局必须是 <分类>/<分类>.md"
    body = (reg / "ctf-web" / "ctf-web.md").read_text(encoding="utf-8")
    assert "/var/ctf/jail/skills/ctf-web/" in body


def test_similar_search_is_not_staged_or_registered() -> None:
    """A category that needs pip + api.tavily.com cannot be offered.

    The run is offline and the image has no Tavily client, so loading it
    costs a turn and teaches nothing runnable.  The upstream index is still
    filtered in ``prompt.py``; this is the second gate, on the registry.
    """
    names = [name for name, _n, _p in skillpack.index_skills()]
    assert "ctf-similar-search" not in names

    seen: list = []
    registered = skillpack.register(register_fn=seen.append)
    assert "ctf-similar-search/ctf-similar-search" not in registered
    assert all("similar-search" not in item for item in registered)


def test_register_calls_strix_once() -> None:
    """注册一次就够了；重复调用会让 strix 的搜索目录里堆同一份副本。"""
    seen: list[Path] = []
    names = skillpack.register(register_fn=seen.append)
    assert len(names) == len(skillpack.index_skills())
    assert len(seen) == 1
    assert all("/" in n and n.split("/")[0] == n.split("/")[1] for n in names)


def test_register_empty_pack_returns_empty(tmp_path: Path) -> None:
    """技能包缺失时返回空列表且**不**注册空目录——注册了只是白扫一遍磁盘。"""
    called: list[Path] = []
    empty = tmp_path / "empty"
    empty.mkdir()
    assert skillpack.register(registry=empty, register_fn=called.append) == []
    assert called == []


def test_prompt_hint_has_routing_and_path() -> None:
    """分流约束必须同时含"先 triage、只挑一个"和子文件绝对路径。"""
    hint = skillpack.prompt_hint(["ctf-triage/ctf-triage"], ref="/var/ctf/jail/skills")
    assert "ctf-triage/ctf-triage" in hint
    assert "一个" in hint
    assert "/var/ctf/jail/skills/<分类>/x.md" in hint
    assert "勿 load_skill" in hint
    assert "read_file" not in hint
    assert "exec_command" in hint
    assert "view_image" in hint


def test_index_hint_sends_text_and_images_to_registered_channels() -> None:
    """The staged index hint is the model's only map from link to file.

    Text must go through ``exec_command`` and images through ``view_image``;
    naming an unregistered reader sends the model at a tool that is not there.
    """
    hint = skillpack._hint("/var/ctf/jail/skills", "ctf-x")
    assert "read_file" not in hint
    assert "`exec_command`" in hint
    assert "cat/sed -n" in hint
    assert "`view_image`" in hint
    assert "load_skill" in hint


def test_prompt_hint_empty_when_no_skills() -> None:
    assert skillpack.prompt_hint([]) == ""


@pytest.mark.parametrize("category", [c for c, _, _ in skillpack.index_skills()])
def test_index_links_resolve(category: str) -> None:
    """266 条相对链接逐条查：断一条，模型 read_file 就撞 404。"""
    path = skillpack.PACK_DIR / category / f"{category}.md"
    text = path.read_text(encoding="utf-8")
    dead = [
        target
        for target in _LINK.findall(text)
        if not target.startswith("http") and not (path.parent / target).is_file()
    ]
    assert dead == []


def test_ref_root_ignores_empty_jail_mount() -> None:
    """宿主侧的 jail 挂载点是空目录（bind 只在 namespace 内生效）。

    只判 ``is_dir()`` 会让本地调试拿到一个读不到子文件的路径——提示写着
    "/var/ctf/jail/skills/ctf-web/x.md"，而那个目录在宿主上是空的。
    """
    import os

    old = os.environ.pop("CTF_SKILLS_REF", None)
    jailed = Path("/var/ctf/jail/skills")
    try:
        if jailed.is_dir() and not any(p.is_dir() for p in jailed.iterdir()):
            assert skillpack.ref_root() == str(skillpack.PACK_DIR)
    finally:
        if old is not None:
            os.environ["CTF_SKILLS_REF"] = old
