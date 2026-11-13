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

from scrub_loader import load_scrub

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


def test_index_skills_skips_skill_md(tmp_path: Path) -> None:
    """上游重同步可能把 ``SKILL.md`` 带回来；它绝不能混进注册面。

    仓库里已无 SKILL.md（只保留索引一份真相），所以这里用合成目录验证跳过
    逻辑——否则这条测试会变成一个空转的断言。
    """
    pack = tmp_path / "pack"
    cat = pack / "ctf-demo"
    cat.mkdir(parents=True)
    (cat / "ctf-demo.md").write_text(
        "---\nname: ctf-demo\n---\nbody\n", encoding="utf-8"
    )
    (cat / "SKILL.md").write_text("---\nname: skill\n---\nbody\n", encoding="utf-8")
    names = [p.name for _, _, p in skillpack.index_skills(pack)]
    assert names == ["ctf-demo.md"]


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
    """The hint must carry the triage entry, the one-index rule and the path."""
    hint = skillpack.prompt_hint(
        ["ctf-triage/ctf-triage", "ctf-web/ctf-web"], ref="/var/ctf/jail/skills"
    )
    assert "ctf-triage/ctf-triage" in hint
    assert "exactly one" in hint
    assert "/var/ctf/jail/skills/<category>/x.md" in hint
    assert "do NOT `load_skill`" in hint
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


def test_render_lists_child_files(tmp_path: Path) -> None:
    """索引必须自带子文件清单，否则封顶后模型只知道方向、不知道读哪个文件。

    ``context.py`` 对注入的索引做头尾封顶（8,000 / head 4,800），13 个索引里
    8 个超限，而"子文件链接表"长在中段——正好被折叠掉。清单紧跟路径提示，
    落在 head 区间，封顶裁不到。
    """
    src = skillpack.PACK_DIR / "ctf-crypto" / "ctf-crypto.md"
    text = skillpack.render(src, "/var/ctf/jail/skills", "ctf-crypto")
    assert skillpack._FILES_MARK in text
    # 提示在前、清单在后，且都落在封顶的 head 窗口内。
    assert text.index("> 子文件目录") < text.index(skillpack._FILES_MARK) < 1_200
    # 每个名字只出现一次（索引正文里同一文件常被多行引用）。
    for name in ("classic-ciphers.md", "patterns/RSA-FERMAT.md"):
        assert text.count(f"`{name}`") == 1
    # 清单是裸文件名，不带索引里的描述——描述会让块超预算。
    assert "Vigenere" not in text.split(skillpack._FILES_MARK, 1)[1].split("\n", 1)[0]


def _frontmatter(path: Path) -> str:
    """索引的 frontmatter 原文（``render`` 会把它留在最前）。"""
    text = path.read_text(encoding="utf-8")
    m = skillpack._FRONTMATTER.match(text)
    return m.group(0) if m else ""


def _context_cap() -> int:
    """``context.CAP_CHARS``：超过它的索引才会被裁剪，只有它们值得测。"""
    from ctf_strix import context

    return context.CAP_CHARS


#: 会被 ``context`` 封顶的索引分类（其余索引原样进上下文，没有清单块需求）。
_OVERSIZE = [
    category
    for category, _, path in skillpack.index_skills()
    if len(path.read_text(encoding="utf-8")) > _context_cap()
]


@pytest.mark.parametrize("evidence", [False, True])
@pytest.mark.parametrize("category", _OVERSIZE)
def test_child_file_list_survives_context_cap(category: str, evidence: bool) -> None:
    """封顶之后，清单块必须逐字节还在——这是本改动的全部意义。

    用真实的 ``context._cap_text`` 与生产常量（不是复刻的近似值），否则
    测的是本文件里的算术，不是运行期的裁剪。
    """
    from ctf_strix import context

    ref = "/var/ctf/jail/skills"
    path = skillpack.PACK_DIR / category / f"{category}.md"
    body = path.read_text(encoding="utf-8")[len(_frontmatter(path)) :]
    block = skillpack._files_index(body, ref, category)
    assert block, f"{category} 没有清单块，封顶测试会空转"

    rendered = skillpack.render(path, ref, category)
    capped = context._cap_text(
        rendered,
        limit=context.CAP_CHARS,
        head=context.HEAD_CHARS,
        tail=context.TAIL_CHARS,
        evidence=evidence,
    )
    assert block in capped, f"{category} 的清单块被封顶裁掉或截断了"


def test_render_skips_list_when_no_local_files(tmp_path: Path) -> None:
    """没有本地 md 可读时不出清单块——空块只是噪音。"""
    src = tmp_path / "demo.md"
    src.write_text(
        "---\nname: demo\n---\n# Demo\n"
        "See [the docs](https://example.com/a.md) or [notes](notes.txt).\n",
        encoding="utf-8",
    )
    text = skillpack.render(src, "/p", "ctf-demo")
    assert skillpack._FILES_MARK not in text


def test_files_index_keeps_relative_paths_and_drops_anchors(tmp_path: Path) -> None:
    """跨方向链接与 ``.md#锚点`` 都是有效路径；只去掉锚点、保留相对写法。"""
    src = tmp_path / "demo.md"
    src.write_text(
        "---\nname: demo\n---\n"
        "- [a](step.md#usage)\n"
        "- [b](../ctf-misc/ctf-misc.md)\n"
        "- [c](https://example.com/x.md)\n"
        "- [d](script.py)\n"
        "- [again](step.md#other)\n",
        encoding="utf-8",
    )
    text = skillpack.render(src, "/p", "ctf-demo")
    line = text.split(skillpack._FILES_MARK, 1)[1].split("\n", 1)[0]
    assert "`step.md`" in line and "#" not in line
    assert "`../ctf-misc/ctf-misc.md`" in line
    assert "example.com" not in line
    assert "script.py" not in line


def test_files_index_degrades_instead_of_truncating() -> None:
    """超预算时给 ``ls`` 指引，不给半截名单——半截名单会让模型以为文件就这些。"""
    ref = "/var/ctf/jail/skills"
    body = "\n".join(f"- [f{i}](file-{i}.md)" for i in range(200))
    block = skillpack._files_index(body, ref, "ctf-demo")
    assert "超出内联预算" in block
    assert f"`ls {ref}/ctf-demo/`" in block
    assert "file-0.md" not in block


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


def test_scrub_flags_check_passes_on_real_repo(capsys: pytest.CaptureFixture[str]) -> None:
    """默认面直接跑一遍闸门：退 0 才算干净。

    扫描量下限 2000 是防空转：路径或后缀白名单写错时零命中，看起来和"干净"
    一模一样。真实默认面约 2800 个文件，取 2000 留出删减余量。
    """
    assert load_scrub().main(["--check"]) == 0
    out = capsys.readouterr().out
    match = re.search(r"scanned (\d+) files", out)
    assert match, f"--check 没回报扫描数：\n{out}"
    assert int(match.group(1)) > 2000, f"只扫到 {match.group(1)} 个文件，扫描根路径不对"


def test_candidate_re_is_the_single_definition() -> None:
    """提交层与装载层必须共用同一条正则，否则会"抹得掉、交不上"。

    两边各写一份时的典型漂移：``skillpack`` 用 ``\\b`` 词边界，``autosubmit``
    不用，``MetaCTF{...}`` 在一边被抹、在另一边被截成 ``CTF{...}`` 交上去。
    """
    from ctf_strix import autosubmit
    from ctf_strix.flag_extract import CANDIDATE_RE

    assert autosubmit._CAND_PATTERNS[0].pattern == CANDIDATE_RE.pattern
    assert autosubmit._CAND_PATTERNS[0].flags == CANDIDATE_RE.flags


def test_scrub_flags_check_is_a_gate(tmp_path: Path) -> None:
    """``--check`` 是 CI 闸门：干净目录退 0，注入一处假 flag 退 1。"""
    import os
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[1]
    script = repo / "scripts" / "scrub_flags.py"
    sample = tmp_path / "skill.md"
    sample.write_text("# demo\nnothing here\n", encoding="utf-8")

    def run() -> "subprocess.CompletedProcess[str]":
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        return subprocess.run(
            [sys.executable, str(script), "--check", str(tmp_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(repo),
            env=env,
        )

    clean = run()
    assert clean.returncode == 0, clean.stdout + clean.stderr

    sample.write_text("# demo\nFLAG{injected_secret}\n", encoding="utf-8")
    dirty = run()
    assert dirty.returncode == 1
    assert "skill.md:2:" in dirty.stdout
    assert "FLAG{injected_secret}" in dirty.stdout


@pytest.mark.parametrize(
    "code",
    [
        'print(f"Flag: flag{{{decoded}}}")',
        'printf "flag{%s}"',
        "FLAG{${secret}}",
        "FLAG{[a-z]+}",
    ],
)
def test_mask_flags_keeps_code_examples(code: str) -> None:
    """代码里的模板串不能被抹：少一个花括号，示例就不再能跑。"""
    assert skillpack.mask_flags(code) == code


def test_mask_flags_still_masks_a_real_flag() -> None:
    assert skillpack.mask_flags("got FLAG{abc123def}") == "got FLAG{...}"


def test_dollar_prefixed_body_is_a_real_flag_not_code() -> None:
    """裸 ``$`` 不能当代码模板：``FLAG{$3cr3t}`` 是真实 flag 的常见写法。"""
    from ctf_strix.flag_extract import is_code_template, is_placeholder

    assert not is_code_template("FLAG{$3cr3t}")
    assert not is_placeholder("FLAG{$3cr3t}")
    assert skillpack.mask_flags("FLAG{$3cr3t}") == "FLAG{...}"

def test_prompt_hint_under_ceiling_is_byte_identical() -> None:
    """低于上限时出口封顶必须是零操作：不加标记、与未封顶的拼接逐字节相同。

    今天实测最坏 2,834 < 4,200，运行期行为零变化；这条断言钉住它。
    """
    names = [f"{c}/{c}" for c, _n, _p in skillpack.index_skills()]
    hint = skillpack.prompt_hint(names, ref="/skills")
    assert hint
    assert len(hint) <= skillpack.HINT_MAX_CHARS
    assert skillpack._HINT_CAPPED_MARK not in hint
    from ctf_strix import method_cards, routing

    raw = "\n\n".join(
        part
        for part in (routing.render(names, "/skills"), method_cards.render(None))
        if part
    )
    assert hint == raw

def test_prompt_hint_caps_oversized_block_at_line_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """判据表膨胀越过上限时：有界、按整行截断、可见标记收尾。

    模拟 ROUTES 长文案膨胀（codex RISK 1 的最小复现），防线在出口生效。
    """
    from ctf_strix import routing

    rows = [f"- row {i:03d} " + "x" * 96 for i in range(80)]
    giant = "\n".join(rows)
    assert len(giant) > skillpack.HINT_MAX_CHARS
    monkeypatch.setattr(routing, "render", lambda *args, **kwargs: giant)
    hint = skillpack.prompt_hint(["ctf-web/ctf-web"], ref="/skills")
    assert len(hint) <= skillpack.HINT_MAX_CHARS
    assert hint.endswith(skillpack._HINT_CAPPED_MARK)
    kept = hint[: -len(skillpack._HINT_CAPPED_MARK)].strip().split("\n")
    assert all(line in rows for line in kept if line)
    # 真的在截，不是整段丢弃。
    assert len(hint) > skillpack.HINT_MAX_CHARS - 300

def test_files_index_drops_flag_shaped_filenames() -> None:
    """RISK 8：清单不得把 flag 形态的文件名送进提示。

    清单块从未遮蔽的正文抽取（mask_flags 只作用于 body 之后）；带 flag
    形态的文件名是零污染面破口——遮蔽会给出读不到的假路径，所以直接不列。
    """
    body = (
        "- [normal](normal.md)\n"
        "- [old writeup](writeup-flag{deadbeef42}.md)\n"
        "- [cross](../ctf-misc/ctf-misc.md)\n"
    )
    block = skillpack._files_index(body, "/skills", "ctf-demo")
    assert "`normal.md`" in block
    assert "deadbeef42" not in block
    assert "flag{" not in block
    assert "../ctf-misc/ctf-misc.md" in block
