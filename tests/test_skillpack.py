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


def _render_of_size(pack: Path, target: int) -> tuple[Path, str]:
    """造一个 ``render()`` 后**恰好** *target* 字节的索引（全 ASCII）。"""
    name = pack.name
    ref = "/var/ctf/jail/skills"
    hint = skillpack._hint(ref, name)
    head = "# t\n\n"
    fill = "x" * (target - len(hint.encode("utf-8")) - len(head.encode("utf-8")))
    pack.mkdir(parents=True, exist_ok=True)
    path = pack / f"{name}.md"
    path.write_text(head + fill, encoding="utf-8")
    body = skillpack.render(path, ref, name)
    assert len(body.encode("utf-8")) == target, len(body.encode("utf-8"))
    return path, body


GATE_REFS = (
    "/var/ctf/jail/skills",
    "/app/src/ctf_strix/skills_strix",
    skillpack.ref_root(),
)


@pytest.mark.parametrize("ref", GATE_REFS)
def test_index_sources_fit_the_gate(ref: str) -> None:
    """strict 闸（单测/CI 专用）：**渲染后**字节必须 ≤ INDEX_MAX_BYTES。

    闸门量的是运行时真正落盘的那一份：``render()`` 会插入路径提示、抹掉
    flag 形态，产物比源文件大 235B（20 字符 ref）。只量源文件的旧闸漏掉了 H-1——
    ctf-supply-chain 渲染 8172B，却被 ``cap - len(marker)`` 的旧预算误截。
    """
    for category, _name, path in skillpack.index_skills():
        body = skillpack.render(path, ref, category)
        size = len(body.encode("utf-8"))
        assert size <= skillpack.INDEX_MAX_BYTES, (
            f"{category} 渲染后 {size}B > {skillpack.INDEX_MAX_BYTES}B：先下沉再进仓库"
        )


def test_render_just_under_the_cap_passes_byte_for_byte(tmp_path: Path) -> None:
    """边界：渲染 8100B（< 8192）必须原样落盘，一个字节都不改。

    旧语义按 ``cap - len(marker)`` 预扣预算，8063 < 8100 ≤ 8192 会被误截；
    这条用例就是那个回归的探针。
    """
    ref = "/var/ctf/jail/skills"
    _path, body = _render_of_size(tmp_path / "ctf-8100", 8100)
    reg = skillpack.stage(ref=ref, pack=tmp_path)
    out = (reg / "ctf-8100" / "ctf-8100.md").read_bytes()
    assert out == body.encode("utf-8"), "未超 cap 的索引被改动了"
    assert "INDEX TRUNCATED" not in out.decode("utf-8")


def test_render_just_over_the_cap_truncates_and_reports_real_size(
    tmp_path: Path,
) -> None:
    """边界：渲染 8200B 才截断；总长 ≤ 8192，标记写**实际**尺寸。"""
    ref = "/var/ctf/jail/skills"
    _path, _body = _render_of_size(tmp_path / "ctf-8200", 8200)
    reg = skillpack.stage(ref=ref, pack=tmp_path)
    out = (reg / "ctf-8200" / "ctf-8200.md").read_bytes()
    assert len(out) <= skillpack.INDEX_MAX_BYTES, f"截断后仍 {len(out)}B > 上限"
    text = out.decode("utf-8")
    assert "INDEX TRUNCATED" in text
    assert "rendered 8200B" in text, "标记里必须是实际渲染尺寸，不是写死的上限"
    assert "rendered 8192B" not in text


def test_truncation_marker_names_deep_dive_only_when_it_exists(tmp_path: Path) -> None:
    """M-2：有子文件才点名路径，没有就只给 ``ls`` 指引，不说谎。"""
    ref = "/ref/skills"
    deep_path, deep_body = _render_of_size(tmp_path / "ctf-deep", 8200)
    (deep_path.parent / "archive-deep-dive.md").write_text("x", encoding="utf-8")
    shallow_path, shallow_body = _render_of_size(tmp_path / "ctf-shallow", 8200)

    deep = skillpack._cap_index(deep_body, ref, "ctf-deep", 8192, deep_path)
    shallow = skillpack._cap_index(shallow_body, ref, "ctf-shallow", 8192, shallow_path)
    assert f"{ref}/ctf-deep/archive-deep-dive.md" in deep
    assert "archive-deep-dive.md" not in shallow
    assert f"ls {ref}/ctf-shallow/" in shallow
    assert "live in subfiles" not in shallow


def test_tiny_cap_degrades_to_markerless_truncation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """L-1：cap 小于标记长度时不许超 cap——退化为纯内容截断（无标记）。"""
    monkeypatch.setenv("CTF_INDEX_CAP", "50")
    _path, _body = _render_of_size(tmp_path / "ctf-tiny", 4000)
    reg = skillpack.stage(ref="/p", pack=tmp_path)
    out = (reg / "ctf-tiny" / "ctf-tiny.md").read_bytes()
    assert len(out) <= 50, f"cap=50 却写出 {len(out)}B"
    assert "INDEX TRUNCATED" not in out.decode("utf-8")


def test_non_positive_cap_falls_back_to_the_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L-1: ``CTF_INDEX_CAP=-1`` is invalid, not "tighter".

    The old reader caught only ``ValueError``; a negative value reached
    ``_cut_lines(encoded, cap)`` and became ``encoded[:-1]`` -- the whole index
    minus its last byte. It must fall back to ``INDEX_MAX_BYTES`` instead.
    """
    monkeypatch.setenv("CTF_INDEX_CAP", "-1")
    ref = "/var/ctf/jail/skills"
    reg = skillpack.stage(ref=ref)
    checked = 0
    for category, _name, path in skillpack.index_skills():
        out = (reg / category / f"{category}.md").read_bytes()
        expected = skillpack.render(path, ref, category).encode("utf-8")
        assert len(out) <= skillpack.INDEX_MAX_BYTES, f"{category} 落盘 {len(out)}B"
        assert out == expected, f"{category} 被 cap=-1 近似整文截断"
        assert "INDEX TRUNCATED" not in out.decode("utf-8")
        checked += 1
    assert checked >= 12


def test_cut_lines_never_emits_a_half_character() -> None:
    """L-2: a 3-byte CJK char straddling the cut must not leave a broken tail."""
    text = "x" * 7 + "中" * 5
    cut = skillpack._cut_lines(text.encode("utf-8"), 8)  # 7 + first byte of 「中」
    assert len(cut.encode("utf-8")) <= 8
    assert cut == "x" * 7
    assert "\ufffd" not in cut

    lined = "x" * 7 + "\n" + "中" * 5
    cut2 = skillpack._cut_lines(lined.encode("utf-8"), 10)
    assert len(cut2.encode("utf-8")) <= 10
    assert cut2 == "x" * 7
    assert "\ufffd" not in cut2


@pytest.mark.parametrize("ref", GATE_REFS)
def test_no_real_index_is_truncated_at_runtime(ref: str) -> None:
    """零截断验收：13 个真实类别逐类 stage，无标记且 ≤ 8192B。

    这不是抽查：任何一类超限都说明源索引该先下沉子文件，而不是调大闸。
    """
    reg = skillpack.stage(ref=ref)
    files = sorted(reg.rglob("*.md"))
    assert len(files) == len(skillpack.index_skills())
    for path in files:
        out = path.read_bytes()
        assert len(out) <= skillpack.INDEX_MAX_BYTES, (
            f"{path.parent.name} 落盘 {len(out)}B > 上限"
        )
        assert "INDEX TRUNCATED" not in out.decode("utf-8"), (
            f"{path.parent.name} 的真实索引被运行时截断了"
        )


def test_stage_truncates_oversize_index_and_marks_it(tmp_path: Path) -> None:
    """运行时闸：超限截断到上限 + 尾部标记行带 L3 子文件路径，绝不 raise。"""
    pack = tmp_path / "ctf-fat"
    pack.mkdir()
    (pack / "ctf-fat.md").write_text(
        "# fat\n\n" + ("filler line\n" * 2000), encoding="utf-8"
    )
    reg = skillpack.stage(ref="/var/ctf/jail/skills", pack=tmp_path)
    out = (reg / "ctf-fat" / "ctf-fat.md").read_bytes()
    assert len(out) <= skillpack.INDEX_MAX_BYTES, f"截断后仍 {len(out)}B > 上限"
    text = out.decode("utf-8")
    assert "INDEX TRUNCATED" in text
    assert "/var/ctf/jail/skills/ctf-fat/" in text
    assert "exec_command" in text


def test_stage_leaves_small_index_untouched(tmp_path: Path) -> None:
    """不超限的索引必须原样通过，不能被闸误伤。"""
    pack = tmp_path / "ctf-thin"
    pack.mkdir()
    (pack / "ctf-thin.md").write_text("# thin\n\nok\n", encoding="utf-8")
    reg = skillpack.stage(ref="/p", pack=tmp_path)
    text = (reg / "ctf-thin" / "ctf-thin.md").read_text(encoding="utf-8")
    assert "INDEX TRUNCATED" not in text
    assert "ok" in text


def test_index_cap_env_relaxes_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``CTF_INDEX_CAP`` 覆盖上限：设小值时同样截断且结果 ≤ 该值。"""
    pack = tmp_path / "ctf-mid"
    pack.mkdir()
    (pack / "ctf-mid.md").write_text(
        "# mid\n\n" + ("x" * 4000) + "\n", encoding="utf-8"
    )
    monkeypatch.setenv("CTF_INDEX_CAP", "2048")
    reg = skillpack.stage(ref="/p", pack=tmp_path)
    out = (reg / "ctf-mid" / "ctf-mid.md").read_bytes()
    assert len(out) <= 2048, f"CTF_INDEX_CAP=2048 未生效，产物 {len(out)}B"
    assert "INDEX TRUNCATED" in out.decode("utf-8")


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
