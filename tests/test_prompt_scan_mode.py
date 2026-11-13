"""``scan_mode`` 必须真的改变渲染结果。

RT-2（评审 §4.1.2）：``agent.py`` 按题型传 ``"deep" if engagement else "quick"``，
harness 也传 ``"quick"``；但替换后的 ``render_system_prompt`` 把它丢掉，
quick 的「先收敛」意图 0 效果。

strix 原实现用 ``scan_mode`` 选 ``scan_modes/<mode>`` 技能
（``vendor/src/strix/agents/prompt.py`` 的 ``_resolve_skills``），我们替换了
整个渲染函数，就只能自己渲染这一段。两条边界必须同时成立：

1. ``quick`` 注入收敛段；
2. ``deep``（engagement 与默认值）与改动前逐字节相同 —— 两处提示大小预算
   和已测量的 engagement 行为都建立在 deep 文本上。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

MARK = "## Scan mode: quick"
KINDS = ("web", "checker", "file", "tcp", "engagement")


@pytest.fixture(autouse=True)
def _isolated_prompt(monkeypatch):
    """关掉环境变量覆盖，并在测试后恢复模块级 kind。"""
    from ctf_strix import prompt

    monkeypatch.delenv("CTF_PROMPT_OFF", raising=False)
    monkeypatch.delenv("CTF_PROMPT_OVERRIDE", raising=False)
    # 仓库里没有 config/prompt_ctf.md；仍显式指向不存在的路径，
    # 免得开发机上放了一个 override 文件就静默绕过本文件的全部断言。
    monkeypatch.setattr(prompt, "OVERRIDE", ROOT / "ctfwork" / ".rt2-no-override")
    before = prompt.active()
    yield
    prompt.activate(*before)


def _render(kind: str, **kwargs) -> str:
    from ctf_strix import prompt

    prompt.activate(kind, ("base", kind))
    return prompt.build({}, **kwargs)


def test_quick_and_deep_render_differently():
    """改前这两个调用返回同一份文本，``scan_mode`` 是死参数。"""
    assert _render("web", scan_mode="quick") != _render("web", scan_mode="deep")


def test_only_quick_injects_the_convergence_section():
    quick = _render("web", scan_mode="quick")
    assert quick.count(MARK) == 1
    assert MARK not in _render("web", scan_mode="deep")
    assert MARK not in _render("web")  # 默认值是 deep，与 strix 原签名一致


@pytest.mark.parametrize("kind", KINDS)
def test_every_challenge_kind_renders_the_quick_section(kind):
    """五种 kind 共用 ``_CORE``；漏一种就是某类题静默退回铺开扫描。"""
    assert MARK in _render(kind, scan_mode="quick")


@pytest.mark.parametrize("mode", ["bogus", "", "  ", "DEEP", None])
def test_unknown_mode_falls_back_to_deep(mode):
    """只认 ``quick``（大小写/空白不敏感）；未知值不能意外改变 deep 文本。"""
    assert _render("web", scan_mode=mode) == _render("web", scan_mode="deep")


def test_mode_is_matched_case_insensitively():
    assert _render("web", scan_mode=" QUICK ") == _render("web", scan_mode="quick")


def test_deep_rendering_is_unchanged():
    """``build({})`` 必须仍然等于显式 deep —— 预算测试跑的就是默认路径。"""
    for kind in KINDS:
        assert _render(kind) == _render(kind, scan_mode="deep")


def test_quick_section_is_the_only_size_delta():
    """增量必须正好是那段文本，防止顺手把别的段落也改了。"""
    from ctf_strix import prompt

    quick = _render("web", scan_mode="quick")
    deep = _render("web", scan_mode="deep")
    assert len(quick) - len(deep) == len(prompt._SCAN_QUICK)


def test_quick_section_is_small():
    from ctf_strix import prompt

    assert 300 <= len(prompt._SCAN_QUICK) <= 600


def test_quick_section_states_no_tool_or_skill_names():
    """机制级文本：工具事实只在 ``## Environment``，技能清单只在索引里。"""
    from ctf_strix import prompt

    text = prompt._SCAN_QUICK.lower()
    for tool in ("nmap", "sqlmap", "ffuf", "gobuster", "r2", "nuclei"):
        assert tool not in text, f"{tool} must stay in the Environment block"
    for skill in ("ctf-web", "ctf-pwn", "ctf-crypto", "ctf-ai-ml", "ctf-triage"):
        assert skill not in text, "the skill index is the only skill list"
    assert "{" not in prompt._SCAN_QUICK and "}" not in prompt._SCAN_QUICK


def test_render_system_prompt_forwards_scan_mode_to_build(monkeypatch):
    """直接观察被丢弃过的那个参数，不依赖渲染细节。"""
    from ctf_strix import prompt

    seen: dict[str, object] = {}

    def fake_build(system_prompt_context=None, *, is_root=True, scan_mode="deep"):
        seen["context"] = system_prompt_context
        seen["is_root"] = is_root
        seen["scan_mode"] = scan_mode
        return "rendered"

    monkeypatch.setattr(prompt, "build", fake_build)
    out = prompt.render_system_prompt(
        scan_mode="quick",
        is_root=True,
        system_prompt_context={"authorized_targets": []},
    )

    assert out == "rendered"
    assert seen == {
        "context": {"authorized_targets": []},
        "is_root": True,
        "scan_mode": "quick",
    }


def test_installed_render_keeps_scan_mode():
    """strix ``runner`` 读 ``scan_config`` 后按关键字调用，安装后仍要透传。"""
    pytest.importorskip("strix.agents.prompt")
    from ctf_strix import prompt
    import strix.agents.prompt as vendor_prompt

    assert prompt.install() is True

    prompt.activate("web", ("base", "web"))
    quick = vendor_prompt.render_system_prompt(scan_mode="quick")
    deep = vendor_prompt.render_system_prompt(scan_mode="deep")

    assert MARK in quick
    assert MARK not in deep
    assert quick != deep