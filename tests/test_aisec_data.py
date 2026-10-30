"""规则库数据完整性。

这份数据是 vendored 的（11 MB、2581 条规则），改动它的人多半不是写引擎的人。
所以把"引擎还能不能从它里面读出东西"钉成测试：条数变了不一定是错，但
**读不出来**一定是错——那时 agent 会拿着一张空表去查 CVE，还返回"未命中"，
看起来像"这题没漏洞"。
"""

from __future__ import annotations

from ctf_strix.aisec import aig_probe


def test_data_dir_present() -> None:
    root = aig_probe.data_dir()
    assert root is not None
    assert (root / "fingerprints.json").is_file()
    assert (root / "vuln_index.json").is_file()
    assert (root / "vuln").is_dir(), "vuln/ 必须整目录在，规则文件按 组件名/文件名 定位"


def test_rule_counts() -> None:
    rb = aig_probe._RULES
    assert len(rb.fingerprints()) == 163
    assert len(rb.vuln_index()) == 147
    assert sum(len(v) for v in rb.vuln_index().values()) == 2581


def test_known_components_resolve() -> None:
    """四个 mock 靶场的数字来自交付包自测；对不上说明数据被换过。"""
    assert len(aig_probe.lookup("ollama", "0.1.29")) == 27
    assert len(aig_probe.lookup("gradio", "4.44.1")) == 19
    assert len(aig_probe.lookup("dify", "0.6.9")) == 25
    assert len(aig_probe.lookup("comfyui", "0.3.27")) == 9


def test_unknown_component_is_empty_not_error() -> None:
    assert aig_probe.lookup("no-such-component-xyz", "1.0") == []
