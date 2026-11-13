# -*- coding: utf-8 -*-
"""B5 死机制删除钉（2026-11-13，r6 审查 DEAD-CODE 1/5 + C-8）。

被删的三个都是「只写不读 / 零调用方 / 教不存在入口」：
1. deadline_guard 的 ``self.observations`` 计数器——全仓只写不读；
2. restart_guard 的 ``stats()``——生产与测试零调用方；
3. ctf-ai-infra 技能教 ``aisec/aig_tool.py`` CLI——文件不存在，模型跑一次
   就是白扔一轮（offline-index 的 COMMAND_FORMS 只盯镜像 CLI 形态，
   python3 脚本形态漏盯）。

另有三条审查点名但**保留**（判据见台账 §4.161）：restart_guard L2 分支、
skillpack 清单降级分支、nonweb TLS 记录头分支——都是原理可达的行为分支，
不是死代码。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DG_SRC = (ROOT / "src" / "ctf_strix" / "deadline_guard.py").read_text(encoding="utf-8")
RG_SRC = (ROOT / "src" / "ctf_strix" / "restart_guard.py").read_text(encoding="utf-8")
MD = (
    ROOT
    / "src"
    / "ctf_strix"
    / "skills_strix"
    / "ctf-ai-infra"
    / "ctf-ai-infra.md"
).read_text(encoding="utf-8")
TOOLS_SRC = (ROOT / "src" / "ctf_strix" / "aisec" / "tools.py").read_text(encoding="utf-8")


def test_deadline_guard_observations_counter_is_gone() -> None:
    """只写不读的计数器已删——观察路径的可见行为不受影响。"""
    assert "self.observations" not in DG_SRC


def test_restart_guard_stats_helper_is_gone() -> None:
    """零调用方的诊断快照函数已删（harness 只调 endpoint_sources）。"""
    assert "def stats()" not in RG_SRC


def test_ai_infra_skill_teaches_registered_tools() -> None:
    """技能不许教不存在的 CLI；点名的工具必须真的注册（双向对齐）。"""
    assert "aig_tool" not in MD
    for name in ("ai_quick_scan", "ai_cve_lookup", "ai_fingerprint"):
        assert name in MD, f"skill md must teach {name}"
        assert f"async def {name}" in TOOLS_SRC, f"tool {name} must exist"
