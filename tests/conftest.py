"""公共夹具：把实例所有权台账隔离到临时目录。

``Client.launch`` 成功即写 ``~/.ctf_instances.json``；单测不该在真实家目录
留下条目，更不该让某条测试登记下来的 pid 影响别的测试的 ``_ledger_dead_ids``。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolated_instance_ledger(monkeypatch):
    """每个测试一份台账，绝不碰真实家目录。

    用 ``tempfile.mkdtemp`` 而不是 ``tmp_path``：本机 ``pytest-of-*`` 目录
    属于另一个用户，fixture 建目录会直接 PermissionError（伪装成测试挂了）。
    """
    d = Path(tempfile.mkdtemp(prefix="ctf-ledger-"))
    path = d / "instance-ledger.json"
    monkeypatch.setenv("CTF_INSTANCE_LEDGER", os.fspath(path))
    yield path


@pytest.fixture(autouse=True)
def _no_llm_preflight(monkeypatch):
    """单测永远不打开真 socket。

    预检默认**开**（生产要多早发现端点死了就多早），关它只能靠显式环境变量。
    以前靠 ``PYTEST_CURRENT_TEST`` 自动关，但那个变量会被子进程继承，
    镜像里跑 pytest 的步骤、或是任何「测试里真拉起一次 agent」的冒烟，
    都会让防线整轮静默消失，日志里只剩一行 ``ok=True reason=disabled``。
    """
    monkeypatch.setenv("CTF_LLM_PREFLIGHT", "0")
    yield
