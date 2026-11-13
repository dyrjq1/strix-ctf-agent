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
