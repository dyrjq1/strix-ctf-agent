"""按路径加载 ``scripts/scrub_flags.py``（它不在任何包里）。

两个测试文件都要用它：一个测脚本自己的闸门行为，一个用它的
``_DEFAULT_ROOTS`` 扫真实仓库。放一处免得两份加载逻辑漂移。
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "scrub_flags.py"


def load_scrub() -> ModuleType:
    """加载清洗脚本，返回模块对象。

    Returns:
        模块；``REPO`` / ``SCRIPT`` 由调用方按需自取。
    """
    spec = importlib.util.spec_from_file_location("scrub_flags_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
