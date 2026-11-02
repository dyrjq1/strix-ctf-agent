"""Regression: each run gets a private ``/tmp``.

CTFARENA-095 (DeepSeek arm) latched onto ``/tmp/words.txt`` / ``/tmp/paths.txt``
left behind by the *previous* run, spent three calls deciding whose directory
it was, and built its route list from it. That is cross-challenge contamination,
not capability — and in a real run every challenge has its own container, so it
is also a measurement error.

The fix wraps the agent process in a private mount namespace and masks ``/tmp``
with tmpfs. This file pins the two properties that make it safe: the sandbox is
bind-mounted to ``/work`` *before* the mask (otherwise archiving is empty), and
``--propagation private`` keeps the mount from leaking back to the host.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from batch_eval import (  # noqa: E402
    _PRIVATE_TMP_WRAPPER,
    _private_tmp_available,
    _wrap_private_tmp,
)


def test_wrapper_binds_box_before_masking_tmp() -> None:
    script = _PRIVATE_TMP_WRAPPER
    bind_at = script.index('mount --bind "$box" /work')
    mask_at = script.index("mount -t tmpfs tmpfs /tmp")
    assert bind_at < mask_at, "先遮蔽 /tmp 会把沙箱目录一起盖住，归档就空了"
    assert "cd /work" in script
    assert 'exec setpriv --reuid="$uid" --regid="$gid" --init-groups env "$@"' in script


def test_wrapper_masks_privilege_escalation() -> None:
    """sudoers 放行了 unshare，若不屏蔽，agent 能自己走回 root。

    实测过：不加这一步，namespace 内 `sudo -n id` 直接返回 uid=0(root)。
    """
    script = _PRIVATE_TMP_WRAPPER
    assert "mount --bind /dev/null" in script
    for path in ("/usr/bin/sudo", "/usr/bin/su"):
        assert path in script


def test_wrapper_drops_root_after_mounting() -> None:
    # unshare needs root, but the agent must not keep it: reading host files
    # as root is not what a real challenge container looks like.
    assert "setpriv" in _PRIVATE_TMP_WRAPPER
    assert '"$uid"' in _PRIVATE_TMP_WRAPPER and '"$gid"' in _PRIVATE_TMP_WRAPPER


def test_wrap_passes_box_and_ids_then_command(tmp_path: Path) -> None:
    argv = _wrap_private_tmp(
        ["/venv/bin/python", "-u", "script.py"], tmp_path, {"PYTHONPATH": "/src"}
    )
    assert argv[:4] == ["sudo", "-n", "unshare", "-m"]
    assert "--propagation" in argv and "private" in argv
    assert argv[-3:] == ["/venv/bin/python", "-u", "script.py"]
    assert str(tmp_path) in argv
    assert "PYTHONPATH=/src" in argv


def test_env_survives_sudo_reset(tmp_path: Path) -> None:
    """``sudo`` 默认 env_reset，Popen 的 env 到不了 namespace 里。

    实测漏掉这一步时题目直接 `ModuleNotFoundError: No module named
    'ctf_strix'`，日志只显示"0 次调用"——看起来像模型不干活。
    """
    argv = _wrap_private_tmp(["python3", "-c", "pass"], tmp_path, {"A": "b"})
    env_at = argv.index("A=b")
    assert argv[env_at + 1 :] == ["python3", "-c", "pass"]
    assert 'env "$@"' in _PRIVATE_TMP_WRAPPER


def test_private_tmp_can_be_disabled_by_env(monkeypatch) -> None:
    monkeypatch.setenv("CTF_PRIVATE_TMP", "0")
    assert _private_tmp_available() is False