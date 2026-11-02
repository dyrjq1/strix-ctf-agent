"""Capability installation shared by the eval harness and the official entrypoint.

Why this module exists
----------------------
The v2 work added three primitives (``http_probe``, ``route_map``,
``method_sweep``) and validated them through ``scripts/run_strix_ctf.py``.
The official CTFY entrypoint (``ctf_strix.agent``) never installed them, so
the submitted container ran with the pre-v2 tool surface while the eval
numbers described the v2 one.  That is a measurement/implementation split,
not a model-quality difference.

Both entrypoints now call the same helper.  Registration failures are
collected instead of swallowed: a capability that fails to register must be
visible in the run log, otherwise it is indistinguishable from "not needed
this challenge".
"""

from __future__ import annotations

from typing import Callable


RegisterFn = Callable[[], list[str]]


def _install(
    name: str,
    register: RegisterFn,
    installed: dict[str, list[str]],
    errors: list[str],
) -> None:
    """Run one registration and record either its tool names or its error."""
    try:
        installed[name] = list(register())
    except Exception as exc:  # noqa: BLE001 - one capability must not kill the run
        installed[name] = []
        errors.append(f"{name}: {type(exc).__name__}: {exc}")


def install_web_capabilities(
    http_register: RegisterFn | None = None,
    discovery_register: RegisterFn | None = None,
    variants_register: RegisterFn | None = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """Install the structured HTTP and route-discovery primitives.

    Args:
        http_register: Test seam; defaults to ``ctf_strix.http_probe.register``.
        discovery_register: Test seam; defaults to ``ctf_strix.discovery.register``.
        variants_register: Test seam; defaults to ``ctf_strix.variants.register``.

    Returns:
        ``(installed, errors)``.  ``installed`` maps capability name to the
        tool names newly registered (empty when already present).  ``errors``
        is a list of human-readable failures, empty on full success.
    """
    if http_register is None:
        from ctf_strix.http_probe import register as http_register
    if discovery_register is None:
        from ctf_strix.discovery import register as discovery_register
    if variants_register is None:
        from ctf_strix.variants import register as variants_register

    installed: dict[str, list[str]] = {}
    errors: list[str] = []
    _install("http_probe", http_register, installed, errors)
    _install("discovery", discovery_register, installed, errors)
    _install("variants", variants_register, installed, errors)
    return installed, errors


def install_soft_deadline(soft_seconds: float, turns: int):
    """Install the soft-deadline guard when a positive budget is configured.

    Args:
        soft_seconds: Seconds after which tool results start telling the agent
            to converge.  Non-positive disables the guard.
        turns: Turn budget, used only to phrase the hint.

    Returns:
        The installed guard, or ``None`` when disabled.
    """
    if soft_seconds <= 0:
        return None
    from ctf_strix.deadline_guard import DeadlineGuard
    from ctf_strix.deadline_guard import install as install_deadline_guard

    return install_deadline_guard(
        DeadlineGuard(
            wall=soft_seconds * 2,
            soft=soft_seconds,
            stall=max(soft_seconds / 3, 30.0),
            grace=20.0,
            turns=turns,
        )
    )
