"""平台注入的 LLM 环境变量 → strix 认识的变量名。

CTFY-0001 §1.1 规定平台注入的是一组**中立的**名字：

    LLM_FLAVOR / LLM_API_KEY / LLM_MODEL / LLM_BASE_URL

而 strix 的 ``LlmSettings`` 读的是另一组（``vendor/src/strix/config/settings.py``）：

    api_key  ← LLM_API_KEY | OPENAI_API_KEY
    api_base ← LLM_API_BASE | OPENAI_API_BASE | OPENAI_BASE_URL | LITELLM_BASE_URL ...
    model    ← STRIX_LLM

两边只有 ``LLM_API_KEY`` 是重合的。**base_url 和 model 不桥接，平台评分时
模型请求会打到 SDK 默认端点**——凭据在那边无效，回来的 401 看起来像"key 被吊销"，
而实际上是一个键送错了地方。CTFY-0001 专门警告过这个坑。

所以本模块在 agent 启动最早期做一次单向归一化：**只填空缺，不覆盖已有值**。
本地调试时 ``STRIX_LLM`` / ``LLM_API_BASE`` 已经设好，这里不会动它们。
"""

from __future__ import annotations

import os

#: 平台给 base_url 用的名字，按可信度排序。
_BASE_URL_KEYS = ("LLM_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL")

#: 平台给 key 用的名字。anthropic flavor 下两个名字携带同一个值，
#: 但 ANTHROPIC_AUTH_TOKEN 走的是 bearer，Anthropic **兼容**端点只认这个。
_KEY_KEYS = ("LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")

#: Public alias.  The startup probe must read the same names the bridge
#: accepts, otherwise "no key" and "key bridged" can disagree and the probe
#: refuses a run that would have worked (2026-11-14 Codex review N4).
KEY_ENV_NAMES = _KEY_KEYS


def _first_set(keys: tuple[str, ...]) -> str | None:
    """返回第一个非空环境变量的值。空字符串按未设置处理（§1.1 的约定）。"""
    for key in keys:
        value = os.environ.get(key)
        if value:
            return value
    return None


def _qualify(model: str, flavor: str) -> str:
    """给模型名补上 litellm 需要的 provider 前缀。

    strix 用 litellm 路由，``openai/DeepSeek-V4.1-Flash`` 这种带前缀的才走
    OpenAI 兼容接口。平台给的 ``LLM_MODEL`` 通常是不带前缀的裸名字，
    到这里补成 ``<flavor>/<model>``。

    Args:
        model: 平台给的模型 id。
        flavor: ``openai`` 或 ``anthropic``。

    Returns:
        带 provider 前缀的模型名；原本就带 ``/`` 的原样返回。
    """
    if "/" in model:
        return model
    return f"{flavor}/{model}"


def normalise() -> dict[str, str]:
    """把平台变量映射到 strix 变量。幂等。

    Returns:
        本次实际写入的 ``{变量名: 来源变量名}``，用于在 result.json 里留痕——
        评分跑偏时第一时间能看出"用的是平台的端点还是镜像里的默认端点"。
    """
    applied: dict[str, str] = {}

    if not os.environ.get("STRIX_LLM"):
        model = _first_set(("LLM_MODEL",))
        if model:
            flavor = (os.environ.get("LLM_FLAVOR") or "openai").strip().lower()
            resolved = _qualify(model, flavor)
            os.environ["STRIX_LLM"] = resolved
            applied["STRIX_LLM"] = model

    if not os.environ.get("LLM_API_BASE"):
        base = _first_set(_BASE_URL_KEYS)
        if base:
            os.environ["LLM_API_BASE"] = base
            applied["LLM_API_BASE"] = "platform"

    if not os.environ.get("LLM_API_KEY"):
        key = _first_set(_KEY_KEYS)
        if key:
            os.environ["LLM_API_KEY"] = key
            applied["LLM_API_KEY"] = "platform"

    return applied
